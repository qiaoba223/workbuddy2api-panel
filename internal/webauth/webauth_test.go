package webauth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestAuth(t *testing.T) (*Auth, string) {
	t.Helper()
	dir := t.TempDir()
	uf := filepath.Join(dir, "web_users.json")
	a, err := New(Config{
		Enabled:          true,
		UsersFile:        uf,
		SessionTTL:       "1h",
		MaxLoginAttempts: 3,
		LoginWindow:      "1m",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a, uf
}

func TestHashAndVerifyPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(h, hashPrefix) {
		t.Fatalf("hash prefix missing: %s", h)
	}
	if !VerifyPassword(h, "correct horse battery staple") {
		t.Error("correct password rejected")
	}
	if VerifyPassword(h, "wrong password") {
		t.Error("wrong password accepted")
	}
	// 同一密码两次哈希应不同（盐随机）。
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Error("salt not random: two hashes identical")
	}
}

func TestVerifyPasswordRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"", "plaintext", "pbkdf2-sha256$", "pbkdf2-sha256$abc$x$y",
		"pbkdf2-sha256$0$AAAA$AAAA", "pbkdf2-sha256$99999999999$AAAA$AAAA",
		"md5$1$AAAA$AAAA",
	} {
		if VerifyPassword(bad, "anything") {
			t.Errorf("malformed hash accepted: %q", bad)
		}
	}
}

func TestPBKDF2MatchesKnownVector(t *testing.T) {
	// RFC 6070 风格的已知答案（PBKDF2-HMAC-SHA256, P="password", S="salt", c=1, dkLen=32）。
	got := pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 32)
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if h := hexEncode(got); h != want {
		t.Fatalf("pbkdf2 vector mismatch:\n got %s\nwant %s", h, want)
	}
}

func TestLoginSetsCookieAndValidates(t *testing.T) {
	a, _ := newTestAuth(t)
	if err := a.SetPassword("admin", "supersecret1"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/panel/api/login", strings.NewReader(`{"username":"admin","password":"supersecret1"}`))
	r.RemoteAddr = "1.2.3.4:5555"
	ok, msg := a.Login(rec, r, "admin", "supersecret1")
	if !ok {
		t.Fatalf("login failed: %s", msg)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie set")
	}
	c := cookies[0]
	if c.Name != sessionCookieName {
		t.Fatalf("cookie name = %s", c.Name)
	}
	if !c.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("session cookie should be SameSite=Lax")
	}

	// 用签发的 Cookie 请求 → 应识别为有效会话。
	r2 := httptest.NewRequest("GET", "/panel/api/overview", nil)
	r2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.Value})
	user, ok := a.Valid(r2)
	if !ok || user != "admin" {
		t.Fatalf("Valid = (%q, %v), want (admin, true)", user, ok)
	}

	// 篡改令牌 → 无效。
	r3 := httptest.NewRequest("GET", "/panel/api/overview", nil)
	r3.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.Value + "x"})
	if _, ok := a.Valid(r3); ok {
		t.Error("tampered token accepted")
	}
}

func TestLoginWrongPasswordAndUserEnumeration(t *testing.T) {
	a, _ := newTestAuth(t)
	_ = a.SetPassword("admin", "supersecret1")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/panel/api/login", nil)
	r.RemoteAddr = "9.9.9.9:1"

	if ok, _ := a.Login(rec, r, "admin", "wrong"); ok {
		t.Error("wrong password accepted")
	}
	// 不存在的用户返回同一句话（不泄露用户名是否存在）。
	_, msg1 := a.Login(httptest.NewRecorder(), r, "admin", "wrong")
	_, msg2 := a.Login(httptest.NewRecorder(), r, "nosuchuser", "wrong")
	if msg1 != msg2 {
		t.Errorf("error messages differ, leaks user existence: %q vs %q", msg1, msg2)
	}
}

func TestLoginRateLimit(t *testing.T) {
	a, _ := newTestAuth(t)
	_ = a.SetPassword("admin", "supersecret1")

	r := httptest.NewRequest("POST", "/panel/api/login", nil)
	r.RemoteAddr = "5.5.5.5:1"

	// MaxLoginAttempts=3：前 3 次失败正常返回"用户名或密码错误"，
	// 第 4 次起被限速（错误信息不同）。
	for i := 0; i < 3; i++ {
		ok, msg := a.Login(httptest.NewRecorder(), r, "admin", "wrong")
		if ok || msg != "用户名或密码错误" {
			t.Fatalf("attempt %d: ok=%v msg=%q", i, ok, msg)
		}
	}
	ok, msg := a.Login(httptest.NewRecorder(), r, "admin", "wrong")
	if ok {
		t.Fatal("rate limit not enforced")
	}
	if !strings.Contains(msg, "频繁") {
		t.Fatalf("want rate-limit message, got %q", msg)
	}
	// 限速期间即便密码正确也拒绝（防绕过）。
	if ok, _ := a.Login(httptest.NewRecorder(), r, "admin", "supersecret1"); ok {
		t.Error("rate limit bypassed by correct password")
	}
	// 换 IP 不受影响。
	r2 := httptest.NewRequest("POST", "/panel/api/login", nil)
	r2.RemoteAddr = "6.6.6.6:1"
	if ok, msg := a.Login(httptest.NewRecorder(), r2, "admin", "supersecret1"); !ok {
		t.Fatalf("other IP blocked: %s", msg)
	}
}

func TestSessionExpiry(t *testing.T) {
	a, _ := newTestAuth(t)
	_ = a.SetPassword("admin", "supersecret1")

	base := time.Now()
	a.now = func() time.Time { return base }

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/panel/api/login", nil)
	r.RemoteAddr = "7.7.7.7:1"
	if ok, msg := a.Login(rec, r, "admin", "supersecret1"); !ok {
		t.Fatalf("login: %s", msg)
	}
	tok := rec.Result().Cookies()[0].Value

	rq := httptest.NewRequest("GET", "/panel/api/overview", nil)
	rq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tok})
	if _, ok := a.Valid(rq); !ok {
		t.Fatal("fresh session invalid")
	}

	// 越过 TTL → 失效。
	a.now = func() time.Time { return base.Add(2 * time.Hour) }
	if _, ok := a.Valid(rq); ok {
		t.Error("expired session still valid")
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	a, _ := newTestAuth(t)
	_ = a.SetPassword("admin", "supersecret1")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/panel/api/login", nil)
	r.RemoteAddr = "8.8.8.8:1"
	a.Login(rec, r, "admin", "supersecret1")
	tok := rec.Result().Cookies()[0].Value

	rq := httptest.NewRequest("GET", "/panel/api/overview", nil)
	rq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tok})
	if _, ok := a.Valid(rq); !ok {
		t.Fatal("session should be valid before logout")
	}

	a.Logout(httptest.NewRecorder(), rq)
	if _, ok := a.Valid(rq); ok {
		t.Error("session still valid after logout")
	}
}

func TestSetPasswordValidationAndPersistence(t *testing.T) {
	a, uf := newTestAuth(t)
	if err := a.SetPassword("admin", "short"); err == nil {
		t.Error("short password accepted")
	}
	if err := a.SetPassword("", "longenough1"); err == nil {
		t.Error("empty username accepted")
	}
	if err := a.SetPassword("admin", "longenough1"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	// 重新加载（模拟重启）→ 用户仍在，且能登录。
	b, err := New(Config{Enabled: true, UsersFile: uf})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !b.HasUsers() {
		t.Fatal("user lost across restart")
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/panel/api/login", nil)
	r.RemoteAddr = "1.1.1.1:1"
	if ok, msg := b.Login(rec, r, "admin", "longenough1"); !ok {
		t.Fatalf("login after reload: %s", msg)
	}
}

func TestDeleteUserInvalidatesSessions(t *testing.T) {
	a, _ := newTestAuth(t)
	_ = a.SetPassword("admin", "supersecret1")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/panel/api/login", nil)
	r.RemoteAddr = "2.2.2.2:1"
	a.Login(rec, r, "admin", "supersecret1")
	tok := rec.Result().Cookies()[0].Value

	if err := a.DeleteUser("admin"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	rq := httptest.NewRequest("GET", "/panel/api/overview", nil)
	rq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tok})
	if _, ok := a.Valid(rq); ok {
		t.Error("session survived user deletion")
	}
}

func TestDisabledByDefault(t *testing.T) {
	// 缺省（Enabled=false）：不启用，且 Valid 恒 false。
	a, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.Enabled() {
		t.Error("should be disabled by default")
	}
	r := httptest.NewRequest("GET", "/panel/api/overview", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "anything"})
	if _, ok := a.Valid(r); ok {
		t.Error("disabled auth must never validate")
	}
}

func TestNormalizeRejectsBadDurations(t *testing.T) {
	c := Config{Enabled: true, SessionTTL: "not-a-duration"}
	if err := c.Normalize(); err == nil {
		t.Error("bad session_ttl accepted")
	}
	c = Config{Enabled: true, LoginWindow: "xyz"}
	if err := c.Normalize(); err == nil {
		t.Error("bad login_window accepted")
	}
}

func TestClientIPExtraction(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	if got := clientIP(r); got != "10.0.0.1" {
		t.Errorf("clientIP = %q", got)
	}
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	if got := clientIP(r); got != "203.0.113.7" {
		t.Errorf("clientIP xff = %q", got)
	}
	r.Header.Del("X-Forwarded-For")
	r.Header.Set("X-Real-IP", "198.51.100.9")
	if got := clientIP(r); got != "198.51.100.9" {
		t.Errorf("clientIP xri = %q", got)
	}
}

// hexEncode 小工具（避免为一个测试再 import encoding/hex 到主文件语义里）。
func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0xf])
	}
	return string(out)
}
