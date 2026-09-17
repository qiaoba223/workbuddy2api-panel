package panel

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/webauth"
)

// loginWithCSRF 登录并返回 (会话Cookie, CSRF令牌)。
func loginWithCSRF(t *testing.T, p *Panel, user, pass string) (*http.Cookie, string) {
	t.Helper()
	body := `{"username":"` + user + `","password":"` + pass + `"}`
	r := httptest.NewRequest("POST", "/panel/api/auth/login", strings.NewReader(body))
	r.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("login status=%d body=%s", rec.Code, rec.Body)
	}
	var sess *http.Cookie
	csrf := ""
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case "wb2api_session":
			sess = c
		case csrfCookieName:
			csrf = c.Value
		}
	}
	if sess == nil {
		t.Fatal("no session cookie")
	}
	if csrf == "" {
		t.Fatal("no csrf cookie issued at login")
	}
	return sess, csrf
}

// TestCSRFCookieIssuedAndNotHttpOnly 登录必须下发可被 JS 读取的 csrf Cookie。
func TestCSRFCookieIssuedAndNotHttpOnly(t *testing.T) {
	p, _ := newAuthPanel(t)
	body := `{"username":"admin","password":"supersecret1"}`
	r := httptest.NewRequest("POST", "/panel/api/auth/login", strings.NewReader(body))
	r.RemoteAddr = "1.2.3.4:1"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, r)

	var csrf *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			csrf = c
		}
	}
	if csrf == nil {
		t.Fatal("csrf cookie not issued")
	}
	if csrf.HttpOnly {
		t.Error("csrf cookie must NOT be HttpOnly (double-submit requires JS access)")
	}
	if csrf.SameSite != http.SameSiteLaxMode {
		t.Errorf("csrf cookie SameSite=%v, want Lax", csrf.SameSite)
	}
	if len(csrf.Value) < 32 {
		t.Errorf("csrf token too short: %d chars", len(csrf.Value))
	}
}

// TestCSRFBlocksStateChangingRequestWithoutToken 缺令牌的改状态请求必须 403。
func TestCSRFBlocksStateChangingRequestWithoutToken(t *testing.T) {
	p, _ := newAuthPanel(t)
	sess, csrf := loginWithCSRF(t, p, "admin", "supersecret1")

	// 带会话 Cookie 但**不带** X-CSRF-Token → 403（模拟 CSRF 攻击）。
	req := httptest.NewRequest("POST", "/panel/api/auth/users",
		strings.NewReader(`{"username":"evil","password":"evilpass123"}`))
	req.AddCookie(sess)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing csrf header: status=%d, want 403", rec.Code)
	}

	// 带上正确令牌 → 通过。
	req = httptest.NewRequest("POST", "/panel/api/auth/users",
		strings.NewReader(`{"username":"ops","password":"opspassword1"}`))
	req.AddCookie(sess)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	req.Header.Set(csrfHeader, csrf)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("with csrf header: status=%d body=%s", rec.Code, rec.Body)
	}
}

// TestCSRFMismatchedTokenRejected 令牌不匹配（伪造值）必须 403。
func TestCSRFMismatchedTokenRejected(t *testing.T) {
	p, _ := newAuthPanel(t)
	sess, csrf := loginWithCSRF(t, p, "admin", "supersecret1")

	req := httptest.NewRequest("POST", "/panel/api/auth/users",
		strings.NewReader(`{"username":"evil","password":"evilpass123"}`))
	req.AddCookie(sess)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	req.Header.Set(csrfHeader, "attacker-guessed-value")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("mismatched csrf: status=%d, want 403", rec.Code)
	}
}

// TestCSRFDoesNotBlockReads GET 读请求不受 CSRF 校验影响。
func TestCSRFDoesNotBlockReads(t *testing.T) {
	p, _ := newAuthPanel(t)
	sess, _ := loginWithCSRF(t, p, "admin", "supersecret1")

	req := httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.AddCookie(sess)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET with session: status=%d, want 200", rec.Code)
	}
}

// TestBearerRejectedInAuthMode 账密模式下 api_key 对面板无效（单通道收敛）。
// 理由：api_key 在 /v1 请求里明文过网，泄露不应连带暴露管理面板。
func TestBearerRejectedInAuthMode(t *testing.T) {
	p, _ := newAuthPanel(t)
	req := httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.Header.Set("Authorization", "Bearer apikey-xyz")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bearer in auth mode: status=%d, want 401", rec.Code)
	}
}

// TestCSRFBearerChannelUnaffected 旧模式（未启用账密）下 Bearer 通道不受 CSRF 影响：
// Bearer 凭据不会被浏览器自动携带，本身免疫 CSRF，强制要求令牌会破坏既有 curl 脚本。
func TestCSRFBearerChannelUnaffected(t *testing.T) {
	p := New(Config{APIKey: "legacy-key"}) // 未启用账密 → 旧模式
	req := httptest.NewRequest("POST", "/panel/api/auth/users",
		strings.NewReader(`{"username":"ops","password":"opspassword1"}`))
	req.Header.Set("Authorization", "Bearer legacy-key")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	// 旧模式下 auth/users 端点自身要求登录会话（webauth 未启用 → 401），
	// 这里只断言"没有被 CSRF 拦成 403"——CSRF 校验只对 Cookie 通道生效。
	if rec.Code == http.StatusForbidden {
		t.Fatalf("bearer should not be blocked by csrf: %d %s", rec.Code, rec.Body)
	}
}

// TestChangePasswordRevokesAllSessions 改密必须踢掉该用户**所有**会话（含其他设备）。
// 回归：早期实现只撤销当前会话，攻击者已建立的会话会在受害者改密后继续存活。
func TestChangePasswordRevokesAllSessions(t *testing.T) {
	p, wa := newAuthPanel(t)

	// 同一用户在两个"设备"上登录。
	dev1, csrf1 := loginWithCSRF(t, p, "admin", "supersecret1")
	dev2, _ := loginWithCSRF(t, p, "admin", "supersecret1")
	if wa.ActiveSessions() != 2 {
		t.Fatalf("want 2 sessions, got %d", wa.ActiveSessions())
	}

	// 设备 1 改密。
	req := httptest.NewRequest("POST", "/panel/api/auth/password",
		strings.NewReader(`{"old_password":"supersecret1","new_password":"brandnewpass1"}`))
	req.AddCookie(dev1)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf1})
	req.Header.Set(csrfHeader, csrf1)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("change password: %d %s", rec.Code, rec.Body)
	}

	// 两个会话都必须失效（不只是发起改密的那一个）。
	if n := wa.ActiveSessions(); n != 0 {
		t.Errorf("after password change want 0 active sessions, got %d", n)
	}
	for name, ck := range map[string]*http.Cookie{"dev1": dev1, "dev2": dev2} {
		req := httptest.NewRequest("GET", "/panel/api/auth/users", nil)
		req.AddCookie(ck)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s session still valid after password change: %d", name, rec.Code)
		}
	}
}

// TestAdminResetRevokesTargetSessions 管理员重置他人密码后，被重置者会话立即下线。
func TestAdminResetRevokesTargetSessions(t *testing.T) {
	p, wa := newAuthPanel(t)
	adminSess, adminCSRF := loginWithCSRF(t, p, "admin", "supersecret1")

	// 建一个用户并让其登录。
	req := httptest.NewRequest("POST", "/panel/api/auth/users",
		strings.NewReader(`{"username":"ops","password":"opspassword1"}`))
	req.AddCookie(adminSess)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: adminCSRF})
	req.Header.Set(csrfHeader, adminCSRF)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body)
	}
	opsSess, _ := loginWithCSRF(t, p, "ops", "opspassword1")

	// 管理员重置 ops 密码。
	req = httptest.NewRequest("POST", "/panel/api/auth/users",
		strings.NewReader(`{"username":"ops","password":"resetpassword9"}`))
	req.AddCookie(adminSess)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: adminCSRF})
	req.Header.Set(csrfHeader, adminCSRF)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("reset password: %d %s", rec.Code, rec.Body)
	}

	// ops 的旧会话必须失效。
	req = httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.AddCookie(opsSess)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("reset user's session still valid: %d", rec.Code)
	}
	// 管理员自己的会话不受影响。
	if n := wa.ActiveSessions(); n != 1 {
		t.Errorf("admin session should survive, active=%d", n)
	}
}

// TestLogoutClearsCSRFCookie 登出同时清掉 csrf Cookie。
func TestLogoutClearsCSRFCookie(t *testing.T) {
	p, _ := newAuthPanel(t)
	sess, csrf := loginWithCSRF(t, p, "admin", "supersecret1")

	req := httptest.NewRequest("POST", "/panel/api/auth/logout", nil)
	req.AddCookie(sess)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	req.Header.Set(csrfHeader, csrf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("logout: %d", rec.Code)
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("csrf cookie not cleared on logout")
	}
}

// TestChangePasswordDoesNotConsumeLoginQuota 改密时输错旧密码**不应**消耗登录限速配额。
//
// 回归：早期实现复用 Login() 校验旧密码，而 Login 内部会 noteFail(ip)——
// 用户在改密对话框里输错几次旧密码，就把自己的 IP 顶到登录限速阈值，
// 之后连正常登录都被拒绝（且错误信息变成"登录尝试过于频繁"，非常困惑）。
func TestChangePasswordDoesNotConsumeLoginQuota(t *testing.T) {
	p, _ := newAuthPanel(t) // MaxLoginAttempts=3（newAuthPanel 用默认，此处单独构造）
	// 用小的限速阈值以便快速触发。
	dir := t.TempDir()
	wa, err := webauth.New(webauth.Config{
		Enabled:          true,
		UsersFile:        filepath.Join(dir, "u.json"),
		MaxLoginAttempts: 3,
		LoginWindow:      "5m",
	})
	if err != nil {
		t.Fatalf("webauth.New: %v", err)
	}
	if err := wa.SetPassword("admin", "supersecret1"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	p = New(Config{WebAuth: wa, APIKey: "k"})

	sess, csrf := loginWithCSRF(t, p, "admin", "supersecret1")

	// 连续 5 次用错误的旧密码尝试改密（超过限速阈值 3）。
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/panel/api/auth/password",
			strings.NewReader(`{"old_password":"wrongold","new_password":"newpassword1"}`))
		req.RemoteAddr = "1.2.3.4:9999"
		req.AddCookie(sess)
		req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
		req.Header.Set(csrfHeader, csrf)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d body=%s, want 401", i, rec.Code, rec.Body)
		}
	}

	// 关键断言：登录配额未被消耗——用正确密码仍能登录。
	body := `{"username":"admin","password":"supersecret1"}`
	req := httptest.NewRequest("POST", "/panel/api/auth/login", strings.NewReader(body))
	req.RemoteAddr = "1.2.3.4:9999"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("login blocked after password-change failures: status=%d body=%s", rec.Code, rec.Body)
	}
}

// TestCSRFFailClosedOnMissingCookie 会话有效但 csrf Cookie 缺失时必须**拒绝**
// （fail-closed），而不是放行。
//
// 回归：早期实现"无 csrf Cookie 就 return true"，导致 csrf Cookie 因任何原因
// （浏览器清理、被逐出）缺失时，CSRF 防护静默失效——会话 Cookie 仍在，
// 改状态请求照常通过。
func TestCSRFFailClosedOnMissingCookie(t *testing.T) {
	p, _ := newAuthPanel(t)
	sess, _ := loginWithCSRF(t, p, "admin", "supersecret1")

	// 只带会话 Cookie，不带 csrf Cookie，也不带头 → 必须 403。
	req := httptest.NewRequest("POST", "/panel/api/balance_all", nil)
	req.AddCookie(sess)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing csrf cookie: status=%d, want 403 (fail-closed)", rec.Code)
	}

	// GET 仍应放行（幂等读）。
	req = httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.AddCookie(sess)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET with session: status=%d, want 200", rec.Code)
	}
}

// TestRenameUser 改名：密码不变、旧名失效、会话踢掉、新名可登录。
func TestRenameUser(t *testing.T) {
	p, wa := newAuthPanel(t)
	sess, csrf := loginWithCSRF(t, p, "admin", "supersecret1")

	req := mutate("POST", "/panel/api/auth/users/admin/rename",
		`{"new_name":"boss"}`, sess, csrf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}

	// 用户列表只剩新名。
	users := wa.Usernames()
	if len(users) != 1 || users[0] != "boss" {
		t.Fatalf("users = %v, want [boss]", users)
	}
	// 旧会话被踢。
	if n := wa.ActiveSessions(); n != 0 {
		t.Errorf("want 0 sessions after rename, got %d", n)
	}
	req = httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.AddCookie(sess)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("old session survived rename: %d", rec.Code)
	}
	// 旧名不能登录，新名可以（密码未变）。
	r := httptest.NewRequest("POST", "/panel/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"supersecret1"}`))
	r.RemoteAddr = "9.9.9.9:1"
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, r)
	if rec.Code == 200 {
		t.Error("old username still works after rename")
	}
	doLogin(t, p, "boss", "supersecret1")
}

// TestRenameUserRejectsDuplicateAndInvalid 重名/非法名必须拒绝。
func TestRenameUserRejectsDuplicateAndInvalid(t *testing.T) {
	p, wa := newAuthPanel(t)
	if err := wa.SetPassword("ops", "opspassword1"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	sess, csrf := loginWithCSRF(t, p, "admin", "supersecret1")

	for _, tc := range []struct{ name, why string }{
		{"ops", "duplicate"},
		{"", "empty"},
		{"bad name", "space"},
	} {
		req := mutate("POST", "/panel/api/auth/users/admin/rename",
			`{"new_name":"`+tc.name+`"}`, sess, csrf)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code == 200 {
			t.Errorf("%s (%q) should be rejected", tc.why, tc.name)
		}
	}
	// 改名幂等：改成同名不算错误。
	req := mutate("POST", "/panel/api/auth/users/admin/rename",
		`{"new_name":"admin"}`, sess, csrf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("same-name rename should be a no-op success, got %d", rec.Code)
	}
}

// TestSessionCookieIsHttpOnlyAndScoped 会话 Cookie 必须 HttpOnly 且限定 /panel 路径。
func TestSessionCookieIsHttpOnlyAndScoped(t *testing.T) {
	p, _ := newAuthPanel(t)
	sess, _ := loginWithCSRF(t, p, "admin", "supersecret1")
	if !sess.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if sess.Path != "/panel" {
		t.Errorf("session cookie path=%q, want /panel", sess.Path)
	}
}

// newAuthPanelWithDir 便于需要直接操作用户库文件的测试。
func newAuthPanelWithDir(t *testing.T) (*Panel, *webauth.Auth, string) {
	t.Helper()
	dir := t.TempDir()
	uf := filepath.Join(dir, "web_users.json")
	wa, err := webauth.New(webauth.Config{Enabled: true, UsersFile: uf})
	if err != nil {
		t.Fatalf("webauth.New: %v", err)
	}
	if err := wa.SetPassword("admin", "supersecret1"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	return New(Config{WebAuth: wa, APIKey: "apikey-xyz"}), wa, uf
}
