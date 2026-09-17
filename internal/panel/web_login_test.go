package panel

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/webauth"
)

// newAuthPanel 构造一个启用了账密登录的面板（无池/上游，只测鉴权层）。
func newAuthPanel(t *testing.T) (*Panel, *webauth.Auth) {
	t.Helper()
	dir := t.TempDir()
	wa, err := webauth.New(webauth.Config{
		Enabled:   true,
		UsersFile: filepath.Join(dir, "web_users.json"),
	})
	if err != nil {
		t.Fatalf("webauth.New: %v", err)
	}
	if err := wa.SetPassword("admin", "supersecret1"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	p := New(Config{WebAuth: wa, APIKey: "apikey-xyz"})
	return p, wa
}

// doLogin 登录并返回会话 Cookie（同时返回 CSRF 令牌，供改状态请求使用）。
func doLogin(t *testing.T, p *Panel, user, pass string) *http.Cookie {
	t.Helper()
	c, _ := doLoginCSRF(t, p, user, pass)
	return c
}

// doLoginCSRF 登录并返回 (会话Cookie, csrf令牌)。
func doLoginCSRF(t *testing.T, p *Panel, user, pass string) (*http.Cookie, string) {
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
		t.Fatal("no session cookie in login response")
	}
	return sess, csrf
}

// mutate 构造一个带会话+CSRF 的改状态请求（CSRF 校验 fail-closed 后，
// 所有 POST/DELETE 测试都必须带上令牌）。
func mutate(method, path, body string, sess *http.Cookie, csrf string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	r.AddCookie(sess)
	r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	r.Header.Set(csrfHeader, csrf)
	return r
}

// TestAuthStatusPublic 公开端点：不泄露敏感信息，只报告启用态与登录态。
func TestAuthStatusPublic(t *testing.T) {
	p, _ := newAuthPanel(t)
	r := httptest.NewRequest("GET", "/panel/api/auth/status", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"enabled":true`) {
		t.Errorf("want enabled:true, got %s", body)
	}
	if !strings.Contains(body, `"logged_in":false`) {
		t.Errorf("want logged_in:false when anonymous, got %s", body)
	}
	// 公开端点绝不能带出用户名单或哈希。
	if strings.Contains(body, "admin") || strings.Contains(body, "pbkdf2") {
		t.Errorf("status endpoint leaks users: %s", body)
	}
}

// TestProtectedAPIRoutesRequireLoginOrKey 保护接口：匿名拒绝，会话通过；
// 账密模式下 Bearer **不再**是面板的有效凭证（单通道收敛，见 withAuth 注释）。
func TestProtectedAPIRoutesRequireLoginOrKey(t *testing.T) {
	p, _ := newAuthPanel(t)

	// 匿名 → 401
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/api/auth/users", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status=%d, want 401", rec.Code)
	}

	// 会话 Cookie → 200
	cookie := doLogin(t, p, "admin", "supersecret1")
	req := httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("session status=%d body=%s", rec.Code, rec.Body)
	}

	// Bearer api_key → 401（账密模式下面板不收 api_key）
	req = httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.Header.Set("Authorization", "Bearer apikey-xyz")
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bearer in auth mode status=%d, want 401", rec.Code)
	}
}

// TestLoginRejectsBadCredentials 错误账密必须 401，且响应不泄露用户是否存在。
func TestLoginRejectsBadCredentials(t *testing.T) {
	p, _ := newAuthPanel(t)
	for _, tc := range []struct{ user, pass string }{
		{"admin", "wrong"},
		{"nosuchuser", "whatever"},
	} {
		body := `{"username":"` + tc.user + `","password":"` + tc.pass + `"}`
		r := httptest.NewRequest("POST", "/panel/api/auth/login", strings.NewReader(body))
		r.RemoteAddr = "7.7.7.7:1"
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, r)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s/%s: status=%d, want 401", tc.user, tc.pass, rec.Code)
		}
	}
}

// TestChangePasswordRequiresOldPassword 改密必须验旧密码，且改后旧会话失效。
func TestChangePasswordRequiresOldPassword(t *testing.T) {
	p, _ := newAuthPanel(t)
	cookie, csrf := doLoginCSRF(t, p, "admin", "supersecret1")

	// 旧密码错误 → 401
	req := mutate("POST", "/panel/api/auth/password",
		`{"old_password":"wrong","new_password":"brandnewpass1"}`, cookie, csrf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong old password: status=%d, want 401", rec.Code)
	}

	// 旧密码正确 → 200
	req = mutate("POST", "/panel/api/auth/password",
		`{"old_password":"supersecret1","new_password":"brandnewpass1"}`, cookie, csrf)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("change password: status=%d body=%s", rec.Code, rec.Body)
	}

	// 旧会话应已失效（改密踢掉所有会话）。
	req = httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("old session still valid after password change: %d", rec.Code)
	}

	// 新密码可登录。
	doLogin(t, p, "admin", "brandnewpass1")
}

// TestUserManagement 增删用户（管理员操作）。
func TestUserManagement(t *testing.T) {
	p, _ := newAuthPanel(t)
	cookie, csrf := doLoginCSRF(t, p, "admin", "supersecret1")

	// 新建用户
	req := mutate("POST", "/panel/api/auth/users", `{"username":"ops","password":"opspassword1"}`, cookie, csrf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "ops") {
		t.Errorf("new user missing from response: %s", rec.Body)
	}

	// 新用户能登录
	opsCookie := doLogin(t, p, "ops", "opspassword1")

	// 删除用户
	req = mutate("DELETE", "/panel/api/auth/users/ops", "", cookie, csrf)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("delete user: %d %s", rec.Code, rec.Body)
	}

	// 被删用户的会话立即失效
	req = httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.AddCookie(opsCookie)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("deleted user's session still valid: %d", rec.Code)
	}
}

// TestCannotDeleteSelf 不允许删自己（防最后一个账号自锁）。
func TestCannotDeleteSelf(t *testing.T) {
	p, _ := newAuthPanel(t)
	cookie, csrf := doLoginCSRF(t, p, "admin", "supersecret1")
	req := mutate("DELETE", "/panel/api/auth/users/admin", "", cookie, csrf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete self: status=%d, want 400", rec.Code)
	}
}

// TestLogoutRevokesCookie 登出后会话失效。
func TestLogoutRevokesCookie(t *testing.T) {
	p, _ := newAuthPanel(t)
	cookie, csrf := doLoginCSRF(t, p, "admin", "supersecret1")

	req := mutate("POST", "/panel/api/auth/logout", "", cookie, csrf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("logout: %d", rec.Code)
	}

	req = httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("session valid after logout: %d", rec.Code)
	}
}

// TestWebAuthDisabledKeepsLegacyBehavior 未启用账密时，鉴权行为与历史完全一致。
func TestWebAuthDisabledKeepsLegacyBehavior(t *testing.T) {
	// 无 WebAuth：仅 Bearer。
	p := New(Config{APIKey: "legacy-key"})
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/api/auth/users", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d, want 401", rec.Code)
	}
	req := httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.Header.Set("Authorization", "Bearer legacy-key")
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("bearer: %d, want 200", rec.Code)
	}
	// auth/status 报告未启用
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/api/auth/status", nil))
	if !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Errorf("want enabled:false, got %s", rec.Body)
	}
	// login 端点返回 501（未启用）
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("POST", "/panel/api/auth/login", strings.NewReader(`{}`)))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("login when disabled: %d, want 501", rec.Code)
	}
}
