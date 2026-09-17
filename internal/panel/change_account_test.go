package panel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tryLogin 尝试登录，返回是否成功。用于断言"旧凭据不可再登录"这类负向用例
// （doLogin 失败时会 t.Fatal，不能用于此场景）。
func tryLogin(p *Panel, user, pass string) bool {
	body := `{"username":"` + user + `","password":"` + pass + `"}`
	req := httptest.NewRequest("POST", "/panel/api/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec.Code == http.StatusOK
}

// TestChangeAccountSimultaneous 同时改用户名 + 改密码必须一次成功。
//
// 这是针对一个真实回归的测试：早前 /panel/api/auth/account 不存在，前端靠
// 「先 auth/password 再 auth/users/{name}/rename」两步实现。而 auth/password
// 会撤销该用户的**全部**会话（含当前会话），于是第二个 rename 请求带着已失效的
// Cookie 发出、返回 401。用户看到的是"密码改了、用户名没改，还被登出"。
//
// 本测试断言：单次请求即同时生效两项，且改后旧密码/旧用户名都不可再登录。
func TestChangeAccountSimultaneous(t *testing.T) {
	p, _ := newAuthPanel(t)
	cookie, csrf := doLoginCSRF(t, p, "admin", "supersecret1")

	req := mutate("POST", "/panel/api/auth/account",
		`{"old_password":"supersecret1","new_name":"ops","new_password":"brandnewpass1"}`,
		cookie, csrf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change account: status=%d body=%s", rec.Code, rec.Body)
	}

	// 改后当前会话必须失效（改名+改密都应踢会话）。
	req = httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("session still valid after account change: %d", rec.Code)
	}

	// 旧凭据（旧用户名 admin）不可再登录。
	if tryLogin(p, "admin", "brandnewpass1") {
		t.Errorf("old username still logs in")
	}
	if tryLogin(p, "admin", "supersecret1") {
		t.Errorf("old password still logs in")
	}

	// 新凭据（新用户名 ops + 新密码）可登录 —— 两项确实都生效了。
	doLogin(t, p, "ops", "brandnewpass1")
}

// TestChangeAccountOnlyPassword 只改密码（new_name 留空 / 等于原名）不该改名。
func TestChangeAccountOnlyPassword(t *testing.T) {
	p, _ := newAuthPanel(t)
	cookie, csrf := doLoginCSRF(t, p, "admin", "supersecret1")

	for _, body := range []string{
		`{"old_password":"supersecret1","new_password":"brandnewpass1"}`,
		`{"old_password":"supersecret1","new_name":"admin","new_password":"brandnewpass1"}`,
	} {
		p2, _ := newAuthPanel(t)
		c, xs := doLoginCSRF(t, p2, "admin", "supersecret1")
		req := mutate("POST", "/panel/api/auth/account", body, c, xs)
		rec := httptest.NewRecorder()
		p2.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("body=%s status=%d resp=%s", body, rec.Code, rec.Body)
		}
		doLogin(t, p2, "admin", "brandnewpass1")
	}
	_ = cookie
	_ = csrf
}

// TestChangeAccountOnlyRename 只改用户名（new_password 留空）不该动密码。
func TestChangeAccountOnlyRename(t *testing.T) {
	p, _ := newAuthPanel(t)
	cookie, csrf := doLoginCSRF(t, p, "admin", "supersecret1")

	req := mutate("POST", "/panel/api/auth/account",
		`{"old_password":"supersecret1","new_name":"ops"}`, cookie, csrf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename only: status=%d body=%s", rec.Code, rec.Body)
	}
	// 密码不变，用户名变。
	doLogin(t, p, "ops", "supersecret1")
}

// TestChangeAccountRejectsBadOldPassword 旧密码错误 → 401，且不改动任何状态。
func TestChangeAccountRejectsBadOldPassword(t *testing.T) {
	p, _ := newAuthPanel(t)
	cookie, csrf := doLoginCSRF(t, p, "admin", "supersecret1")

	req := mutate("POST", "/panel/api/auth/account",
		`{"old_password":"wrong","new_name":"ops","new_password":"brandnewpass1"}`,
		cookie, csrf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong old password: status=%d, want 401", rec.Code)
	}

	// 会话仍有效（身份未确认，不该踢会话）。
	req = httptest.NewRequest("GET", "/panel/api/auth/users", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("session should stay valid on failed change: %d", rec.Code)
	}
	// 原名原密码仍可用。
	doLogin(t, p, "admin", "supersecret1")
}

// TestChangeAccountRejectsDuplicateName 新用户名已被占用 → 400，且密码不该被改。
func TestChangeAccountRejectsDuplicateName(t *testing.T) {
	p, _ := newAuthPanel(t)
	cookie, csrf := doLoginCSRF(t, p, "admin", "supersecret1")

	// 先建一个 ops。
	req := mutate("POST", "/panel/api/auth/users", `{"username":"ops","password":"opspassword1"}`, cookie, csrf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("create ops: %d %s", rec.Code, rec.Body)
	}

	// 改 admin → ops（已存在），应失败，且密码也不能变（原子性）。
	req = mutate("POST", "/panel/api/auth/account",
		`{"old_password":"supersecret1","new_name":"ops","new_password":"brandnewpass1"}`,
		cookie, csrf)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate name: status=%d, want 400 (body=%s)", rec.Code, rec.Body)
	}
	// 密码未被改动 —— 旧密码仍能登录。
	doLogin(t, p, "admin", "supersecret1")
}

// TestChangeAccountRejectsShortPassword 新密码过短 → 400，且不改名。
func TestChangeAccountRejectsShortPassword(t *testing.T) {
	p, _ := newAuthPanel(t)
	cookie, csrf := doLoginCSRF(t, p, "admin", "supersecret1")

	req := mutate("POST", "/panel/api/auth/account",
		`{"old_password":"supersecret1","new_name":"ops","new_password":"short"}`, cookie, csrf)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short password: status=%d, want 400", rec.Code)
	}
	// 改名也没发生（原子性）：admin 仍存在。
	doLogin(t, p, "admin", "supersecret1")
}

// TestChangeAccountRequiresCSRF 改账号是改状态请求，必须过 CSRF 校验。
func TestChangeAccountRequiresCSRF(t *testing.T) {
	p, _ := newAuthPanel(t)
	cookie, _ := doLoginCSRF(t, p, "admin", "supersecret1")

	req := mutate("POST", "/panel/api/auth/account",
		`{"old_password":"supersecret1","new_password":"brandnewpass1"}`, cookie, "")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing csrf: status=%d, want 403", rec.Code)
	}
}
