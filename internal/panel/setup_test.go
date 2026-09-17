package panel

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/webauth"
)

// newEmptyAuthPanel 构建一个**启用了账密但用户库为空**的面板——即刚部署完、
// 尚未初始化的状态。用于测试首次初始化流程。
func newEmptyAuthPanel(t *testing.T) *Panel {
	t.Helper()
	dir := t.TempDir()
	wa, err := webauth.New(webauth.Config{
		Enabled:   true,
		UsersFile: filepath.Join(dir, "web_users.json"),
	})
	if err != nil {
		t.Fatalf("webauth.New: %v", err)
	}
	if wa.HasUsers() {
		t.Fatalf("expected empty user store")
	}
	return New(Config{WebAuth: wa, APIKey: "apikey-xyz"})
}

// setupFirstUser 走公开端点创建首个用户，返回响应记录器。
func setupFirstUser(t *testing.T, p *Panel, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/panel/api/auth/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

// TestSetupCreatesFirstUser 空库时可通过公开端点创建首个用户。
func TestSetupCreatesFirstUser(t *testing.T) {
	p := newEmptyAuthPanel(t)

	rec := setupFirstUser(t, p, `{"username":"admin","password":"firstpass123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"username":"admin"`) {
		t.Errorf("setup body = %s", rec.Body.String())
	}

	// 建好后能登录。
	doLogin(t, p, "admin", "firstpass123")
}

// TestSetupDefaultsToAdmin 用户名为空时回落默认名 admin。
func TestSetupDefaultsToAdmin(t *testing.T) {
	p := newEmptyAuthPanel(t)

	rec := setupFirstUser(t, p, `{"password":"firstpass123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"username":"admin"`) {
		t.Errorf("expected default username admin, got %s", rec.Body.String())
	}
	doLogin(t, p, "admin", "firstpass123")
}

// TestSetupRejectedWhenUserExists 是**最关键的安全测试**：
// 一旦已有用户，公开的 setup 入口必须永久关闭，否则任何人都能静默新建管理员。
func TestSetupRejectedWhenUserExists(t *testing.T) {
	p := newEmptyAuthPanel(t)

	// 先用 setup 建首个用户。
	if rec := setupFirstUser(t, p, `{"username":"admin","password":"firstpass123"}`); rec.Code != http.StatusOK {
		t.Fatalf("first setup failed: %d %s", rec.Code, rec.Body.String())
	}

	// 第二次 setup 必须被拒（不能靠它偷偷加管理账号）。
	second := httptest.NewRequest("POST", "/panel/api/auth/setup",
		strings.NewReader(`{"username":"sneaky","password":"sneakypass1"}`))
	second.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	p.ServeHTTP(rec2, second)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("second setup status = %d (want 403), body = %s", rec2.Code, rec2.Body.String())
	}

	// 那个偷偷建的用户绝不应能登录。
	if tryLogin(p, "sneaky", "sneakypass1") {
		t.Errorf("sneaky user was created despite existing user")
	}
}

// TestSetupValidation setup 的参数校验。
func TestSetupValidation(t *testing.T) {
	cases := []struct{ name, body string }{
		{"密码过短", `{"username":"admin","password":"short"}`},
		{"用户名含空格", `{"username":"ad min","password":"firstpass123"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newEmptyAuthPanel(t)
			rec := setupFirstUser(t, p, c.body)
			if rec.Code == http.StatusOK {
				t.Errorf("expected rejection, got 200: %s", rec.Body.String())
			}
			// 校验失败不应留下任何用户（否则会把初始化入口永久关死）。
			st := httptest.NewRequest("GET", "/panel/api/auth/status", nil)
			recSt := httptest.NewRecorder()
			p.ServeHTTP(recSt, st)
			if !strings.Contains(recSt.Body.String(), `"has_users":false`) {
				t.Errorf("failed setup left a user behind: %s", recSt.Body.String())
			}
		})
	}
}

// TestStatusReportsHasUsers status 必须如实报告 has_users，前端据此决定
// 显示登录框还是初始化表单。
func TestStatusReportsHasUsers(t *testing.T) {
	p := newEmptyAuthPanel(t)

	req := httptest.NewRequest("GET", "/panel/api/auth/status", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"has_users":false`) {
		t.Errorf("empty store: body = %s", rec.Body.String())
	}

	setupFirstUser(t, p, `{"username":"admin","password":"firstpass123"}`)

	rec2 := httptest.NewRecorder()
	p.ServeHTTP(rec2, httptest.NewRequest("GET", "/panel/api/auth/status", nil))
	if !strings.Contains(rec2.Body.String(), `"has_users":true`) {
		t.Errorf("after setup: body = %s", rec2.Body.String())
	}
}
