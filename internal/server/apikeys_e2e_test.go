package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/livecfg"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

// liveWithKeys 构造一个只含鉴权字段的 Live holder（其余走零值默认）。
func liveWithKeys(main string, entries ...APIKeyEntry) *livecfg.Holder {
	h := livecfg.New(livecfg.Snapshot{APIKey: main, Keys: entries})
	return h
}

// TestWithAuth_MultiKey 覆盖鉴权层的三种结果：主密钥放行、受限密钥放行、无匹配拒绝。
func TestWithAuth_MultiKey(t *testing.T) {
	live := liveWithKeys("main-key",
		APIKeyEntry{Key: "k-cn", Name: "cn-only", Allow: []string{"cn:deepseek-v4.1-flash"}})

	h := NewHandler(Config{
		Pool:     pool.New(""),
		Upstream: newFakeUpstream(t, func(string) (int, string, bool) { return 200, sseOK, true }),
		Live:     live,
	})
	called := false
	guarded := h.withAuth(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(204) })

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"主密钥放行", "Bearer main-key", 204},
		{"受限密钥放行", "Bearer k-cn", 204},
		{"未知密钥拒绝", "Bearer nope", 401},
		{"无 Authorization 拒绝", "", 401},
		{"只给了前几位拒绝", "Bearer k-c", 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			r := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			guarded(rec, r)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == 204 && !called {
				t.Fatal("放行时下游未被调用")
			}
		})
	}
}

// TestWithAuth_XApiKeyHeader 兼容 x-api-key 头（部分客户端不用 Bearer）。
func TestWithAuth_XApiKeyHeader(t *testing.T) {
	live := liveWithKeys("main-key", APIKeyEntry{Key: "k-cn", Allow: []string{"cn:x"}})
	h := NewHandler(Config{Pool: pool.New(""), Live: live})
	guarded := h.withAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })

	r := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	r.Header.Set("X-Api-Key", "k-cn")
	rec := httptest.NewRecorder()
	guarded(rec, r)
	if rec.Code != 204 {
		t.Fatalf("x-api-key 未被识别，status = %d", rec.Code)
	}
}

// TestWithAuth_EmptyMainKey_DisablesAuth 主密钥为空 = 关闭鉴权（历史行为，零回归）。
func TestWithAuth_EmptyMainKey_DisablesAuth(t *testing.T) {
	h := NewHandler(Config{Pool: pool.New(""), Live: livecfg.New(livecfg.Snapshot{})})
	guarded := h.withAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	rec := httptest.NewRecorder()
	guarded(rec, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if rec.Code != 204 {
		t.Fatalf("空主密钥应不鉴权，status = %d", rec.Code)
	}
}

// TestChat_WhitelistForbidden 越权模型在 chatCompletions 层被 403，
// 且错误信息包含可定位的信息（备注名 + 请求模型）。
func TestChat_WhitelistForbidden(t *testing.T) {
	live := liveWithKeys("main-key",
		APIKeyEntry{Key: "k-cn", Name: "cn-only", Allow: []string{"cn:deepseek-v4.1-flash"}})
	upstreamHit := false
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		upstreamHit = true
		return 200, sseOK, true
	})
	h := NewHandler(Config{Pool: pool.New(""), Upstream: up, Live: live})

	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"global:deepseek-v4.1-flash","messages":[{"role":"user","content":"hi"}]}`))
	r.Header.Set("Authorization", "Bearer k-cn")
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("越权应 403，得到 %d (body=%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "model_not_allowed") || !strings.Contains(body, "cn-only") {
		t.Fatalf("错误信息缺少定位信息: %s", body)
	}
	if upstreamHit {
		t.Fatal("越权请求不应触达上游（会白耗额度/罚号）")
	}
}

// TestChat_WhitelistAllowed 白名单内模型正常放行（不因加了过滤而误伤）。
func TestChat_WhitelistAllowed(t *testing.T) {
	live := liveWithKeys("main-key",
		APIKeyEntry{Key: "k-cn", Allow: []string{"cn:deepseek-v4.1-flash"}})
	h := NewHandler(Config{
		Pool:     pool.New(""),
		Upstream: newFakeUpstream(t, func(string) (int, string, bool) { return 200, sseOK, true }),
		Live:     live,
	})

	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"cn:deepseek-v4.1-flash","messages":[{"role":"user","content":"hi"}],"stream":true}`))
	r.Header.Set("Authorization", "Bearer k-cn")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	// 本测试的 pool 无健康账号，放行后会停在选号阶段返回 503。
	// 关键断言：不能被 403 拦下（403 才代表白名单误伤）。
	if rec.Code == http.StatusForbidden {
		t.Fatalf("白名单内模型被误拦截: %s", rec.Body.String())
	}
}

// TestModels_WhitelistFilter /v1/models 对受限密钥只返回白名单内模型。
func TestModels_WhitelistFilter(t *testing.T) {
	live := liveWithKeys("main-key",
		APIKeyEntry{Key: "k-one", Allow: []string{"cn:glm-5.2"}})
	h := NewHandler(Config{Pool: pool.New(""), Live: live})

	// 先确认全量列表里确实有多个模型（否则本测试无意义）。
	all := h.modelList()
	if len(all) < 2 {
		t.Skipf("模型数过少(%d)，跳过过滤测试", len(all))
	}

	r := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	r.Header.Set("Authorization", "Bearer k-one")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var got struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("解析响应失败: %v (body=%s)", err, rec.Body.String())
	}
	if len(got.Data) != 1 {
		t.Fatalf("白名单只含 1 个模型，返回 %d 个: %+v", len(got.Data), got.Data)
	}
	if id, _ := got.Data[0]["id"].(string); canonicalModelKey(id) != "cn:glm-5.2" {
		t.Fatalf("返回了白名单外的模型: %v", got.Data[0]["id"])
	}
}

// TestModels_MainKeySeesAll 主密钥不受过滤（零回归）。
func TestModels_MainKeySeesAll(t *testing.T) {
	h := NewHandler(Config{Pool: pool.New(""), Live: liveWithKeys("main-key")})
	want := len(h.modelList())

	r := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	r.Header.Set("Authorization", "Bearer main-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	var got struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("解析响应失败: %v (body=%s)", err, rec.Body.String())
	}
	if len(got.Data) != want {
		t.Fatalf("主密钥应看到全部 %d 个模型，实际 %d", want, len(got.Data))
	}
}

// TestModels_EmptyAllowSeesNone 空白名单的受限密钥：/v1/models 返回空列表，
// 且调用任何模型都会 403（安全语义：未配置模型 = 不可用，避免"忘记勾选 = 全开"越权）。
func TestModels_EmptyAllowSeesNone(t *testing.T) {
	live := liveWithKeys("main-key", APIKeyEntry{Key: "k-open"}) // 无 Allow
	h := NewHandler(Config{Pool: pool.New(""), Live: live})

	r := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	r.Header.Set("Authorization", "Bearer k-open")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	var got struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("解析响应失败: %v (body=%s)", err, rec.Body.String())
	}
	if len(got.Data) != 0 {
		t.Fatalf("空白名单应看不到任何模型，实际 %d", len(got.Data))
	}
}

// TestModels_ManualAllowListed 白名单里"上游动态目录未列出"的模型也要出现在
// /v1/models 中（如手动添加的 global:deepseek-v4.1-flash——上游可用但 /v3/config 不列），
// 否则客户端看不到、无从选择；而实际调用是通的。补全项带 manual:true 标识。
func TestModels_ManualAllowListed(t *testing.T) {
	live := liveWithKeys("main-key",
		APIKeyEntry{Key: "k-manual", Allow: []string{"global:deepseek-v4.1-flash"}})
	h := NewHandler(Config{Pool: pool.New(""), Live: live})

	r := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	r.Header.Set("Authorization", "Bearer k-manual")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var got struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("解析响应失败: %v (body=%s)", err, rec.Body.String())
	}
	var found map[string]any
	for _, m := range got.Data {
		if id, _ := m["id"].(string); id == "global:deepseek-v4.1-flash" {
			found = m
		}
	}
	if found == nil {
		t.Fatalf("手动添加的白名单模型未出现在 /v1/models：%+v", got.Data)
	}
	if manual, _ := found["manual"].(bool); !manual {
		t.Fatalf("补全项应带 manual:true，实际 %+v", found)
	}
	if owned, _ := found["owned_by"].(string); owned != "global" {
		t.Fatalf("owned_by 应为 global，实际 %q", owned)
	}
}
