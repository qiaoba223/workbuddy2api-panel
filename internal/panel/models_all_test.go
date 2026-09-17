package panel

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// httptestGet 发起带 api_key 鉴权的 GET（面板未启用账密时走 Bearer）。
func httptestGet(t *testing.T, p *Panel, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer k")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

// roundTripFunc 把函数适配成 http.RoundTripper，用于拦截假上游请求。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fakeModelsUpstream 构造一个假 upstream.Client：企业端点按请求路径返回不同模型集，
// /v3/config 返回 404（触发降级），从而 FetchModels 只取企业端点结果。
// 通过 map[路径]模型ID列表 控制每个账号/路径的返回，验证跨账号汇总。
func fakeModelsUpstream(byPath map[string][]string) *upstream.Client {
	return &upstream.Client{
		HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			path := r.URL.Path
			ids, ok := byPath[path]
			if !ok {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"code":404,"msg":"not found"}`)),
				}, nil
			}
			var models []string
			for _, id := range ids {
				models = append(models, `{"id":"`+id+`","maxInputTokens":65536,"maxOutputTokens":8192}`)
			}
			body := `{"code":0,"data":{"models":[` + strings.Join(models, ",") + `],` +
				`"agents":[{"name":"cli","models":` + mustJSON(ids) + `}]}}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		})},
		ChatBaseCN:     "https://fake-cn.example",
		ChatBaseGlobal: "https://fake-global.example",
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestModelsAllAggregatesPerRealmNoDedup 验证 all=1 的核心契约：
// 遍历所有账号、按 realm 分成 cn/global 两组、**不去重**（同名重复保留）。
func TestModelsAllAggregatesPerRealmNoDedup(t *testing.T) {
	p := pool.New("")
	// 两个 cn 账号（其中一个与另一个含同名模型 glm-5.1，验证不去重）
	a1 := &auth.Auth{UID: "cn-1", AccessToken: "at1", Domain: "copilot.tencent.com"}
	a2 := &auth.Auth{UID: "cn-2", AccessToken: "at2", Domain: "copilot.tencent.com"}
	// 一个 global 账号
	a3 := &auth.Auth{UID: "gl-1", AccessToken: "at3", Domain: "workbuddy.ai"}
	for _, a := range []*auth.Auth{a1, a2, a3} {
		p.Add(a)
	}

	// 假上游：按账号 AccessToken 区分返回。企业端点路径对 cn 与 global 不同，
	// 这里用同一个假 client，按 path 返回；不同账号同 path 会拿到同一份——
	// 因此改用「每个账号独立 client」不可行（Client 是共享的）。
	// 折中：让 cn 账号走默认企业路径、global 走 /v2 路径，二者返回不同集合，
	// 而两个 cn 账号拿同一份（因此 cn 组内必然含两份同名模型 → 恰好验证不去重）。
	up := fakeModelsUpstream(map[string][]string{
		"/console/enterprises/personal/models": {"deepseek-v4.1-flash", "glm-5.1"},
		"/v2/enterprises/personal/models":      {"deepseek-v4.1-flash-global", "gemini-3.5-flash"},
	})
	pn := New(Config{Pool: p, Upstream: up, APIKey: "k"})

	rec := httptestGet(t, pn, "/panel/api/models?all=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		OK     bool     `json:"ok"`
		CN     []string `json:"cn"`
		Global []string `json:"global"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if !out.OK {
		t.Fatalf("ok=false: %s", rec.Body.String())
	}

	// 两个 cn 账号 × 各 2 个模型 = 4 条 cn（不去重 → 同名 glm-5.1 出现两次）。
	if len(out.CN) != 4 {
		t.Errorf("cn 组应含 4 条（不去重），实际 %d: %v", len(out.CN), out.CN)
	}
	// 每个 cn 模型都带 cn: 前缀。
	for _, id := range out.CN {
		if !strings.HasPrefix(id, "cn:") {
			t.Errorf("cn 组元素缺少 cn: 前缀: %q", id)
		}
	}
	// 重复项确实保留（glm-5.1 出现 ≥2 次）。
	count := 0
	for _, id := range out.CN {
		if id == "cn:glm-5.1" {
			count++
		}
	}
	if count < 2 {
		t.Errorf("不去重契约失败：cn:glm-5.1 应出现 ≥2 次，实际 %d 次: %v", count, out.CN)
	}
	// global 组：1 个账号 × 2 个模型 = 2 条，带 global: 前缀。
	if len(out.Global) != 2 {
		t.Errorf("global 组应含 2 条，实际 %d: %v", len(out.Global), out.Global)
	}
	for _, id := range out.Global {
		if !strings.HasPrefix(id, "global:") {
			t.Errorf("global 组元素缺少 global: 前缀: %q", id)
		}
	}
}

// TestModelsAllEmptyPool：无账号时返回空组、不报错。
func TestModelsAllEmptyPool(t *testing.T) {
	pn := New(Config{Pool: pool.New(""), Upstream: fakeModelsUpstream(nil), APIKey: "k"})
	rec := httptestGet(t, pn, "/panel/api/models?all=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		OK     bool     `json:"ok"`
		CN     []string `json:"cn"`
		Global []string `json:"global"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.CN) != 0 || len(out.Global) != 0 {
		t.Errorf("空池应返回空组，实际 cn=%v global=%v", out.CN, out.Global)
	}
}
