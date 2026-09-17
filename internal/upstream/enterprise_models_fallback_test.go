package upstream

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// TestEnterpriseModelsFallsBackToV2 回归：/console 失败时企业端点路应回退 /v2，
// 而不是整路失败（global 域实测 /console 恒 500）。
func TestEnterpriseModelsFallsBackToV2(t *testing.T) {
	var hitConsole, hitV2 bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/console/enterprises/personal/models":
			hitConsole = true
			w.WriteHeader(500)
			w.Write([]byte("boom"))
		case "/v2/enterprises/personal/models":
			hitV2 = true
			writeModelsEnv(w, []string{"deepseek-v4.1-flash", "glm-5.2"}, nil)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := New()
	c.ChatBaseCN = srv.URL
	a := &auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}
	out, err := c.fetchEnterpriseModels(a)
	if err != nil {
		t.Fatalf("want v2 fallback to succeed, got err=%v", err)
	}
	if !hitConsole || !hitV2 {
		t.Fatalf("want both endpoints probed, console=%v v2=%v", hitConsole, hitV2)
	}
	if len(out) != 2 || out[0].ID != "deepseek-v4.1-flash" {
		t.Fatalf("want 2 models incl deepseek-v4.1-flash, got %+v", out)
	}
}

// TestEnterpriseModelsKeepsNonCliModels 回归：上游下发但未登在 agents[cli].models
// 里的对话模型必须保留（早期实现只输出 cliIDs 交集，静默吞掉 deepseek-v4-pro 等）。
func TestEnterpriseModelsKeepsNonCliModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/console/enterprises/personal/models" {
			// models 含 3 条；agents[cli] 只登其中 1 条。
			writeModelsEnv(w,
				[]string{"glm-5.2", "deepseek-v4-pro", "kimi-k2.5"},
				[]string{"glm-5.2"},
			)
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()

	c := New()
	c.ChatBaseCN = srv.URL
	a := &auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}
	out, err := c.fetchEnterpriseModels(a)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	got := map[string]bool{}
	for _, mi := range out {
		got[mi.ID] = true
	}
	// cli 面模型排在最前（零回归），未登记的对话模型补在后面。
	if len(out) != 3 || out[0].ID != "glm-5.2" {
		t.Fatalf("want cli model first then the other 2, got %+v", out)
	}
	for _, want := range []string{"glm-5.2", "deepseek-v4-pro", "kimi-k2.5"} {
		if !got[want] {
			t.Errorf("missing %s in result: %+v", want, out)
		}
	}
}

// TestEnterpriseModelsSkipsNonChat 非对话条目仍须剔除（不得因"全量补齐"回归）。
// 判定口径与真实上游一致：前缀 nes-/completion-/codewise-、maxOutputTokens<=256、
// tags 含 text-to-image（实测 hunyuan-image-* 走 tags、codewise-*/nes-* 走前缀或 256）。
func TestEnterpriseModelsSkipsNonChat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/console/enterprises/personal/models" {
			writeModelsEnvRaw(w, []map[string]any{
				{"id": "glm-5.2", "maxInputTokens": 1000000, "maxOutputTokens": 131072},
				{"id": "nes-gf", "maxOutputTokens": 256},
				{"id": "codewise-jump", "maxOutputTokens": 256},
				{"id": "hunyuan-image-v3.0", "tags": []string{"text-to-image"}},
			}, []string{"glm-5.2"})
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()

	c := New()
	c.ChatBaseCN = srv.URL
	a := &auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}
	out, err := c.fetchEnterpriseModels(a)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if len(out) != 1 || out[0].ID != "glm-5.2" {
		t.Fatalf("non-chat entries must be filtered, got %+v", out)
	}
}

// writeModelsEnv 写一份 /console 形态的模型目录响应（models[] + agents[]）。
func writeModelsEnv(w http.ResponseWriter, ids []string, cliIDs []string) {
	entries := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, map[string]any{
			"id": id, "name": id, "maxInputTokens": 1000000, "maxOutputTokens": 131072,
		})
	}
	writeModelsEnvRaw(w, entries, cliIDs)
}

// writeModelsEnvRaw 同上，但直接给出 models[] 原始条目（用于构造 tags/maxOutputTokens
// 等字段的边界用例）。
func writeModelsEnvRaw(w http.ResponseWriter, entries []map[string]any, cliIDs []string) {
	agents := []map[string]any{}
	if cliIDs != nil {
		agents = append(agents, map[string]any{"name": "cli", "models": cliIDs})
	}
	body, _ := json.Marshal(map[string]any{
		"code": 0,
		"data": map[string]any{"models": entries, "agents": agents},
	})
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}
