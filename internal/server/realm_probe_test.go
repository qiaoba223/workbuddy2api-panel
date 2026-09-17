package server

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

// TestDynamicModelsProbesCNAccountOnly 回归：CN 模型目录必须只从 CN 账号探测。
//
// 早期实现用 Pool.Pick()（无 realm 过滤），global 账号被抽中时会返回**国际版目录**
// （代号形态 default-model/fast-model/…），于是 /v1/models 的 `cn:` 前缀下出现
// 国际版模型名——而且随选号随机漂移，时对时错极难复现。
func TestDynamicModelsProbesCNAccountOnly(t *testing.T) {
	resetDynamicModelsCache()

	// 两个账号：一个 cn、一个 global。
	// **关键**：让 global 账号积分更高——测试池的随机源恒返回 0，pickWeighted 会选
	// 积分最高者。这样旧实现（Pool.Pick()，无 realm 过滤）**必然**选中 global，
	// 从而稳定复现"CN 列表里出现国际版模型"的 bug；若只依赖随机则可能 flaky 通过。
	cnAcct := &auth.Auth{UID: "cn1", AccessToken: "at1", ExpiresAt: 9999999999, Domain: "copilot.tencent.com"}
	glAcct := &auth.Auth{UID: "gl1", AccessToken: "at2", ExpiresAt: 9999999999, Domain: "www.workbuddy.ai"}
	p := pool.New("")
	p.SetRandomSource(func(n int64) int64 { return 0 })
	p.Add(cnAcct)
	p.Add(glAcct)
	p.SetCredits("cn1", 100, 0)    // 低积分
	p.SetCredits("gl1", 999999, 0) // 高积分 → 无过滤选号必中 global

	// 用 realm 记录每个账号被探测的次数（按 Authorization 头的 token 反查）。
	var mu sync.Mutex
	probedRealms := map[string]int{}
	tokenRealm := map[string]string{"Bearer at1": "cn", "Bearer at2": "global"}
	up := newFakeUpstream(t, func(authz string) (int, string, bool) {
		realm := tokenRealm[authz]
		mu.Lock()
		probedRealms[realm]++
		mu.Unlock()
		if realm == "global" {
			// 国际版目录形态（代号）。
			return 200, `{"code":0,"data":{"models":[{"id":"default-model","maxInputTokens":168000}]}}`, false
		}
		// CN 目录形态（真名）。
		return 200, `{"code":0,"data":{"models":[{"id":"deepseek-v4.1-flash","maxInputTokens":1000000}]}}`, false
	})
	h := NewHandler(Config{Pool: p, Upstream: up, GlobalEnabled: true})

	// 反复请求多次：随机选号下 global 被抽中的概率不低，足以暴露旧实现。
	for i := 0; i < 8; i++ {
		resetDynamicModelsCache()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/models", nil))
		if rec.Code != 200 {
			t.Fatalf("iteration %d: code=%d", i, rec.Code)
		}
		body := rec.Body.String()
		// `cn:` 条目必须是 CN 目录里的真名，绝不能出现国际版代号。
		if strings.Contains(body, `"cn:default-model"`) || strings.Contains(body, `"cn:fast-model"`) {
			t.Fatalf("iteration %d: CN list contains global-realm model names:\n%s", i, body)
		}
		if !strings.Contains(body, `"cn:deepseek-v4.1-flash"`) {
			t.Fatalf("iteration %d: CN model missing from list:\n%s", i, body)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if probedRealms["global"] != 0 {
		t.Errorf("CN model probe touched global account %d times, want 0", probedRealms["global"])
	}
	if probedRealms["cn"] == 0 {
		t.Error("CN model probe never ran")
	}
}

// resetDynamicModelsCache 清空包级模型缓存（测试间隔离）。
func resetDynamicModelsCache() {
	dynamicModelsCache.Lock()
	dynamicModelsCache.ids = nil
	dynamicModelsCache.fetched = time.Time{}
	dynamicModelsCache.lastFail = time.Time{}
	dynamicModelsCache.Unlock()
}

// newFakeUpstreamRealm 已移除：realm 由 Authorization 头（token）反查即可，
// 无需从 *auth.Auth 读取（见 TestDynamicModelsProbesCNAccountOnly 内的 tokenRealm 映射）。
