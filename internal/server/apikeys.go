package server

import (
	"strings"

	"github.com/linguo2625469/workbuddy2api-panel/internal/livecfg"
)

// APIKeyEntry 是 livecfg.APIKeyEntry 的包内别名，便于 server 包各处直接书写。
//
// 设计（PLAN D6 的延伸）：
//   - 老的顶层 api_key 保留为「主密钥」，不受白名单限制（零回归）。
//   - keys[] 里的每个条目是受限密钥，只能访问 Allow 列出的模型。
//   - Allow 为空 = 该密钥不限制（等价于主密钥），便于"先建 key 后配白名单"。
//
// Allow 条目的写法与请求模型名同构，遵循 resolveModel 的归一化规则：
//
//	"deepseek-v4.1-flash"        → cn:deepseek-v4.1-flash（裸名默认 cn）
//	"cn:deepseek-v4.1-flash"     → cn:deepseek-v4.1-flash
//	"global:deepseek-v4.1-flash" → global:deepseek-v4.1-flash
//
// 定义（含 JSON tag）在 livecfg，避免 server ↔ cmd/server 的环依赖。
type APIKeyEntry = livecfg.APIKeyEntry

// canonicalModelKey 把模型名归一化为 "realm:bare" 形式作为白名单比较键。
// 复用 resolveModel 的规则（裸名 → cn；未知前缀 → cn 且保留整串为 bare）。
func canonicalModelKey(model string) string {
	realm, bare := resolveModel(strings.TrimSpace(model))
	return realm + ":" + bare
}

// normalizeAllow 把白名单条目批量归一化为比较键，去重。
// normalizeAllow 把白名单条目批量归一化为比较键，去重。
// 注意：**空白名单返回空集（非 nil）**，表示"不允许任何模型"。
// 安全语义：未配置模型的受限密钥一律 403，避免"忘记勾选 = 全开"的越权。
func normalizeAllow(allow []string) map[string]struct{} {
	set := make(map[string]struct{}, len(allow))
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		set[canonicalModelKey(a)] = struct{}{}
	}
	return set
}

// allowedModel 判断某密钥是否可访问指定模型。
//
// 规则：
//   - allow 为空（未配置白名单）→ 放行（不限制）。
//   - 否则请求模型归一化后必须精确命中白名单。
//
// 精确匹配即可满足当前需求（裸名/cn:/global: 三种写法都已归一化）。
// allowedModel 判断某密钥是否可访问指定模型。
// 空白名单（或全是空串）视为不允许任何模型——受限密钥必须显式配置才能用。
// 说明：主密钥不进入本函数（鉴权阶段已区分），因此"不限制"由主密钥承担。
func allowedModel(entry APIKeyEntry, model string) bool {
	set := normalizeAllow(entry.Allow)
	if len(set) == 0 {
		return false
	}
	_, ok := set[canonicalModelKey(model)]
	return ok
}

// findAPIKey 在 keys[] 中查找与 presented 匹配的条目。
// 返回 (条目, 是否命中)。用常量时间比较避免时序侧信道（自用网关威胁模型有限，
// 但匹配多 key 时顺手做对没有成本）。
func findAPIKey(keys []APIKeyEntry, presented string) (APIKeyEntry, bool) {
	if presented == "" {
		return APIKeyEntry{}, false
	}
	for _, k := range keys {
		if k.Key != "" && subtleEqual(k.Key, presented) {
			return k, true
		}
	}
	return APIKeyEntry{}, false
}

// subtleEqual 定长比较（长度不同立即 false，不泄露内容）。
func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
