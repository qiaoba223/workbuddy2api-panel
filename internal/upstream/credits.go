// credits.go 上游积分倍率字段的归一化与格式化。
//
// 背景：上游对同一语义（模型倍率）下发两种格式——
//
//	"x0.03"          （多数模型）
//	"x0.23 credits"  （部分模型，如 glm-4.6 / deepseek-v3-2-volc / kimi-k2.5）
//
// 原样透出会让面板与 /v1/models 出现格式不一的同一字段（排序、比较、展示都别扭），
// 因此统一归一化为 "x0.03" 形态。
//
// 放在 upstream 包并由 server / panel 共用：两处展示必须同口径，
// 各自实现一份会随时间漂移（面板显示 "x0.23 credits"、API 显示 "x0.23"）。
package upstream

import "strings"

// NormalizeCredits 归一化倍率字段：去尾部 "credits" 后缀与多余空白。
// 空值原样返回（空串），调用方据此省略字段（不编造）。
func NormalizeCredits(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// 去尾部 "credits"（大小写不敏感）。
	if len(s) >= 7 && strings.EqualFold(s[len(s)-7:], "credits") {
		s = strings.TrimSpace(s[:len(s)-7])
	}
	return s
}

// CreditsPrefix 生成 description 前缀（如 "[x0.03 credit]"）；空倍率返回空串。
// 客户端普遍只读 description 不读 credits 字段，前缀保证倍率在两种读法下都可见。
func CreditsPrefix(raw string) string {
	s := NormalizeCredits(raw)
	if s == "" {
		return ""
	}
	return "[" + s + " credit]"
}
