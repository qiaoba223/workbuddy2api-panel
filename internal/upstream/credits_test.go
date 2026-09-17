package upstream

import "testing"

// TestNormalizeCredits 倍率归一化：上游两种格式必须收敛到同一形态。
func TestNormalizeCredits(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"x0.03", "x0.03"},
		{"x0.23 credits", "x0.23"},
		{"x2.20 credits", "x2.20"},
		{"x0.00 credits", "x0.00"},
		{"  x0.79  ", "x0.79"},
		{"x1.62", "x1.62"},
		{"", ""},
		{"   ", ""},
		{"credits", ""},          // 只有后缀 → 空（不编造）
		{"x0.5 CREDITS", "x0.5"}, // 大小写不敏感
	} {
		if got := NormalizeCredits(tc.in); got != tc.want {
			t.Errorf("NormalizeCredits(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCreditsPrefix 前缀格式（客户端常只读 description）。
func TestCreditsPrefix(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"x0.03", "[x0.03 credit]"},
		{"x0.23 credits", "[x0.23 credit]"},
		{"", ""},
	} {
		if got := CreditsPrefix(tc.in); got != tc.want {
			t.Errorf("CreditsPrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
