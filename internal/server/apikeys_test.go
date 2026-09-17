package server

import "testing"

func TestAllowedModel(t *testing.T) {
	cases := []struct {
		name    string
		allow   []string
		model   string
		want    bool
	}{
		// 空白名单 = 全部禁止（安全语义：未配置模型的受限密钥不可用）
		{"空白名单禁止cn", nil, "cn:deepseek-v4.1-flash", false},
		{"空白名单禁止global", nil, "global:deepseek-v4.1-flash", false},
		{"空切片禁止", []string{}, "cn:anything", false},
		{"纯空白条目禁止", []string{" ", "  "}, "cn:x", false},

		// 裸名默认视为 cn
		{"裸名允许裸名请求", []string{"deepseek-v4.1-flash"}, "deepseek-v4.1-flash", true},
		{"裸名允许cn前缀请求", []string{"deepseek-v4.1-flash"}, "cn:deepseek-v4.1-flash", true},
		{"裸名拒绝global请求", []string{"deepseek-v4.1-flash"}, "global:deepseek-v4.1-flash", false},

		// 显式 realm 区分
		{"cn显式允许cn请求", []string{"cn:deepseek-v4.1-flash"}, "cn:deepseek-v4.1-flash", true},
		{"cn显式拒绝global请求", []string{"cn:deepseek-v4.1-flash"}, "global:deepseek-v4.1-flash", false},
		{"global显式允许global请求", []string{"global:deepseek-v4.1-flash"}, "global:deepseek-v4.1-flash", true},
		{"global显式拒绝cn请求", []string{"global:deepseek-v4.1-flash"}, "cn:deepseek-v4.1-flash", false},

		// 多条目
		{"多条目命中其一", []string{"cn:a", "global:b"}, "global:b", true},
		{"多条目都不命中", []string{"cn:a", "global:b"}, "cn:b", false},
		{"多条目裸名+global", []string{"deepseek-v4.1-flash", "global:deepseek-v4.1-flash"}, "cn:deepseek-v4.1-flash", true},

		// 其他模型一律拒绝
		{"白名单外模型拒绝", []string{"cn:deepseek-v4.1-flash"}, "cn:gpt-5", false},

		// 空白容错
		{"空白条目被忽略", []string{"  ", "cn:x"}, "cn:x", true},
		{"前后空格容错", []string{" cn:x "}, "cn:x", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := allowedModel(APIKeyEntry{Key: "k", Allow: c.allow}, c.model)
			if got != c.want {
				t.Errorf("allowedModel(allow=%v, model=%q) = %v, want %v", c.allow, c.model, got, c.want)
			}
		})
	}
}

func TestFindAPIKey(t *testing.T) {
	keys := []APIKeyEntry{
		{Key: "sk-aaa", Name: "a", Allow: []string{"cn:x"}},
		{Key: "sk-bbb", Name: "b", Allow: []string{"global:x"}},
	}
	if e, ok := findAPIKey(keys, "sk-bbb"); !ok || e.Name != "b" {
		t.Errorf("findAPIKey 未命中 sk-bbb: ok=%v name=%q", ok, e.Name)
	}
	if _, ok := findAPIKey(keys, "sk-zzz"); ok {
		t.Error("findAPIKey 对未知 key 应返回 false")
	}
	if _, ok := findAPIKey(keys, ""); ok {
		t.Error("空 key 应返回 false")
	}
	// 空 Key 条目不应匹配空 presented
	if _, ok := findAPIKey([]APIKeyEntry{{Key: "", Name: "empty"}}, ""); ok {
		t.Error("空 key 条目不应命中")
	}
}

func TestCanonicalModelKey(t *testing.T) {
	cases := map[string]string{
		"deepseek-v4.1-flash":        "cn:deepseek-v4.1-flash",
		"cn:deepseek-v4.1-flash":     "cn:deepseek-v4.1-flash",
		"global:deepseek-v4.1-flash": "global:deepseek-v4.1-flash",
		"  cn:x  ":                   "cn:x",
		"weird:model":                "cn:weird:model", // 未知前缀 → cn，整串为 bare
	}
	for in, want := range cases {
		if got := canonicalModelKey(in); got != want {
			t.Errorf("canonicalModelKey(%q) = %q, want %q", in, got, want)
		}
	}
}
