package panel

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestAppJSSyntax app.js 必须能通过 JS 解析器语法校验。
//
// 为什么需要：app.js 是 go:embed 进二进制的静态资源，Go 编译器不检查其内容——
// 一次对象字面量键名未加引号（Model_chat_GLM5.2 被解析成属性访问 + 数字字面量）
// 就让整个面板白屏，而所有 Go 测试依然全绿。此测试把语法校验前移到 CI。
// 无 node 环境时跳过（不阻塞无 Node 的构建机）。
func TestAppJSSyntax(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available; skipping JS syntax check")
	}
	path, err := filepath.Abs("app.js")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "--check", path).CombinedOutput()
	if err != nil {
		t.Fatalf("app.js syntax error:\n%s", out)
	}
}

// TestIndexHTMLNoInlineScript index.html 不得含内联 <script> 块：
// 严格 CSP（script-src 'self'）会拦截内联脚本，页面将完全不可用。
// 外链形式 <script src="..."> 允许。
func TestIndexHTMLNoInlineScript(t *testing.T) {
	p := newTestPanel()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/", nil))
	body := rec.Body.String()

	rest := body
	for {
		idx := strings.Index(rest, "<script")
		if idx < 0 {
			break
		}
		rest = rest[idx:]
		end := strings.Index(rest, ">")
		if end < 0 {
			break
		}
		tag := rest[:end+1]
		if !strings.Contains(tag, "src=") {
			t.Fatalf("index.html contains inline <script> (blocked by CSP): %s", tag)
		}
		rest = rest[end:]
	}
}

// TestIndexHTMLCSSVarsDefined index.html 中所有 var(--x) 引用的自定义属性
// 必须在 :root 或 [data-theme="light"] 里有定义。
//
// 为什么需要：曾出现 .keycard 用 var(--bg-2, #fff) —— --bg-2 从未定义，
// 于是夜间模式下该卡片回退到硬编码白色，与深色主题割裂（用户报的 bug）。
// 这类笔误 Go / JS 测试都发现不了，只能靠静态校验兜住。
func TestIndexHTMLCSSVarsDefined(t *testing.T) {
	p := newTestPanel()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/", nil))
	body := rec.Body.String()

	// 1) 收集定义：`--name:` 形式
	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`(--[a-zA-Z0-9_-]+)\s*:`).FindAllStringSubmatch(body, -1) {
		defined[m[1]] = true
	}
	// 2) 收集引用：`var(--name` 形式
	refRe := regexp.MustCompile(`var\(\s*(--[a-zA-Z0-9_-]+)`)
	var missing []string
	seen := map[string]bool{}
	for _, m := range refRe.FindAllStringSubmatch(body, -1) {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		if !defined[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("index.html 引用了未定义的 CSS 变量（夜间模式会回退到硬编码颜色）: %s",
			strings.Join(missing, ", "))
	}
}

// TestKeyModelListShowsCanonicalID 白名单「模型选择」列表项的显示文本必须用
// 归一化后的 id（带 realm 前缀），不得用原始 mid。
//
// 为什么需要：默认模式后端返回 {"id":"deepseek-v4.1-flash"}（无前缀），
// all=1 模式返回 "global:deepseek-v4.1-flash"（带前缀）。曾用 mid(m) 渲染，
// 于是刷新页面显示裸名、点「加载所有账号模型」后又变成带前缀，同一模型两种
// 显示，用户以为加错了（用户报的 bug）。勾选值是 id，显示必须与之一致。
func TestKeyModelListShowsCanonicalID(t *testing.T) {
	path, err := filepath.Abs("app.js")
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)

	// 列表项 <span> 必须输出 esc(id)，不能是 esc(mid(m))。
	if strings.Contains(code, "esc(mid(m))") {
		t.Errorf("app.js 仍以 esc(mid(m)) 渲染列表项，应改为 esc(id)（带前缀，与勾选值一致）")
	}
	if !strings.Contains(code, "esc(id)") {
		t.Errorf("app.js 未发现 esc(id) 渲染，模型列表可能仍显示裸名")
	}
	// 搜索也必须基于归一化 id，否则搜 "global:" 搜不到。
	if strings.Contains(code, "mid(m).toLowerCase().includes") {
		t.Errorf("app.js 搜索仍基于 mid(m)，应改为 idOf(m)（含前缀），否则搜 global:/cn: 匹配不到")
	}
}
