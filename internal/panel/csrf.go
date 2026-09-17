// csrf.go Cookie 鉴权模式下的 CSRF 防护。
//
// 为什么 Cookie 模式需要而 Bearer 模式不需要：
//   - Bearer 鉴权时，凭据在 Authorization 头里，**浏览器不会自动携带**——
//     恶意站点诱导用户点链接，请求也不带那个头，天然免疫 CSRF；
//   - 换成 Cookie 后，浏览器对同源请求**自动带上** Cookie。此时若用户已登录面板，
//     访问 evil.com 上的一张图片 `<img src="http://面板/panel/api/accounts/x/remove">`
//     就会带着 Cookie 发出——CSRF 由此产生。
//
// 防护采用 **双提交令牌（double-submit token）**：
//   1. 登录成功后除会话 Cookie 外，再下发一个**非 HttpOnly** 的 csrf Cookie
//      （前端 JS 必须能读到它，才能把它回填到请求头）；
//   2. 前端对每个**改状态**请求（POST/PUT/DELETE/PATCH）带 `X-CSRF-Token: <cookie值>`；
//   3. 服务端比对「请求头」与「Cookie」是否一致（常量时间比较）。
//
// 攻击者站点为什么伪造不出来：evil.com 的 JS **读不到**面板域的 Cookie（同源策略），
// 而它发出的跨站请求虽然会自动带上 Cookie，却**无法设置自定义请求头**
// （跨域请求带头会触发预检，且它拿不到 csrf 值来填）。
//
// 与 SameSite=Lax 的关系：Lax 已能挡住跨站 POST（浏览器不带 Cookie），是第二道防线；
// 双提交令牌是纵深防御——覆盖 SameSite 被旧浏览器忽略、或将来误改成 None 的情况。
package panel

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

// csrfCookieName 双提交令牌的 Cookie 名。
// **非 HttpOnly**：前端 JS 需要读出来回填请求头（这是双提交模式的前提）。
const csrfCookieName = "wb2api_csrf"

// csrfHeader 前端回填令牌的请求头名。
const csrfHeader = "X-CSRF-Token"

// newCSRFToken 生成 32 字节随机令牌（base64url 无填充）。
func newCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败时宁可拒绝请求也不下发可预测令牌。
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// setCSRFCookie 下发/刷新 CSRF 令牌 Cookie。
func setCSRFCookie(w http.ResponseWriter, token string, secure bool, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/panel",
		HttpOnly: false, // 前端必须可读（双提交模式前提）
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// checkCSRF 校验双提交令牌（仅对改状态方法生效）。
//
// 判定：请求头 X-CSRF-Token 与 Cookie wb2api_csrf 必须**同时存在且相等**。
// GET/HEAD/OPTIONS 不校验（幂等读，无副作用——本面板所有改状态动作都是
// POST/DELETE，已核验无 GET 改状态路由）。
//
// **失败即拒绝（fail-closed）**：缺 Cookie、缺头、不匹配一律 403。
// 早期实现"无 Cookie 就放行"是 fail-open——会话有效但 csrf Cookie 因任何原因
// （被清理、被浏览器逐出、被误删）缺失时，CSRF 防护会**静默失效**。
// 本函数只在已确认会话有效的分支被调用，因此 fail-closed 不会误伤正常用户；
// 令牌丢失时用户重新登录即可（登录会重新下发）。
func checkCSRF(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	c, err := r.Cookie(csrfCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	h := r.Header.Get(csrfHeader)
	if h == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h), []byte(c.Value)) == 1
}
