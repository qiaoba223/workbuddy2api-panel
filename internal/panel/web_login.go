// web_login.go 面板账密登录路由与处理。
//
// 端点划分（**公开端点必须极简**，其余一律要登录态）：
//
//	GET  /panel/api/auth/status   公开：报告是否启用账密 / 当前是否已登录 / 当前用户名
//	POST /panel/api/auth/login    公开：账密换会话 Cookie（限速 + 常量时间校验）
//	POST /panel/api/auth/logout   需登录：撤销会话
//	POST /panel/api/auth/password 需登录：改自己的密码（需旧密码）
//	GET  /panel/api/auth/users    需登录：列出用户名 + 活跃会话数
//	POST /panel/api/auth/users    需登录：新建/重置某用户密码（管理员操作）
//	DEL  /panel/api/auth/users/{name} 需登录：删除用户
//
// 为什么"改密码"要单独一个需登录端点而不是塞进 config：密码哈希不该进 config.json
// （那是会被人随手贴出来的文件），且改密码是低频操作，走独立端点便于审计。
package panel

import (
	"encoding/json"
	"net/http"
	"strings"
)

// authStatus 报告登录态（前端据此决定是渲染面板还是弹登录框）。
//
// 注意：本端点是公开的，但**不泄露任何敏感信息**——只说"是否启用账密"、
// "你当前是否已登录"、"你是谁"。未登录时 username 为空。
func (p *Panel) authStatus(w http.ResponseWriter, r *http.Request) {
	wa := p.cfg.WebAuth
	out := map[string]any{
		"enabled":  wa.Enabled(),
		"logged_in": false,
	}
	if wa.Enabled() {
		out["has_users"] = wa.HasUsers()
		if user, ok := wa.Valid(r); ok {
			out["logged_in"] = true
			out["username"] = user
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// authSetup 首次初始化：用户库为空时创建首个管理员账号（公开端点）。
//
// 为什么放在 Web 而不是只留 CLI：登录需要账号、建账号需要先登录，是个鸡生蛋。
// 原先只能从宿主机 `docker exec ... setpassword` 打破，导致每次重新部署都要
// SSH 进容器敲命令。本端点用「仅当用户库为空时可用」作为安全约束来打破这个环：
// 部署完直接开浏览器建管理员，之后此入口自动永久关闭。
//
// 安全要点：
//   - 仅当 `HasUsers() == false` 时可用；一旦有用户，CreateFirstUser 内部也会拒绝。
//   - **不受 CSRF 约束**：此刻还没有任何会话/CSRF Cookie，前端拿不到 token。
//     风险可控——因为该端点只能在"空库"这一瞬态下生效，且不返回任何已有信息。
//   - 不校验也不签发会话：建完让用户去登录页显式登录一遍（避免"初始化即登录"被
//     误解为匿名可进）。
func (p *Panel) authSetup(w http.ResponseWriter, r *http.Request) {
	wa := p.cfg.WebAuth
	if !wa.Enabled() {
		writeErr(w, http.StatusNotImplemented, "未启用账密登录（config web_auth.enabled）")
		return
	}
	if wa.HasUsers() {
		writeErr(w, http.StatusForbidden, "面板已存在用户，初始化入口已关闭")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	username := strings.TrimSpace(body.Username)
	if username == "" {
		username = "admin" // 留空则用默认名，省一次输入
	}
	if err := wa.CreateFirstUser(username, body.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"username": username,
	})
}

// authLogin 账密登录：校验成功则签发会话 Cookie。
func (p *Panel) authLogin(w http.ResponseWriter, r *http.Request) {
	wa := p.cfg.WebAuth
	if !wa.Enabled() {
		writeErr(w, http.StatusNotImplemented, "未启用账密登录（config web_auth.enabled）")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	ok, msg := wa.Login(w, r, strings.TrimSpace(body.Username), body.Password)
	if !ok {
		// 401 + 统一文案（不区分"用户不存在"与"密码错误"，防用户名枚举）。
		writeErr(w, http.StatusUnauthorized, msg)
		return
	}
	// 登录成功同时下发 CSRF 双提交令牌（非 HttpOnly，前端读出后回填请求头）。
	if tok := newCSRFToken(); tok != "" {
		setCSRFCookie(w, tok, wa.CookieSecure(), int(wa.TTL().Seconds()))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": body.Username})
}

// authLogout 撤销当前会话。
func (p *Panel) authLogout(w http.ResponseWriter, r *http.Request) {
	p.cfg.WebAuth.Logout(w, r)
	setCSRFCookie(w, "", p.cfg.WebAuth.CookieSecure(), -1) // 一并清掉 csrf 令牌
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// authChangeAccount 修改当前登录用户的用户名和/或密码（一次事务完成）。
//
// 为什么要有这个合体端点：早前端点是分开的（先 auth/password 再 .../rename），
// 而 auth/password 会撤销**全部**会话（含当前会话），导致紧随其后的 rename
// 请求带着已失效的会话发出、返回 401——用户看到"改了密码但用户名没变，还被迫登出"。
// 合体后一次请求原子完成，前端无需关心调用顺序。
//
// 请求体（两项都可选，但至少一项）：
//
//	{"old_password":"...", "new_name":"...", "new_password":"..."}
//
//   - old_password：必填，用于确认身份（防会话令牌被窃后直接锁定账号）。
//   - new_name：留空或等于当前用户名 → 不改名。
//   - new_password：留空 → 不改密码。
func (p *Panel) authChangeAccount(w http.ResponseWriter, r *http.Request) {
	wa := p.cfg.WebAuth
	user, ok := wa.Valid(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "未登录")
		return
	}
	var body struct {
		OldPassword string `json:"old_password"`
		NewName     string `json:"new_name"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	newName := strings.TrimSpace(body.NewName)
	if newName == "" {
		newName = user // 未填视为保持原名
	}
	// 校验旧密码：用 VerifyCredentials（无副作用）而非 Login——后者会消耗登录
	// 限速配额并签发多余会话，导致"输错旧密码"把自己的 IP 限速锁死。
	// 放在最前：身份未确认前不泄露"新用户名是否已存在"这类信息。
	if !wa.VerifyCredentials(user, body.OldPassword) {
		writeErr(w, http.StatusUnauthorized, "当前密码不正确")
		return
	}
	if err := wa.ChangeAccount(user, newName, body.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// ChangeAccount 内部已撤销该用户的全部会话（含当前会话）。
	// 前端收到 relogin 后跳登录页，用新凭据重新登录。
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"relogin":  true,
		"username": newName,
	})
}

// authChangePassword 修改当前登录用户的密码（需提供旧密码）。
// 保留此端点以兼容旧前端/脚本；新前端统一走 auth/account。
func (p *Panel) authChangePassword(w http.ResponseWriter, r *http.Request) {
	wa := p.cfg.WebAuth
	user, ok := wa.Valid(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "未登录")
		return
	}
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	// 校验旧密码：防止会话令牌被窃后直接改密码锁死账号。
	// 用 VerifyCredentials（无副作用）而非 Login——后者会消耗登录限速配额并签发
	// 一个多余会话，导致"改密时输错旧密码"把自己的 IP 限速锁死。
	if !wa.VerifyCredentials(user, body.OldPassword) {
		writeErr(w, http.StatusUnauthorized, "当前密码不正确")
		return
	}
	if err := wa.SetPassword(user, body.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 改密后该用户的**全部**会话立即失效（含其他设备）：旧密码可能已泄露，
	// 只撤销当前会话会让攻击者已建立的会话在改密后继续存活。
	wa.RevokeUserSessions(user)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "relogin": true})
}

// authListUsers 列出用户名与活跃会话数（不返回任何哈希）。
func (p *Panel) authListUsers(w http.ResponseWriter, r *http.Request) {
	wa := p.cfg.WebAuth
	me, _ := wa.Valid(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"users":           wa.Usernames(),
		"me":              me,
		"active_sessions": wa.ActiveSessions(),
	})
}

// authUpsertUser 新建用户或重置密码（管理员操作：已登录即可，无需旧密码）。
func (p *Panel) authUpsertUser(w http.ResponseWriter, r *http.Request) {
	wa := p.cfg.WebAuth
	if _, ok := wa.Valid(r); !ok {
		writeErr(w, http.StatusUnauthorized, "未登录")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if err := wa.SetPassword(strings.TrimSpace(body.Username), body.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 管理员重置他人密码后，被重置者的既有会话必须下线（否则旧密码持有者仍在线）。
	// 重置自己时当前会话也会失效，前端提示需重新登录。
	revoked := wa.RevokeUserSessions(strings.TrimSpace(body.Username))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "users": wa.Usernames(), "revoked_sessions": revoked})
}

// authRenameUser 重命名用户（其既有会话全部失效，需用新用户名重新登录）。
//
// 语义：把 old 的密码哈希搬到 new（密码不变）。改名后旧会话失效——用户名是会话
// 的身份标识，继续有效会造成审计混乱。改自己的名字时当前会话也会失效。
func (p *Panel) authRenameUser(w http.ResponseWriter, r *http.Request) {
	wa := p.cfg.WebAuth
	if _, ok := wa.Valid(r); !ok {
		writeErr(w, http.StatusUnauthorized, "未登录")
		return
	}
	oldName := r.PathValue("name")
	var body struct {
		NewName string `json:"new_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if err := wa.RenameUser(oldName, body.NewName); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "users": wa.Usernames()})
}

// authDeleteUser 删除用户（其全部会话立即失效）。
func (p *Panel) authDeleteUser(w http.ResponseWriter, r *http.Request) {
	wa := p.cfg.WebAuth
	me, ok := wa.Valid(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "未登录")
		return
	}
	name := r.PathValue("name")
	if name == "" {
		writeErr(w, http.StatusBadRequest, "缺少用户名")
		return
	}
	// 不允许删除自己：避免最后一个用户把自己删掉后彻底进不去面板。
	if name == me {
		writeErr(w, http.StatusBadRequest, "不能删除当前登录用户（请用其他账号操作）")
		return
	}
	if err := wa.DeleteUser(name); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "users": wa.Usernames()})
}

