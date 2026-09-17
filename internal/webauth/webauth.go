// Package webauth 面板的账密登录层（独立于网关 api_key）。
//
// 设计目标与边界：
//   - **与 api_key 解耦**：api_key 是给 OpenAI 兼容客户端用的机器凭证，不适合人用
//     （无用户名、无审计、轮换要改所有客户端）。本包提供"用户名 + 密码"的人用登录，
//     登录成功后发会话 Cookie，与 Bearer 鉴权并行存在、互不影响。
//   - **零外部依赖**：只用标准库。密码哈希用 PBKDF2-HMAC-SHA256（golang.org/x/crypto
//     需要额外依赖，而 stdlib 的 crypto/pbkdf2 在 go1.24+ 才有；此处自带 40 行实现，
//     避免为一个哈希函数引入依赖树）。
//   - **默认关闭**：config 里 web_auth.enabled 为 false 时完全不生效（零回归，老配置
//     行为不变），面板仍走 api_key。
//
// 安全取舍（明确记录，便于审计）：
//   - 会话令牌 32 字节 crypto/rand，落 Cookie 时设 HttpOnly + SameSite=Lax；
//     Secure 标志由 config 控制（面板常裸 HTTP 部署，写死 Secure 会让登录直接不可用）。
//   - 令牌在服务端只存 SHA-256 摘要，不存明文（内存泄露/日志误打印不直接泄令牌）。
//   - 登录失败计数按 IP 限速，防在线爆破（成功登录清零）。
//   - 会话固定过期（默认 12h），不做滑动续期：面板是运维工具，重登成本低，
//     缩短令牌有效窗口收益更大。
package webauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

// Config web_auth 配置段。
type Config struct {
	// Enabled 总开关。false（缺省）= 不启用账密登录，面板仍走 api_key 鉴权。
	Enabled bool `json:"enabled"`
	// Users 用户名 → 密码哈希（由 SetPassword 生成，格式见 hashPassword）。
	// 明文密码绝不落盘。
	Users map[string]string `json:"users"`
	// SessionTTL 会话有效期，Go duration 字符串（如 "12h"）。空 = 12h。
	SessionTTL string `json:"session_ttl"`
	// CookieSecure 会话 Cookie 是否带 Secure 标志。
	// HTTPS 部署应设为 true；纯 HTTP 部署必须 false，否则浏览器不回传 Cookie。
	CookieSecure bool `json:"cookie_secure"`
	// MaxLoginAttempts 单 IP 在 LoginWindow 内的最大失败次数。<=0 = 10。
	MaxLoginAttempts int `json:"max_login_attempts"`
	// LoginWindow 失败计数滑动窗口，Go duration 字符串。空 = 5m。
	LoginWindow string `json:"login_window"`
	// UsersFile 用户库落盘路径（空 = 仅内存，重启丢失）。
	// 与 config.json 分开存：密码哈希不该出现在会被人随手贴出来的配置文件里。
	UsersFile string `json:"users_file"`
}

// Normalize 补齐缺省值并校验。
func (c *Config) Normalize() error {
	if c.SessionTTL == "" {
		c.SessionTTL = "12h"
	}
	if c.LoginWindow == "" {
		c.LoginWindow = "5m"
	}
	if c.MaxLoginAttempts <= 0 {
		c.MaxLoginAttempts = 10
	}
	if _, err := time.ParseDuration(c.SessionTTL); err != nil {
		return fmt.Errorf("web_auth.session_ttl 非法: %w", err)
	}
	if _, err := time.ParseDuration(c.LoginWindow); err != nil {
		return fmt.Errorf("web_auth.login_window 非法: %w", err)
	}
	for u, h := range c.Users {
		if strings.TrimSpace(u) == "" {
			return fmt.Errorf("web_auth.users 存在空用户名")
		}
		if !strings.HasPrefix(h, hashPrefix) {
			return fmt.Errorf("web_auth.users[%s] 不是合法的密码哈希（应用 setpassword 生成）", u)
		}
	}
	return nil
}

// TTL 解析后的会话有效期。
func (c *Config) TTL() time.Duration {
	d, _ := time.ParseDuration(c.SessionTTL)
	if d <= 0 {
		return 12 * time.Hour
	}
	return d
}

// CookieSecure 报告会话 Cookie 是否应带 Secure 标志（面板 csrf.go 复用同一取值）。
func (a *Auth) CookieSecure() bool {
	if a == nil {
		return false
	}
	return a.cfg.CookieSecure
}

// TTL 本鉴权器生效的会话有效期（面板签发 csrf Cookie 时需与之一致）。
func (a *Auth) TTL() time.Duration {
	if a == nil {
		return 12 * time.Hour
	}
	return a.cfg.TTL()
}

// window 解析后的失败计数窗口。
func (c *Config) window() time.Duration {
	d, _ := time.ParseDuration(c.LoginWindow)
	if d <= 0 {
		return 5 * time.Minute
	}
	return d
}

// ---------------------------------------------------------------------------
// 密码哈希：PBKDF2-HMAC-SHA256
// ---------------------------------------------------------------------------

// hashPrefix 哈希格式标识与版本，便于将来换算法时平滑迁移。
const hashPrefix = "pbkdf2-sha256$"

// pbkdf2Iters 迭代次数。OWASP 2023 对 PBKDF2-HMAC-SHA256 的建议下限是 600k；
// 取 600k 在服务器 CPU 上单次约 0.2~0.4s，对登录（低频）可接受，对爆破足够昂贵。
const pbkdf2Iters = 600000

// HashPassword 生成可落盘的密码哈希，格式：
//
//	pbkdf2-sha256$<iters>$<salt_b64>$<dk_b64>
//
// salt 为 16 字节 crypto/rand。
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2SHA256([]byte(password), salt, pbkdf2Iters, 32)
	return fmt.Sprintf("%s%d$%s$%s", hashPrefix, pbkdf2Iters,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// VerifyPassword 常量时间校验密码。哈希格式非法/解析失败一律返回 false（不 panic）。
func VerifyPassword(hash, password string) bool {
	rest, ok := strings.CutPrefix(hash, hashPrefix)
	if !ok {
		return false
	}
	parts := strings.Split(rest, "$")
	if len(parts) != 3 {
		return false
	}
	iters, err := parseUint(parts[0])
	if err != nil || iters <= 0 || iters > 10_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, int(iters), len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// pbkdf2SHA256 RFC 2898 PBKDF2（PRF = HMAC-SHA256）。
// 自带实现的原因见包注释：stdlib 的 crypto/pbkdf2 在 go1.24 才引入，而本项目
// 目标 go1.22；为一个哈希函数引入 x/crypto 依赖树不划算。
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	var buf [4]byte
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf[:], uint32(block))
		prf.Write(buf[:])
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// parseUint 解析十进制非负整数（避免引入 strconv 的额外错误路径）。
func parseUint(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(r-'0')
		if n > 1<<31 {
			return 0, fmt.Errorf("too large")
		}
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// 用户库
// ---------------------------------------------------------------------------

// usersFile 落盘格式（独立于 config.json，见 Config.UsersFile 注释）。
type usersFile struct {
	Users map[string]string `json:"users"`
}

// LoadUsers 从文件读用户库；文件不存在返回空表（不是错误）。
func LoadUsers(path string) (map[string]string, error) {
	if path == "" {
		return map[string]string{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	var f usersFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("解析用户库 %s: %w", path, err)
	}
	if f.Users == nil {
		f.Users = map[string]string{}
	}
	return f.Users, nil
}

// SaveUsers 原子写用户库（tmp + rename，权限 0600）。
func SaveUsers(path string, users map[string]string) error {
	if path == "" {
		return fmt.Errorf("未配置 web_auth.users_file，无法落盘")
	}
	raw, err := json.MarshalIndent(usersFile{Users: users}, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---------------------------------------------------------------------------
// 会话
// ---------------------------------------------------------------------------

// session 一条已登录会话。token 摘要为 SHA-256，明文只存在于客户端 Cookie。
type session struct {
	user    string
	expires time.Time
}

// Auth 账密登录鉴权器（并发安全）。
type Auth struct {
	cfg Config

	mu       sync.Mutex
	sessions map[string]session // tokenSHA256(hex) → session
	users    map[string]string  // 用户名 → 密码哈希

	// 登录失败限速：IP → 失败时刻列表（滑动窗口内计数）。
	fails map[string][]time.Time

	// now 可注入时钟（测试用）。
	now func() time.Time
}

// New 构建鉴权器并加载用户库（UsersFile 优先，回落到 Config.Users 作为初始值）。
func New(cfg Config) (*Auth, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	users, err := LoadUsers(cfg.UsersFile)
	if err != nil {
		return nil, err
	}
	// config 内联用户作为补充（UsersFile 里同名条目优先——文件是运行时 setpassword
	// 的产物，比静态配置新鲜）。
	for u, h := range cfg.Users {
		if _, ok := users[u]; !ok {
			users[u] = h
		}
	}
	return &Auth{
		cfg:      cfg,
		sessions: map[string]session{},
		users:    users,
		fails:    map[string][]time.Time{},
		now:      time.Now,
	}, nil
}

// Enabled 报告账密登录是否启用。
func (a *Auth) Enabled() bool { return a != nil && a.cfg.Enabled }

// HasUsers 报告是否至少有一个可登录用户。
// HasUsers 报告是否已存在任何用户（用于前端判断是否需要走「首次初始化」）。
func (a *Auth) HasUsers() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.users) > 0
}

// CreateFirstUser 创建**首个**用户，仅当当前用户库为空时允许。
//
// 背景（为什么需要它）：登录面板需要账号，而创建账号原先只能从宿主机 CLI
// （`wb2api setpassword`）走——首次部署被迫"SSH 进容器敲命令"，体验割裂。
// 本方法把这一步搬到 Web，部署完直接开浏览器建管理员即可。
//
// 安全性：**只在用户库为空时可调用**。一旦存在任何用户，此入口永久关闭，
// 否则任何人都能通过它静默新建一个管理员账号。这里用"检查 + 写入"在同一把锁内
// 完成来防竞态（两个并发 setup 请求，只有一个能成功）。
//
// 初始用户默认取名为 admin（可自定义），不给它任何特殊权限——目前面板没有角色
// 模型，所有已登录用户等价。保留"首个用户"这一概念纯粹是为了安全引导。
func (a *Auth) CreateFirstUser(username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("用户名不能为空")
	}
	if len(username) > 64 {
		return fmt.Errorf("用户名过长（最多 64 字符）")
	}
	for _, r := range username {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("用户名不能包含空格或控制字符")
		}
	}
	if len(password) < 8 {
		return fmt.Errorf("密码至少 8 位")
	}
	// 哈希在锁外算：HashPassword 开销大（内存硬化），不宜持锁。
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	a.mu.Lock()
	if len(a.users) > 0 {
		a.mu.Unlock()
		// 关键防线：已有用户则拒绝。正常 UI 流程走不到这里，
		// 但直接调 API 的请求会命中，必须挡住。
		return fmt.Errorf("面板已存在用户，初始化入口已关闭")
	}
	if _, exists := a.users[username]; exists {
		a.mu.Unlock()
		return fmt.Errorf("用户名 %q 已存在", username)
	}
	a.users[username] = hash
	snapshot := map[string]string{username: hash}
	a.mu.Unlock()

	return SaveUsers(a.cfg.UsersFile, snapshot)
}

// sessionCookieName 会话 Cookie 名。
const sessionCookieName = "wb2api_session"

// VerifyCredentials 校验用户名+密码是否正确，**不产生任何副作用**。
//
// 与 Login 的区别：不做限速计数、不签发会话。供"改密时校验旧密码"这类场景使用——
// 那些场景复用 Login 会污染登录限速配额（用户改密输错几次就把自己的 IP 锁了）。
func (a *Auth) VerifyCredentials(username, password string) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	hash, exists := a.users[username]
	a.mu.Unlock()
	if !exists {
		// 用户不存在也走一次哈希：保持耗时形状一致，防用户名枚举。
		VerifyPassword(dummyHash, password)
		return false
	}
	return VerifyPassword(hash, password)
}

// Login 校验账密并签发会话。成功返回 true。
// 失败按 IP 限速：窗口内失败次数超限直接拒绝（不进入密码校验，省 CPU 也防爆破）。
func (a *Auth) Login(w http.ResponseWriter, r *http.Request, username, password string) (ok bool, errMsg string) {
	ip := clientIP(r)
	if !a.allowAttempt(ip) {
		return false, "登录尝试过于频繁，请稍后再试"
	}
	a.mu.Lock()
	hash, exists := a.users[username]
	a.mu.Unlock()

	// 用户不存在也走一次哈希校验：避免"用户存在与否"的响应时间差异被用来枚举用户名。
	if !exists {
		VerifyPassword(dummyHash, password)
		a.noteFail(ip)
		return false, "用户名或密码错误"
	}
	if !VerifyPassword(hash, password) {
		a.noteFail(ip)
		return false, "用户名或密码错误"
	}
	a.clearFails(ip)

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return false, "生成会话失败"
	}
	raw := base64.RawURLEncoding.EncodeToString(token)
	exp := a.now().Add(a.cfg.TTL())

	a.mu.Lock()
	a.sessions[tokenKey(raw)] = session{user: username, expires: exp}
	a.gcLocked()
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    raw,
		Path:     "/panel",
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
	})
	return true, ""
}

// Logout 撤销当前会话并清除 Cookie。
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		a.mu.Lock()
		delete(a.sessions, tokenKey(c.Value))
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/panel",
		HttpOnly: true,
		Secure:   a.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// Valid 报告请求是否携带有效会话，并返回用户名。
func (a *Auth) Valid(r *http.Request) (string, bool) {
	if a == nil {
		return "", false
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	key := tokenKey(c.Value)
	a.mu.Lock()
	s, ok := a.sessions[key]
	a.mu.Unlock()
	if !ok {
		return "", false
	}
	if a.now().After(s.expires) {
		a.mu.Lock()
		delete(a.sessions, key)
		a.mu.Unlock()
		return "", false
	}
	return s.user, true
}

// RevokeUserSessions 撤销某用户的**全部**会话（含其他设备），返回撤销数量。
//
// 用途：改密/重置密码后必须调用——否则旧密码泄露场景下，攻击者已建立的会话
// 会在改密后继续存活，改密就失去意义（仅撤销当前会话是不够的）。
func (a *Auth) RevokeUserSessions(username string) int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for k, s := range a.sessions {
		if s.user == username {
			delete(a.sessions, k)
			n++
		}
	}
	return n
}

// SetPassword 设置/更新用户密码（并落盘）。
//
// 注意：本方法**不会**撤销该用户的既有会话——调用方按语义决定：
//   - 管理员重置他人密码 → 应调 RevokeUserSessions（旧密码持有者必须下线）；
//   - 用户自助改密 → 也应 RevokeUserSessions（改密踢全部会话是安全惯例）。
//
// 之所以不在此处隐式撤销：保持方法单一职责，且调用方可能需要在撤销前统计会话数。
func (a *Auth) SetPassword(username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("用户名不能为空")
	}
	if len(password) < 8 {
		return fmt.Errorf("密码至少 8 位")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.users[username] = hash
	snapshot := make(map[string]string, len(a.users))
	for u, h := range a.users {
		snapshot[u] = h
	}
	a.mu.Unlock()
	return SaveUsers(a.cfg.UsersFile, snapshot)
}

// ChangeAccount 在**一次事务**内完成「改用户名 + 改密码」，原子生效。
//
// 为什么需要这个合体方法（而不是让调用方顺序调 RenameUser + SetPassword）：
// 两者各自都会 RevokeUserSessions。若分两步调，第 1 步就把当前会话踢掉了，
// 第 2 步带着已失效的会话发请求必然 401——用户看到的是「改密成功、改名失败」，
// 且已登出无法重试。合体后无论改几项，都在同一次加锁内完成、最后统一撤销会话。
//
// 参数语义：
//   - newName 为空 → 不改名；等于 oldName → 视为不改名（幂等）。
//   - newPassword 为空 → 不改密码。
//
// 校验顺序：先全量校验、后统一落盘。任一项不合法则**不改动任何状态**，
// 避免"名字改了一半、密码没改"的中间态。
func (a *Auth) ChangeAccount(oldName, newName, newPassword string) error {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)

	rename := newName != "" && newName != oldName
	changePwd := newPassword != ""

	// ── 阶段一：纯校验，不持有锁、不改状态 ──────────────────────────────
	if rename {
		if len(newName) > 64 {
			return fmt.Errorf("用户名过长（最多 64 字符）")
		}
		// 禁止空白与控制字符：用户名会出现在日志/审计里，含空格或换行会造成混淆。
		for _, r := range newName {
			if r <= ' ' || r == 0x7f {
				return fmt.Errorf("用户名不能包含空格或控制字符")
			}
		}
	}
	if changePwd && len(newPassword) < 8 {
		return fmt.Errorf("密码至少 8 位")
	}
	if !rename && !changePwd {
		return nil // 无事可做
	}

	// ── 阶段二：持锁改内存状态；失败则整体回滚 ──────────────────────────
	a.mu.Lock()
	hash, ok := a.users[oldName]
	if !ok {
		a.mu.Unlock()
		return fmt.Errorf("用户 %q 不存在", oldName)
	}
	if rename {
		if _, exists := a.users[newName]; exists {
			a.mu.Unlock()
			return fmt.Errorf("用户名 %q 已存在", newName)
		}
	}

	// 先在锁外算出新哈希（HashPassword 开销较大，不宜持锁做）。
	a.mu.Unlock()
	newHash := hash
	if changePwd {
		h, err := HashPassword(newPassword)
		if err != nil {
			return err
		}
		newHash = h
	}

	a.mu.Lock()
	// 重新校验：上锁间隙状态可能被其他请求改动。
	if _, ok := a.users[oldName]; !ok {
		a.mu.Unlock()
		return fmt.Errorf("用户 %q 不存在", oldName)
	}
	if rename {
		if _, exists := a.users[newName]; exists {
			a.mu.Unlock()
			return fmt.Errorf("用户名 %q 已存在", newName)
		}
		delete(a.users, oldName)
		a.users[newName] = newHash
	} else {
		a.users[oldName] = newHash
	}
	// 用户名是会话的身份标识；改名或改密后旧会话一律失效。
	// 改名时按**旧名**撤销（会话里存的还是旧名），并对新名再撤一遍兜底。
	for k, s := range a.sessions {
		if s.user == oldName || (rename && s.user == newName) {
			delete(a.sessions, k)
		}
	}
	snapshot := make(map[string]string, len(a.users))
	for u, h := range a.users {
		snapshot[u] = h
	}
	a.mu.Unlock()

	// ── 阶段三：落盘 ────────────────────────────────────────────────────
	// 落盘失败会把磁盘上的用户库留在旧状态，而内存已是新状态；返回错误让调用方
	// 感知。此处不做内存回滚——进程重启后以磁盘为准，与既有 SetPassword 行为一致。
	return SaveUsers(a.cfg.UsersFile, snapshot)
}

// RenameUser 重命名用户：把 old 的密码哈希搬到 new，并使其既有会话全部失效。
//
// 为什么重命名要踢会话：用户名是会话的身份标识，改名后旧会话携带的是旧身份，
// 继续有效会造成"已改名的用户仍以旧名在操作"的审计混乱。踢掉后重新登录即可。
//
// 注意：**不要用它 + SetPassword 组合实现"同时改用户名的密码"**——
// 两者都会撤销会话，第二步必然因会话失效而失败。请用 ChangeAccount。
func (a *Auth) RenameUser(oldName, newName string) error {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return fmt.Errorf("用户名不能为空")
	}
	if oldName == newName {
		return nil // 幂等：同名视为无操作
	}
	if len(newName) > 64 {
		return fmt.Errorf("用户名过长（最多 64 字符）")
	}
	// 禁止空白与控制字符：用户名会出现在日志/审计里，含空格或换行会造成混淆。
	for _, r := range newName {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("用户名不能包含空格或控制字符")
		}
	}
	a.mu.Lock()
	hash, ok := a.users[oldName]
	if !ok {
		a.mu.Unlock()
		return fmt.Errorf("用户 %q 不存在", oldName)
	}
	if _, exists := a.users[newName]; exists {
		a.mu.Unlock()
		return fmt.Errorf("用户名 %q 已存在", newName)
	}
	delete(a.users, oldName)
	a.users[newName] = hash
	for k, s := range a.sessions {
		if s.user == oldName {
			delete(a.sessions, k)
		}
	}
	snapshot := make(map[string]string, len(a.users))
	for u, h := range a.users {
		snapshot[u] = h
	}
	a.mu.Unlock()
	return SaveUsers(a.cfg.UsersFile, snapshot)
}

// DeleteUser 删除用户并使其所有会话立即失效。
func (a *Auth) DeleteUser(username string) error {
	a.mu.Lock()
	delete(a.users, username)
	for k, s := range a.sessions {
		if s.user == username {
			delete(a.sessions, k)
		}
	}
	snapshot := make(map[string]string, len(a.users))
	for u, h := range a.users {
		snapshot[u] = h
	}
	a.mu.Unlock()
	return SaveUsers(a.cfg.UsersFile, snapshot)
}

// Usernames 返回已配置用户名（排序，供面板展示）。
func (a *Auth) Usernames() []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.users))
	for u := range a.users {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// ActiveSessions 当前有效会话数（面板展示用）。
func (a *Auth) ActiveSessions() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	now := a.now()
	for _, s := range a.sessions {
		if now.Before(s.expires) {
			n++
		}
	}
	return n
}

// tokenKey 会话表键：明文令牌的 SHA-256 摘要（hex）。服务端不存明文。
func tokenKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// gcLocked 清理过期会话（持锁调用）。
func (a *Auth) gcLocked() {
	now := a.now()
	for k, s := range a.sessions {
		if now.After(s.expires) {
			delete(a.sessions, k)
		}
	}
}

// ---------------------------------------------------------------------------
// 失败限速
// ---------------------------------------------------------------------------

// allowAttempt 报告该 IP 是否还有尝试配额。
func (a *Auth) allowAttempt(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := a.now().Add(-a.cfg.window())
	kept := a.fails[ip][:0]
	for _, t := range a.fails[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(a.fails, ip)
		return true
	}
	a.fails[ip] = kept
	return len(kept) < a.cfg.MaxLoginAttempts
}

// noteFail 记录一次失败。
func (a *Auth) noteFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fails[ip] = append(a.fails[ip], a.now())
}

// clearFails 登录成功后清空该 IP 的失败计数。
func (a *Auth) clearFails(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fails, ip)
}

// clientIP 提取客户端 IP（优先 X-Forwarded-For 首段，回落 RemoteAddr）。
// 注意：X-Forwarded-For 可伪造，此处只用于登录限速的粗略归组，不作为安全边界。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// dummyHash 用于"用户不存在"分支的等价耗时校验（见 Login）。
var dummyHash = func() string {
	h, err := HashPassword("dummy-password-for-timing-equalization")
	if err != nil {
		// crypto/rand 失败在此环境不可恢复；回退一个固定形状的哈希。
		return hashPrefix + "600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	return h
}()
