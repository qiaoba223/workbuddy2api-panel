// Package livecfg 运行期可变配置的并发安全持有者。
//
// 背景：进程启动时读入的配置是普通字段（读多写零），但管理面板允许在线改配置，
// 于是少量"可热生效"的字段需要有并发安全的读写点。此处用不可变快照 + atomic 指针：
// 读方 Load 拿到一致视图，写方 Store 整体替换，无锁无数据竞争。
//
// 只承载**读路径深、热改需求强**的少数字段；池参数/排程参数等各有既有 setter
// （pool.SetBreaker、scheduler.Reconfigure 等），不重复收编到这里。
package livecfg

import (
	"sync/atomic"
	"time"
)

// Snapshot 一次读取的不可变配置视图。
type Snapshot struct {
	APIKey               string        // 网关/面板共同鉴权密钥；空 = 不鉴权（主密钥，全模型放行）
	Keys                 []APIKeyEntry // 受限密钥（带模型白名单）
	SoftCooldown         time.Duration // 429 软冷却基数（<=0 时调用方回退内置默认）
	SanitizeFingerprints bool          // 出站请求体指纹脱敏
}

// APIKeyEntry 一个受限访问密钥（带模型白名单）。
//
// 定义放在 livecfg 而非 server，是为了让 cmd/server/config.go 直接复用同一类型：
// server 依赖 livecfg（反向不可），config 又需要 server 类型时会出现环——
// 把共享数据结构沉到最底层的 livecfg，各层引用它即可。
//
// Allow 的匹配规则见 server.allowedModel：裸名默认 cn，可显式写 cn:/global: 区分。
type APIKeyEntry struct {
	Key   string   `json:"key"`
	Name  string   `json:"name,omitempty"`  // 备注名，面板展示用，不参与鉴权
	Allow []string `json:"allow,omitempty"` // 白名单；空 = 不限制
}

// Holder 原子持有当前快照。
type Holder struct {
	p atomic.Pointer[Snapshot]
}

// New 以初始快照构建。
func New(s Snapshot) *Holder {
	h := &Holder{}
	h.Store(s)
	return h
}

// Load 返回当前快照（Holder 为 nil 或从未 Store 时返回零值快照，调用方无需判空）。
func (h *Holder) Load() Snapshot {
	if h == nil {
		return Snapshot{}
	}
	if s := h.p.Load(); s != nil {
		return *s
	}
	return Snapshot{}
}

// Store 整体替换快照。
func (h *Holder) Store(s Snapshot) { h.p.Store(&s) }
