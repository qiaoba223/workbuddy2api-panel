'use strict';
/* ── 状态 ─────────────────────────────────────────────────────────── */
const LS_KEY = 'wb2api.key', LS_THEME = 'wb2api.theme';
let theme = localStorage.getItem(LS_THEME) || 'auto';   // auto | light | dark
let view = 'accounts';
let overviewData = null, cfgLoaded = null;
let logPin = true, loginState = null, loginTimer = null;
let refTimer = null;
let meUser = '';        // 当前登录用户名（账号设置对话框预填用）

const $ = id => document.getElementById(id);

/* ── 主题 ─────────────────────────────────────────────────────────── */
/* 两态翻转（浅/深），首次访问跟随系统偏好；点击总是切换可见外观，符合直觉。 */
function effTheme() {
  return theme === 'auto' ? (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark') : theme;
}
function applyTheme() {
  const eff = effTheme();
  document.documentElement.dataset.theme = eff;
  $('icoTheme').innerHTML = eff === 'light'
    ? '<circle cx="8" cy="8" r="3"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.2 3.2l1.4 1.4M11.4 11.4l1.4 1.4M12.8 3.2l-1.4 1.4M4.6 11.4l-1.4 1.4"/>'
    : '<path d="M13.2 9.6A5.6 5.6 0 0 1 6.4 2.8a5.6 5.6 0 1 0 6.8 6.8z"/>';
  $('btnTheme').title = eff === 'light' ? '切换到深色' : '切换到浅色';
}
addEventListener('change', applyTheme);
$('btnTheme').onclick = () => {
  theme = effTheme() === 'light' ? 'dark' : 'light';
  localStorage.setItem(LS_THEME, theme);
  applyTheme();
};
applyTheme();

/* ── 请求 ─────────────────────────────────────────────────────────── */
function readCookie(name) {
  const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[.$?*|{}()[\]\\/+^]/g, '\\$&') + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}

async function api(path, opts = {}) {
  const h = Object.assign({}, opts.headers || {});
  // 账密模式：靠 HttpOnly 会话 Cookie 鉴权（浏览器自动携带），前端不接触密钥。
  // key 模式：仍发 Bearer（老行为，零回归）。
  if (authMode !== 'session') {
    const k = localStorage.getItem(LS_KEY);
    if (k) h['Authorization'] = 'Bearer ' + k;
  } else {
    // CSRF 双提交令牌：改状态请求必须回填（见后端 csrf.go）。
    // Cookie 是非 HttpOnly 的，这里读出来放进请求头，服务端比对两者是否一致。
    const m = (opts.method || 'GET').toUpperCase();
    if (m !== 'GET' && m !== 'HEAD' && m !== 'OPTIONS') {
      const t = readCookie('wb2api_csrf');
      if (t) h['X-CSRF-Token'] = t;
    }
  }
  if (opts.body) h['Content-Type'] = 'application/json';
  const r = await fetch('/panel/api/' + path, Object.assign({}, opts, { headers: h }));
  if (r.status === 401) {
    // authMode 兜底：'none' 表示 gate() 还没跑完（不该发生，见文件末尾启动顺序），
    // 此时**不能**臆断是 key 模式——否则会话失效会弹错对话框。按会话模式处理更安全
    // （服务端 auth/status 是权威；账密模式下 401 一律回登录框）。
    if (authMode !== 'key') {
      $('appShell').hidden = true;
      $('btnLogout').hidden = true;
      $('btnPwd').hidden = true;
      $('meName').textContent = '';
      meUser = '';
      openLogin();
      throw new Error('登录已过期，请重新登录');
    }
    openKey(); throw new Error('密钥无效或未填写');
  }
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}
function toast(msg, cls) {
  const el = document.createElement('div');
  el.className = 'tst ' + (cls || '');
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3600);
}
// esc 文本/属性双安全转义。不能只用 div.innerHTML（它转义 <>& 但不转义引号），
// 否则字符串拼进 HTML 属性（如 title="uid: ..."）时引号可闭合属性并注入事件处理器。
// 显式替换 5 个字符：& < > " '（& 必须最先，避免二次转义）。
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
function ago(iso) {
  if (!iso || iso.startsWith('0001-')) return '—';
  const s = (Date.now() - new Date(iso)) / 1000;
  if (s < 0) return '刚刚';
  if (s < 60) return Math.floor(s) + ' 秒前';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
  if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
  return Math.floor(s / 86400) + ' 天前';
}
function dur(sec) {
  sec = Math.max(0, Math.round(sec));
  const h = Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
  return h ? h + '时' + String(m).padStart(2, '0') + '分' : m ? m + '分' + String(s).padStart(2, '0') + '秒' : s + '秒';
}

function formatTokenCount(tokens) {
  if (tokens == null || tokens === '') return '—';
  const n = Number(tokens);
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n < 1000) return String(Math.round(n));
  const units = [['k', 1e3], ['m', 1e6], ['b', 1e9]];
  let unit = units[0];
  for (const candidate of units) {
    if (n >= candidate[1]) unit = candidate;
  }
  let value = n / unit[1];
  let rounded = Number(value.toFixed(1));
  // 999999 → 1m，而不是 1000k；四舍五入后自动升级单位。
  const next = units[units.indexOf(unit) + 1];
  if (next && rounded >= 1000) {
    unit = next;
    value = n / unit[1];
    rounded = Number(value.toFixed(1));
  }
  return rounded + unit[0];
}

function formatLatency(ms) {
  if (ms == null || ms === '') return '—';
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return '—';
  return n < 1000 ? Math.round(n) + 'ms' : (n / 1000).toFixed(1).replace(/\.0$/, '') + 's';
}
function formatRate(rate) {
  if (rate == null || rate === '') return '—';
  const n = Number(rate);
  if (!Number.isFinite(n) || n < 0) return '—';
  return n.toFixed(1) + 'tok/s';
}

/* ── 登录门 ───────────────────────────────────────────────────────── */
/* 两条鉴权通道（与后端 withAuth 对应）：
   - 账密登录启用时：走 /panel/api/auth/login 换会话 Cookie（HttpOnly，JS 读不到），
     此后所有 api() 请求靠浏览器自动带 Cookie，前端不接触任何密钥；
   - 未启用时：退回 api_key 输入框（老行为）。
   启动时先问 /panel/api/auth/status 决定弹哪个门。 */
let authMode = 'none';   // 'session' | 'key' | 'none'

function openKey() { $('keyVeil').classList.add('on'); setTimeout(() => $('keyInput').focus(), 60); }
$('btnKey').onclick = async () => {
  const v = $('keyInput').value.trim();
  if (!v) return;
  localStorage.setItem(LS_KEY, v);
  try {
    await api('overview');
    $('keyErr').hidden = true;
    $('keyVeil').classList.remove('on');
    start();
  } catch (e) { $('keyErr').hidden = false; }
};
$('keyInput').addEventListener('keydown', e => { if (e.key === 'Enter') $('btnKey').click(); });

/* 登录框 */
// setupMode：登录框处于「首次初始化」态（用户库为空）。此时按钮变成「创建账号」，
// 多出一个确认密码框，提交打到 auth/setup 而不是 auth/login。
let setupMode = false;

function openLogin() {
  $('loginVeil').classList.add('on');
  setTimeout(() => $('loginUser').focus(), 60);
}

// enterSetupMode 把登录框切换成首次初始化表单。
function enterSetupMode() {
  setupMode = true;
  $('loginTitle').textContent = '初始化面板';
  $('loginHint').textContent = '首次使用，请创建管理员账号。创建后此入口自动关闭。';
  $('loginUser').value = 'admin';           // 默认名，可改
  $('loginPass').placeholder = '设置密码（至少 8 位）';
  $('loginPass2').hidden = false;
  $('btnLogin').textContent = '创建账号';
}

$('btnLogin').onclick = doLogin;
$('loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') setupMode ? $('loginPass2').focus() : doLogin(); });
$('loginPass2').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
$('loginUser').addEventListener('keydown', e => { if (e.key === 'Enter') $('loginPass').focus(); });

/* 伪密码框降级：不支持 -webkit-text-security 的浏览器（少见）会显示明文。
   此时退回到"真密码框 + 关闭自动填充"，至少视觉安全。
   检测方式：设置该属性后读取是否生效。 */
(function secretFallback() {
  const probe = document.createElement('input');
  probe.style.webkitTextSecurity = 'disc';
  // Chrome/Safari/微信 WebView 支持；Firefox 长期不支持。
  if (probe.style.webkitTextSecurity !== 'disc') {
    document.querySelectorAll('.secret').forEach(el => { el.type = 'password'; });
  }
})();

async function doLogin() {
  const u = $('loginUser').value.trim(), p = $('loginPass').value;
  if (!u || !p) return;
  const btn = $('btnLogin');

  // ── 首次初始化：校验两次密码一致后调 auth/setup ────────────────────
  if (setupMode) {
    const p2 = $('loginPass2').value;
    const fail = m => { $('loginErr').textContent = m; $('loginErr').hidden = false; };
    if (p.length < 8) return fail('密码至少 8 位');
    if (p !== p2) return fail('两次输入的密码不一致');

    btn.disabled = true; btn.textContent = '创建中…';
    try {
      const r = await fetch('/panel/api/auth/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
      // 建完不自动登录（后端也不签会话）：切回普通登录态，让用户显式登一次。
      // 这样"初始化"和"进入面板"是两个明确动作，不会让匿名访问误以为已进后台。
      setupMode = false;
      $('loginTitle').textContent = '登录';
      $('loginHint').textContent = '账号已创建，请用刚才的凭据登录。';
      $('loginPass').placeholder = '密码';
      $('loginPass2').hidden = true;
      $('loginPass2').value = '';
      $('loginPass').value = '';
      $('loginErr').hidden = true;
      $('btnLogin').textContent = '登录';
      toast('管理员账号已创建，请登录', 'ok');
      setTimeout(() => $('loginPass').focus(), 60);
    } catch (e) {
      fail(e.message || '创建失败');
    } finally { btn.disabled = false; if (setupMode) btn.textContent = '创建账号'; }
    return;
  }

  // ── 常规登录 ────────────────────────────────────────────────────────
  btn.disabled = true; btn.textContent = '登录中…';
  try {
    const r = await fetch('/panel/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    $('loginPass').value = '';
    $('loginErr').hidden = true;
    $('loginVeil').classList.remove('on');
    // 登录成功才显示面板骨架（未登录时始终保持 hidden）。
    $('appShell').hidden = false;
    $('btnLogout').hidden = false;
    $('btnPwd').hidden = false;
    meUser = d.username || u;
    $('meName').textContent = meUser;
    toast('已登录：' + (d.username || u), 'ok');
    // 走与启动路径相同的入口：绑定导航 + 首次路由渲染 + 启动轮询。
    // （早期这里只调 start()，导致登录后导航点击无效——见 enterPanel 注释。）
    enterPanel();
  } catch (e) {
    $('loginErr').textContent = e.message || '登录失败';
    $('loginErr').hidden = false;
  } finally { btn.disabled = false; btn.textContent = '登录'; }
}

async function doLogout() {
  try {
    // 走 api() 以便自动带上 CSRF 令牌（logout 是改状态 POST，受双提交校验保护）。
    await api('auth/logout', { method: 'POST' });
  } catch (e) { /* 忽略：无论成功与否都回登录页 */ }
  location.reload();
}

/* 账号设置（改用户名 / 改密码） */
function openPwd() {
  $('pwdUser').value = meUser;
  $('pwdOld').value = ''; $('pwdNew').value = ''; $('pwdNew2').value = '';
  $('pwdErr').hidden = true;
  $('pwdVeil').classList.add('on');
  setTimeout(() => $('pwdOld').focus(), 60);
}
function closePwd() { $('pwdVeil').classList.remove('on'); }
$('btnPwdCancel').onclick = closePwd;
$('btnPwd').onclick = openPwd;
$('pwdNew2').addEventListener('keydown', e => { if (e.key === 'Enter') $('btnPwdSave').click(); });

async function doSaveAccount() {
  const newUser = $('pwdUser').value.trim();
  const oldP = $('pwdOld').value;
  const n1 = $('pwdNew').value, n2 = $('pwdNew2').value;
  const err = $('pwdErr');
  const fail = m => { err.textContent = m; err.hidden = false; };

  const wantRename = newUser && newUser !== meUser;
  const wantPwd = !!n1;

  if (!newUser) return fail('用户名不能为空');
  if (!oldP) return fail('请输入当前密码');
  if (!wantRename && !wantPwd) return fail('没有需要修改的内容');
  if (wantPwd) {
    if (n1.length < 8) return fail('新密码至少 8 位');
    if (n1 !== n2) return fail('两次输入的新密码不一致');
    if (n1 === oldP) return fail('新密码不能与当前密码相同');
  }

  const btn = $('btnPwdSave');
  btn.disabled = true; btn.textContent = '保存中…';
  try {
    // 一个请求同时改用户名和密码。**不要**拆成两次调用：
    // 改密会撤销全部会话（含当前会话），第二个请求必然 401，
    // 结果是"密码改了、用户名没改，还被登出"。
    await api('auth/account', {
      method: 'POST',
      body: JSON.stringify({
        old_password: oldP,
        new_name: newUser,
        new_password: n1,   // 空字符串 = 不改密码
      }),
    });
    closePwd();
    toast('已保存，请用新凭据重新登录', 'ok');
    // 改密/改名都会踢掉全部会话：等提示显示后再跳登录页。
    setTimeout(() => location.reload(), 1200);
  } catch (e) {
    fail(e.message || '保存失败');
  } finally { btn.disabled = false; btn.textContent = '保存'; }
}
$('btnPwdSave').onclick = doSaveAccount;

/* 登录门判定：账密启用且未登录 → 登录框；否则沿用 api_key 门。
   未登录时 #appShell 保持 hidden（HTML 里默认 hidden）——登录前不渲染任何面板内容。 */
async function gate() {
  let st = null;
  try {
    const r = await fetch('/panel/api/auth/status');
    st = await r.json();
  } catch (e) { /* 服务异常时退回 key 门 */ }
  if (st && st.enabled) {
    authMode = 'session';
    if (!st.logged_in) {
      // 未登录：不显示面板骨架，直接弹登录框。
      openLogin();
      // 无用户时把登录框切换成「首次初始化」表单——部署完直接在这里建管理员，
      // 不必再 SSH 进容器敲 setpassword。提交成功后此入口永久关闭（后端保证）。
      if (st.has_users === false) enterSetupMode();
      return false;
    }
    $('appShell').hidden = false;
    $('btnLogout').hidden = false;
    $('btnPwd').hidden = false;
    meUser = st.username || '';
    $('meName').textContent = meUser;
    return true;
  }
  // 未启用账密（旧模式）：沿用 api_key 门。面板骨架先显示，401 时弹密钥框。
  authMode = 'key';
  $('appShell').hidden = false;
  return true;
}

/* ── 路由 ─────────────────────────────────────────────────────────── */
const TITLES = { accounts: '账号池', usage: '用量', packages: '积分构成', taskscenter: '任务中心', models: '模型与档位', config: '配置', logs: '运行日志' };
function go(v) {
  view = v;
  document.querySelectorAll('.view').forEach(s => s.hidden = s.id !== 'view-' + v);
  document.querySelectorAll('.nav a').forEach(a => a.classList.toggle('on', a.dataset.view === v));
  $('ttl').textContent = TITLES[v];
  switchView(v);
}

/* switchView 切视图的收尾：复位滚动 + 按需拉数据。
   滚动复位采用「同步 + 双 rAF」三重保险：
   - 同步一次：display 切换后立即归零，覆盖大多数情况；
   - 第 1 帧：浏览器完成布局后归零（视图高度差异极大，配置页 ~3500px）；
   - 第 2 帧：兜底，防止首帧仍在滚动恢复过程中。
   只做其中任意一层，长页（配置）切短页时仍会残留一帧旧滚动位置，看起来"跳一下"。 */
function switchView(v) {
  window.scrollTo(0, 0);
  requestAnimationFrame(() => {
    window.scrollTo(0, 0);
    requestAnimationFrame(() => window.scrollTo(0, 0));
  });
  if (v === 'models' && !$('mdBody').children.length) loadModels();
  if (v === 'config') loadConfig();
  if (v === 'logs') loadLogs();
  if (v === 'usage') loadUsage();
  if (v === 'packages') loadPackages();
  if (v === 'taskscenter') { loadSchoolStatus(true); pollQueueOnce(); }
  else scanHold = false;   // 离开任务中心则解除扫描保持，下次进入展示实时队列状态
}
/* 导航点击绑定移到文件末尾的启动 IIFE（必须在 gate() 之后，见该处注释）。 */

/* ── 账号池 ───────────────────────────────────────────────────────── */
function renderAccounts(list) {
  const tb = $('accBody');
  if (!list.length) {
    tb.innerHTML = '<tr><td colspan="9"><div class="empty"><div class="big">账号池是空的</div>点击右上角「添加账号」，用浏览器登录一个 WorkBuddy 账号</div></td></tr>';
    return;
  }
  // 有总额度（credits_total）→ 进度条按自身 剩余/总额 百分比；旧数据无总额 → 退回池内最高=100%
  const maxCred = Math.max(1, ...list.map(s => s.credits || 0));
  tb.innerHTML = list.map(s => {
    const bl = (new Date(s.breaker_until || 0) - Date.now()) / 1000;
    const dg = (new Date(s.degrade_until || 0) - Date.now()) / 1000;
    const cool = Math.max(s.cool_remaining_sec || 0, bl > 0 ? bl : 0, dg > 0 ? dg : 0);
    let cls = '', tag;
    if (s.disabled) { cls = 'off'; tag = '<span class="tag bad">已禁用</span>'; }
    else if (cool > 0) {
      cls = 'cool';
      const kind = bl > Math.max(s.cool_remaining_sec || 0, dg > 0 ? dg : 0) ? '熔断'
        : (dg > (s.cool_remaining_sec || 0) ? '连败降权' : (s.cool_kind === 'hard_credit' ? '积分冷却' : '限流冷却'));
      tag = '<span class="tag warn">' + kind + ' · ' + dur(cool) + '</span>';
    } else tag = '<span class="tag ok">可用</span>' + (s.in_flight ? '' : '');
    const note = s.reason ? '<div class="hint" style="font-size:11.5px;color:var(--ink-3);margin-top:3px">' + esc(s.reason) + '</div>' : '';
    const short = s.uid.length > 16 ? s.uid.slice(0, 16) + '…' : s.uid;
    const cred = s.credits == null ? '—' : (s.credits_total > 0 ? s.credits + '<span class="of">/' + s.credits_total + '</span>' : String(s.credits));
    const pct = s.credits_total > 0
      ? Math.min(100, Math.round((s.credits || 0) / s.credits_total * 100))
      : Math.round((s.credits || 0) / maxCred * 100);
    // 成本台账 tooltip（model_costs）：每模型实测单价（≤0 = 实测免费），运维据此
    // 看「为什么总选它」——免费号垄断 / 单价排序一眼可见。
    let credTip = s.credits_total > 0 ? '剩余 ' + s.credits + ' / 总额 ' + s.credits_total + '（' + pct + '%）' : '积分（相对池内最高）';
    const costs = (s.model_costs || []).filter(c => c.model);
    if (costs.length) {
      credTip += '\n实测单价（credits/1K）：\n' + costs.map(c =>
        '  ' + c.model + '：' + (c.cost_per_1k <= 0 ? '免费' : c.cost_per_1k)).join('\n');
    }
    const frozen = s.disabled || cool > 0;
    const tu = s.token_usage || {};
    const req = tu.request_count || 0;
    const totalTok = formatTokenCount(tu.total_tokens);
    const totalTokUnit = totalTok === '—' ? '' : '<em>tok</em>';
    const latency = formatLatency(tu.last_latency_ms);
    const rate = formatRate(tu.last_tokens_per_second);
    const usageTitle = '最近一次：' + req + ' 次 / ' + totalTok + ' / 延迟 ' + latency + ' / ' + rate;
    return '<tr class="' + cls + '" title="uid: ' + esc(s.uid) + '">' +
      '<td class="mark" aria-hidden="true"><i></i></td>' +
      '<td class="who"><div class="nm">' + (s.nickname ? esc(s.nickname) : '<span style="color:var(--ink-3)">未命名</span>') + (s.realm === 'global' ? ' <span class="realm-tag">国际版</span>' : '') + '</div><div class="id">' + esc(short) + '</div></td>' +
      '<td>' + tag + note + '</td>' +
      '<td class="cred" title="' + esc(credTip) + '"><div class="n">' + cred + '</div><div class="bar"><i style="width:' + pct + '%"></i></div></td>' +
      '<td class="num">' + (s.success_count || 0) + ' <span style="color:var(--ink-3)">/</span> <span style="color:var(--bad)">' + (s.err_total || 0) + '</span></td>' +
      '<td class="num">' + (s.in_flight || 0) + '</td>' +
      '<td class="num usage-cell" title="' + esc(usageTitle) + '"><span class="usage-line" aria-label="' + esc(usageTitle) + '">' +
        '<span class="usage-item usage-count"><b>' + req + '</b><em>次</em></span>' +
        '<span class="usage-item usage-total"><b>' + totalTok + '</b>' + totalTokUnit + '</span>' +
        '<span class="usage-item usage-latency"><b>' + latency + '</b></span>' +
        '<span class="usage-item usage-rate"><b>' + rate + '</b></span>' +
      '</span></td>' +
      '<td class="num" style="color:var(--ink-3)">' + ago(s.last_success) + '</td>' +
      '<td class="acts">' +
        '<button class="xs ghost" data-a="checkin" data-u="' + esc(s.uid) + '">签到</button>' +
        '<button class="xs ghost" data-a="balance" data-u="' + esc(s.uid) + '">余额</button>' +
        '<button class="xs ghost" data-a="tasks" data-u="' + esc(s.uid) + '">任务</button>' +
        (frozen ? '<button class="xs primary" data-a="revive" data-u="' + esc(s.uid) + '">解冻</button>'
                : '<button class="xs ghost" data-a="disable" data-u="' + esc(s.uid) + '">禁用</button>') +
        '<button class="xs ghost danger" data-a="remove" data-u="' + esc(s.uid) + '">移除</button>' +
      '</td></tr>';
  }).join('');
}

async function loadOverview(quiet) {
  try {
    const d = await api('overview');
    overviewData = d;
    $('sTotal').textContent = d.total;
    $('sHealthy').textContent = d.healthy;
    $('sCooling').textContent = d.cooling;
    $('sDisabled').textContent = d.disabled;
    const remSum = (d.accounts || []).reduce((a, s) => a + (s.credits || 0), 0);
  const totSum = (d.accounts || []).reduce((a, s) => a + (s.credits_total || 0), 0);
  $('sCredits').textContent = totSum > 0 ? remSum + ' / ' + totSum : remSum;
    $('sSticky').textContent = d.sticky_sessions;
    $('navSub').textContent = 'v' + d.version;
    $('navVer').textContent = 'v' + d.version;
    $('navRedis').textContent = d.redis_mode === 'upstash' ? 'Redis 镜像' : '本地内存';
    $('navState').textContent = d.healthy > 0 ? '服务正常' : (d.total ? '无可用账号' : '待添加账号');
    const p = $('navPulse');
    p.className = 'pulse' + (d.healthy > 0 ? '' : (d.total ? ' warn' : ' bad'));
    $('accNote').textContent = d.in_flight_full ? d.in_flight_full + ' 个账号在途占满' : '';
    const up = Math.floor(d.uptime_sec);
    $('subMeta').textContent = '运行 ' + (up >= 86400 ? Math.floor(up / 86400) + ' 天 ' : '') + Math.floor(up % 86400 / 3600) + ' 时 ' + Math.floor(up % 3600 / 60) + ' 分';
    renderAccounts(d.accounts || []);
  } catch (e) { if (!quiet) toast(e.message, 'err'); }
}

$('accBody').addEventListener('click', async ev => {
  const b = ev.target.closest('button[data-a]');
  if (!b) return;
  const u = b.dataset.u, a = b.dataset.a;
  if (a === 'remove' && !confirm('移除账号将删除池状态与 auths/ 下的凭证文件，且不可恢复。确认移除？')) return;
  if (a === 'disable' && !confirm('禁用后该账号不再参与选号，需手动解冻才能恢复。确认禁用？')) return;
  b.disabled = true;
  try {
    if (a === 'checkin') {
      const r = await api('accounts/' + encodeURIComponent(u) + '/checkin', { method: 'POST' });
      toast('签到完成' + (r.credits != null ? '，积分 ' + r.credits + (r.credits_total > 0 ? '/' + r.credits_total : '') : '') + (r.checkin_message ? '（' + r.checkin_message + '）' : ''), 'ok');
    } else if (a === 'balance') {
      const r = await api('accounts/' + encodeURIComponent(u) + '/balance', { method: 'POST' });
      toast('余额已更新：' + r.credits + (r.credits_total > 0 ? ' / ' + r.credits_total : ''), 'ok');
    } else if (a === 'revive') {
      await api('accounts/' + encodeURIComponent(u) + '/revive', { method: 'POST' });
      toast('已解冻', 'ok');
    } else if (a === 'disable') {
      await api('accounts/' + encodeURIComponent(u) + '/disable', { method: 'POST' });
      toast('已禁用', 'ok');
    } else if (a === 'tasks') {
      openTasks(u);
    } else if (a === 'remove') {
      const r = await api('accounts/' + encodeURIComponent(u) + '/remove', { method: 'POST' });
      toast(r.file_error ? '已移除（凭证文件删除失败：' + r.file_error + '）' : '已移除', 'ok');
    }
  } catch (e) { toast(e.message, 'err'); }
  finally { b.disabled = false; loadOverview(true); }
});

$('btnCheckinAll').onclick = async () => {
  try { await api('checkin_all', { method: 'POST' }); toast('全部签到已开始，结果见日志', 'ok'); }
  catch (e) { toast(e.message, 'err'); }
};
$('btnKeepaliveAll').onclick = async () => {
  try { await api('keepalive_all', { method: 'POST' }); toast('全部保活已开始，结果见日志', 'ok'); }
  catch (e) { toast(e.message, 'err'); }
};
$('btnTravelAll').onclick = async () => {
  try { await api('travel_all', { method: 'POST' }); toast('旅行巡检已开始（含领养链路），结果见日志', 'ok'); }
  catch (e) { toast(e.message, 'err'); }
};
$('btnActivityAll').onclick = async () => {
  try { await api('activity_all', { method: 'POST' }); toast('活跃上报已开始，结果见日志', 'ok'); }
  catch (e) { toast(e.message, 'err'); }
};

/* ── 模型 ─────────────────────────────────────────────────────────── */
/* 实测上限标注：scripts/probe_max_tokens.py --panel-out 写入探测结果，
   /panel/api/model_probes 只读透传。探测键带域前缀（cn:glm-5.2），模型表
   显示裸名，按「精确命中或 :后缀」关联。无数据时本列退回上游声称值。 */
function fmtK(n) { n = Number(n || 0); return n >= 1000 ? Math.round(n / 1000) + 'K' : String(n); }
function probeDays(ts) {
  if (!ts) return null;
  const t = new Date(String(ts).replace(' ', 'T'));
  const d = (Date.now() - t.getTime()) / 86400000;
  return isNaN(d) ? null : Math.floor(d);
}
function outCell(m, pr) {
  if (!pr) return '<td class="num">' + (m.max_output_tokens ? fmtK(m.max_output_tokens) : '—') + '</td>';
  const tip = '声称 ' + (pr.claimed ? fmtK(pr.claimed) : '?') + ' · 实测 ' + (pr.measured ? fmtK(pr.measured) : '?') +
    (pr.note ? ' · ' + pr.note : '') + (pr.tested_at ? ' · 探测于 ' + pr.tested_at : '');
  const days = probeDays(pr.tested_at);
  const stale = days !== null && days > 30 ? ' · ' + days + ' 天前' : '';
  if (pr.verdict === 'clamped' && pr.measured) {
    if (pr.claimed && pr.measured < pr.claimed) {
      const x = pr.claimed / pr.measured;
      const xs = (x >= 10 ? Math.round(x) : Math.round(x * 10) / 10) + '×';
      return '<td class="num" title="' + esc(tip) + '"><span style="color:var(--warn);font-weight:600">' +
        fmtK(pr.measured) + ' ⚠</span><div class="note">钳制 ' + xs + stale + '</div></td>';
    }
    return '<td class="num" title="' + esc(tip) + '"><span style="color:var(--ok)">' + fmtK(pr.measured) +
      (pr.claimed && pr.measured > pr.claimed ? ' ↑' : ' ✓') + '</span></td>';
  }
  if (pr.verdict === 'at_least' && pr.measured)
    return '<td class="num" title="' + esc(tip) + '"><span style="color:var(--ink-3)">≥' + fmtK(pr.measured) + '</span></td>';
  return '<td class="num" title="' + esc(tip) + '"><span style="color:var(--ink-3)">?</span><div class="note">未测出' + stale + '</div></td>';
}

async function loadModels() {
  const tb = $('mdBody');
  tb.innerHTML = '<tr><td colspan="7"><div class="empty">正在向上游查询…</div></td></tr>';
  try {
    // 探测数据是可选增强：拉取失败不影响模型列表本身
    const [d, pr] = await Promise.all([
      api('models' + (mdRealm === 'global' ? '?realm=global' : '')),
      api('model_probes').catch(() => ({})),
    ]);
    const list = d.models || [];
    if (!list.length) { tb.innerHTML = '<tr><td colspan="7"><div class="empty">上游未返回模型</div></td></tr>'; return; }
    const probes = pr.probes || {};
    const probeKeys = Object.keys(probes);
    const probeOf = id => probes[id] || probes[probeKeys.find(k => k.endsWith(':' + id))];
    tb.innerHTML = list.map(m => {
      const eff = (m.supported_efforts || []).slice();
      if (m.can_disable_thinking && eff.length && !eff.includes('off')) eff.push('off（可关）');
      const effs = eff.length ? eff.map(e => '<span class="tag warn">' + esc(e) + '</span>').join(' ')
        : '<span style="color:var(--ink-3);font-size:12.5px">' + (m.supports_reasoning ? '固定档 · 默认 ' + esc(m.default_effort || '?') : '不支持思考') + '</span>';
      // 能力徽标：默认模型 / 工具调用 / 视觉 / 纯推理（上游目录全字段透出，缺失不显示）
      const caps = [];
      if (m.is_default) caps.push('<span class="tag ok">默认</span>');
      if (m.supports_tool_call) caps.push('<span class="tag warn">工具</span>');
      if (m.supports_images) caps.push('<span class="tag warn">视觉</span>');
      if (m.supports_reasoning && !m.can_disable_thinking) caps.push('<span class="tag warn">思考常开</span>');
      const capHtml = caps.length ? '<div class="id" style="margin-top:2px">' + caps.join(' ') + '</div>' : '';
      const tip = m.description ? ' title="' + esc(m.description) + '"' : '';
      return '<tr><td class="mark" aria-hidden="true"><i></i></td><td class="who"' + tip + '><div class="nm">' + esc(m.id) + '</div><div class="id">' + esc(m.name || '') + '</div>' + capHtml + '</td>' +
        '<td class="num">' + (m.credits ? esc(m.credits) : '—') + '</td>' +
        '<td>' + (m.default_effort ? '<span class="tag ok">' + esc(m.default_effort) + '</span>' : '<span style="color:var(--ink-3)">—</span>') + '</td>' +
        '<td class="efs" style="white-space:normal">' + effs + '</td>' +
        '<td class="num">' + (m.context_length ? Math.round(m.context_length / 1000) + 'K' : '—') + '</td>' +
        outCell(m, probeOf(m.id)) + '</tr>';
    }).join('');
    const hit = list.filter(m => probeOf(m.id)).length;
    $('mdNote').textContent = (mdRealm === 'global' ? '国际版 · ' : '国内版 · ') + list.length + ' 个模型 · 已刷新降级缓存' + (hit ? ' · ' + hit + ' 个有实测上限' : '');
  } catch (e) {
    tb.innerHTML = '<tr><td colspan="7"><div class="empty">' + esc(e.message) + '</div></td></tr>';
  }
}
$('btnModels').onclick = loadModels;

/* 域切换（国内版 / 国际版）：两套独立目录，切换即重新拉取。
   切域时清空 tbody，避免旧域数据残留在新域视图里造成误读。 */
let mdRealm = 'cn';
$('mdRealmChips').addEventListener('click', ev => {
  const b = ev.target.closest('button[data-realm]');
  if (!b || b.dataset.realm === mdRealm) return;
  mdRealm = b.dataset.realm;
  document.querySelectorAll('#mdRealmChips .chip').forEach(c => c.classList.toggle('on', c === b));
  $('mdBody').innerHTML = '';
  loadModels();
});

/* ── 日志（频道：全部/任务/对话/系统） ─────────────────────────────── */
let logCh = 'all';
$('logChips').addEventListener('click', ev => {
  const b = ev.target.closest('button[data-ch]');
  if (!b) return;
  logCh = b.dataset.ch;
  document.querySelectorAll('#logChips .chip').forEach(c => c.classList.toggle('on', c === b));
  loadLogs();
});
async function loadLogs() {
  const box = $('logBox');
  const atEnd = box.scrollTop + box.clientHeight >= box.scrollHeight - 24;
  try {
    const d = await api('logs');
    const entries = (d.entries || []).filter(e => logCh === 'all' || e.ch === logCh);
    box.innerHTML = entries.length
      ? entries.map(e => {
        const lvl = /error|失败|错误/.test(e.text) ? ' e' : /warn|冷却|熔断/.test(e.text) ? ' w' : '';
        const t = e.ts ? new Date(e.ts).toLocaleTimeString('zh-CN', { hour12: false }) : '';
        const ch = logCh === 'all' ? '<i class="lch c-' + esc(e.ch) + '">' + ({ task: '任务', chat: '对话', sys: '系统' }[e.ch] || e.ch) + '</i>' : '';
        return '<span class="ln' + lvl + '">' + ch + esc(t + ' ' + e.text) + '</span>';
      }).join('')
      : '<span style="color:var(--ink-3)">暂无日志</span>';
    if (logPin && atEnd) box.scrollTop = box.scrollHeight;
    const counts = {};
    for (const e of (d.entries || [])) counts[e.ch] = (counts[e.ch] || 0) + 1;
    $('logNote').textContent = logCh === 'all'
      ? '任务 ' + (counts.task || 0) + ' · 对话 ' + (counts.chat || 0) + ' · 系统 ' + (counts.sys || 0)
      : (logCh === 'task' ? '任务' : logCh === 'chat' ? '对话' : '系统') + ' ' + entries.length + ' 行';
  } catch (e) { /* 概览已提示 */ }
}
$('btnLogPin').onclick = () => {
  logPin = !logPin;
  $('btnLogPin').textContent = '自动滚动：' + (logPin ? '开' : '关');
};

/* ── 配置 ─────────────────────────────────────────────────────────── */
const CFG_MAP = {
  listen: ['listen'], api_key: ['api_key'],
  checkin_hours: ['schedule', 'checkin_hours'], checkin_enabled: ['schedule', 'checkin_enabled'],
  travel_hours: ['schedule', 'travel_hours'], travel_enabled: ['schedule', 'travel_enabled'],
  activity_hours: ['schedule', 'activity_hours'], activity_enabled: ['schedule', 'activity_enabled'],
  keepalive_hours: ['schedule', 'keepalive_hours'], keepalive_enabled: ['schedule', 'keepalive_enabled'],
  balance_refresh_enabled: ['schedule', 'balance_refresh_enabled'], balance_refresh_minutes: ['schedule', 'balance_refresh_minutes'],
  max_body_mb: ['server', 'max_body_mb'],
  max_in_flight: ['pool', 'max_in_flight'], max_in_flight_global: ['pool', 'max_in_flight_global'],
  breaker_threshold: ['pool', 'breaker_threshold'],
  degrade_threshold: ['pool', 'degrade_threshold'], degrade_cooldown: ['pool', 'degrade_cooldown'],
  degrade_cooldown_max: ['pool', 'degrade_cooldown_max'],
  soft_rate: ['cooldown', 'soft_rate'], soft_rate_max: ['cooldown', 'soft_rate_max'],
  breaker_cooldown: ['pool', 'breaker_cooldown'], breaker_cooldown_max: ['pool', 'breaker_cooldown_max'],
  idle_weight_per_hour: ['pool', 'idle_weight_per_hour'], idle_weight_max: ['pool', 'idle_weight_max'],
  ttl: ['session_sticky', 'ttl'],
  timeout_seconds: ['upstream', 'timeout_seconds'], header_timeout_seconds: ['upstream', 'header_timeout_seconds'],
  idle_timeout_seconds: ['upstream', 'idle_timeout_seconds'], user_agent: ['upstream', 'user_agent'],
  prompt_mode: ['prompt', 'mode'], prompt_file: ['prompt', 'file'],
  sanitize_blacklist_fingerprints: ['features', 'sanitize_blacklist_fingerprints'],
  session_sticky_enabled: ['session_sticky', 'enabled'],
};
function dig(obj, path) { return path.reduce((o, k) => (o == null ? undefined : o[k]), obj); }
function put(obj, path, val) {
  let o = obj;
  for (let i = 0; i < path.length - 1; i++) { if (typeof o[path[i]] !== 'object' || o[path[i]] === null) o[path[i]] = {}; o = o[path[i]]; }
  o[path[path.length - 1]] = val;
}

async function loadConfig() {
  try {
    const d = await api('config');
    cfgLoaded = d.config;
    $('cfgPath').textContent = d.path || '';
    const f = $('cfgForm');
    for (const [name, path] of Object.entries(CFG_MAP)) {
      const el = f.elements[name];
      if (!el) continue;
      const v = dig(cfgLoaded, path);
      if (el.type === 'checkbox') el.checked = !!v;
      else if (Array.isArray(v)) el.value = v.join(', ');
      else el.value = v == null ? '' : v;
    }
    markDurationFields(); // 回填后重置校验态（清掉残留红框；现值来自后端必然合法）
    KEDIT.load(cfgLoaded && cfgLoaded.keys); // 白名单密钥区块（数组结构，不走 CFG_MAP）
    $('cfgNote').textContent = '';
  } catch (e) { toast('读取配置失败：' + e.message, 'err'); }
}
function collectConfig() {
  const f = $('cfgForm'), out = {};
  for (const [name, path] of Object.entries(CFG_MAP)) {
    const el = f.elements[name];
    if (!el) continue;
    let v;
    if (el.type === 'checkbox') v = el.checked;
    else if (el.type === 'number') { v = el.value.trim() === '' ? undefined : Number(el.value); }
    else {
      const raw = el.value.trim();
      if (raw === '') v = undefined;
      else if (name.endsWith('_hours')) v = raw.split(/[,，\s]+/).filter(Boolean).map(Number);
      else v = raw;
    }
    if (v !== undefined) put(out, path, v);
  }
  // 白名单密钥：数组结构，无法走 CFG_MAP，单独收集。
  // 必须每次都带 keys（哪怕空数组）—— 后端 mergeConfigMaps 对数组是整体替换，
  // 不带则保留旧值，用户就删不掉密钥了。
  out.keys = KEDIT.collect();
  return out;
}
/* Go 时长字段即时校验：空 = 沿用现值（collectConfig 跳过发送）；非空必须是
   ParseDuration 语法（30m / 2h / 600s / 1h30m，可组合可带小数）。与后端
   config.go normalize() 的 time.ParseDuration 同口径，脏值在前端就地标红，
   不再等到保存被拒。 */
const DURATION_RE = /^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/;
const DURATION_FIELDS = ['soft_rate', 'soft_rate_max', 'breaker_cooldown', 'breaker_cooldown_max',
  'degrade_cooldown', 'degrade_cooldown_max', 'ttl'];
const DURATION_TIP = '格式应为 Go 时长：30m / 2h / 600s / 1h30m';
function durationBad(name) {
  const el = $('cfgForm').elements[name];
  if (!el) return false;
  const v = el.value.trim();
  return v !== '' && !DURATION_RE.test(v);
}
function markDurationFields() {
  for (const name of DURATION_FIELDS) {
    const el = $('cfgForm').elements[name];
    if (!el) continue;
    const bad = durationBad(name);
    el.classList.toggle('invalid', bad);
    el.title = bad ? DURATION_TIP : '';
  }
}
$('cfgForm').addEventListener('input', ev => {
  if (DURATION_FIELDS.includes(ev.target.name)) markDurationFields();
});
$('btnEye').onclick = () => {
  const el = $('cfgKey');
  const show = el.type === 'password';
  el.type = show ? 'text' : 'password';
  $('btnEye').textContent = show ? '隐藏' : '显示';
};
$('btnCfgReload').onclick = loadConfig;
$('cfgForm').onsubmit = async ev => {
  ev.preventDefault();
  // 时长字段脏值拦截：标红 + toast 点名，不发保存请求（后端同样会拒，这里前置）。
  markDurationFields();
  const firstBad = DURATION_FIELDS.find(durationBad);
  if (firstBad) {
    const el = $('cfgForm').elements[firstBad];
    el.focus();
    toast('「' + (el.closest('.fld')?.querySelector('.lb')?.textContent || firstBad) + '」' + DURATION_TIP, 'err');
    return;
  }
  const btn = $('btnCfgSave');
  btn.disabled = true; btn.textContent = '保存中…';
  try {
    const r = await api('config', { method: 'POST', body: JSON.stringify(collectConfig()) });
    const n = (r.restart_required || []).length;
    toast(n ? '配置已保存，其中 ' + n + ' 项需重启进程生效' : '配置已保存并立即生效', 'ok');
    // 密钥可能已改：本次会话沿用新值，避免下一次轮询被 401。
    const k = $('cfgKey').value.trim();
    if (k) localStorage.setItem(LS_KEY, k);
    loadConfig();
    loadOverview(true);
  } catch (e) { toast('保存失败：' + e.message, 'err'); }
  finally { btn.disabled = false; btn.textContent = '保存配置'; }
};

/* ── 添加账号 ─────────────────────────────────────────────────────── */
function openAdd() {
  $('addVeil').classList.add('on');
  // 重置到选域态：选域可见、加载/就绪/完成/错误全收，起始按钮亮起。
  $('addPick').hidden = false;
  $('addLoad').hidden = true; $('addReady').hidden = true;
  $('addDone').hidden = true; $('addErr').hidden = true;
  $('btnCopyUrl').hidden = true; $('btnOpenUrl').hidden = true;
  $('btnStartLogin').hidden = false; $('btnStartLogin').disabled = false;
  stopPoll();
}
function startAddLogin() {
  const realm = (document.querySelector('input[name="addRealm"]:checked') || {}).value || 'cn';
  $('btnStartLogin').disabled = true;
  $('addLoad').hidden = false; $('addErr').hidden = true;
  api('login/start', { method: 'POST', body: JSON.stringify({ realm }) }).then(r => {
    loginState = r.state;
    $('addUrl').textContent = r.url;
    $('addPick').hidden = true; // 选域锁定（会话已按该域发起）
    $('addLoad').hidden = true; $('addReady').hidden = false;
    $('btnStartLogin').hidden = true;
    $('btnCopyUrl').hidden = false; $('btnOpenUrl').hidden = false;
    loginTimer = setInterval(pollLogin, 3000);
  }).catch(e => {
    $('addLoad').hidden = true;
    $('btnStartLogin').disabled = false;
    $('addErr').hidden = false;
    $('addErr').textContent = e.message;
  });
}
function stopPoll() { if (loginTimer) { clearInterval(loginTimer); loginTimer = null; } }
async function pollLogin() {
  if (!loginState) return;
  try {
    const r = await api('login/poll?state=' + encodeURIComponent(loginState));
    if (r.done) {
      stopPoll();
      $('addReady').hidden = true;
      $('addDone').hidden = false;
      $('addDone').textContent = '已添加 ' + (r.nickname || r.uid) + (r.realm === 'global' ? '（国际版）' : '') + (r.credits >= 0 ? ' · 积分 ' + r.credits + (r.credits_total > 0 ? '/' + r.credits_total : '') : '') + '，账号已载入池中';
      setTimeout(() => { closeAdd(); loadOverview(true); }, 1600);
    }
  } catch (e) {
    stopPoll();
    $('addReady').hidden = true;
    $('addErr').hidden = false;
    $('addErr').textContent = e.message + '（关闭后重新添加）';
  }
}
function closeAdd() { stopPoll(); loginState = null; $('addVeil').classList.remove('on'); }
$('btnCloseAdd').onclick = closeAdd;
$('btnStartLogin').onclick = startAddLogin;
$('btnOpenUrl').onclick = () => open($('addUrl').textContent, '_blank');
$('btnCopyUrl').onclick = () => navigator.clipboard.writeText($('addUrl').textContent)
  .then(() => toast('链接已复制', 'ok'), () => toast('复制失败，请手动选择复制', 'err'));

/* ── 顶部动作 ─────────────────────────────────────────────────────── */
$('btnAdd').onclick = openAdd;
$('btnLogout').onclick = doLogout;
$('btnRefresh').onclick = async () => {
  const b = $('btnRefresh');
  b.disabled = true; b.textContent = '刷新中…';
  try {
    await api('balance_all', { method: 'POST' });
    await loadOverview(true);
    toast('余额已从上游刷新', 'ok');
  } catch (e) { toast('刷新失败：' + e.message, 'err'); await loadOverview(true); }
  finally { b.disabled = false; b.textContent = '刷新'; }
  if (view === 'logs') loadLogs();
};

/* ── 轮询 ─────────────────────────────────────────────────────────── */
function refreshVisible() {
  if (view === 'accounts') loadOverview(true);
  else if (view === 'logs') loadLogs();
  else if (view === 'taskscenter') pollQueueOnce();
}
function start() {
  loadOverview(true);
  if (refTimer) clearInterval(refTimer);
  refTimer = setInterval(refreshVisible, 5000);
  checkAuthGate();
}
async function checkAuthGate() {
  try { await api('overview'); }
  catch (e) { if (String(e.message).includes('密钥') || String(e.message).includes('api_key') || String(e.message).includes('登录')) return; }
}
/* enterPanel 进入面板：绑定导航点击 + 首次路由渲染 + 启动轮询。
   **必须由两条路径共用**：启动时 gate() 通过（已登录/回访），以及登录框提交成功后。
   早期只在启动块里绑定导航，导致"在登录页直接登录"这条路径下导航点击全部失效
   （go() 从未被调用、onclick 从未挂上），点用量/积分毫无反应。 */
function enterPanel() {
  // 幂等：重复调用不重复绑定（onclick 赋值本身幂等，这里只是避免重复设置初始路由）。
  document.querySelectorAll('.nav a').forEach(a => a.onclick = e => {
    e.preventDefault();
    go(a.dataset.view);
    history.replaceState(null, '', '#' + a.dataset.view);
  });
  const initial = (location.hash || '#accounts').slice(1);
  go(initial in TITLES ? initial : 'accounts');
  start();
}

/* 启动顺序：**先**过登录门（决定用 Cookie 还是 key），**再**渲染路由。
   顺序至关重要：go() 会立即触发 api() 请求，而 api() 的 401 分支要靠 authMode
   决定弹「登录框」还是「密钥框」。若 go() 先跑，authMode 还是 'none'，
   会话失效时就会错误地弹出 api_key 对话框（改名后重载即触发此 bug）。 */
(async () => {
  if (await gate()) enterPanel();
})();

/* ── 积分任务 ─────────────────────────────────────────────────────── */
let taskUID = null;

// 可自动完成的任务（与后端 autoActions 表一致）：判据为行为事件、可经网关复现。
// 其余任务需在官方客户端内交互，面板只展示指引（行 title 提示）。
// 注意：键含点号（Model_chat_GLM5.2）必须加引号，否则会被解析成属性访问 + 数字字面量。
const AUTO_TASKS = {
  'chat_5': '上报 5 条对话活跃事件（自动补足差额）',
  'first_buddy': '上报解锁 → 同意协议 → 领取第一只 Buddy',
  'Model_chat_GLM5.2': '接受任务 → glm-5.2 真实对话一次 → 对齐模型上报',
  'RichMeow_Chat': '桌面指纹事件链上报（已验证可点亮）',
  'Buddy_App': '上报「进入 Buddy 应用」事件链（已验证可点亮）',
  'Buddy_App_QQ': '上报「进入企鹅教师助手」事件链（已验证可点亮）',
  'automation_1': '上报「定时任务创建」事件（已验证可点亮）',
  'Library_read': '上报「读资料库介绍」事件（已验证可点亮）',
  'template_5': '上报「使用模板创建任务」事件组 ×5（三账号实测点亮）',
  'playbook_prompt': '上报「灵感案例做同款发送 Prompt」事件组（三账号实测点亮）',
  'create_canvas': '上报「设计创意画布创建」事件组（三账号实测点亮，+300 分）',
  'expert_5': '真实专家召唤+使用链 ×5（专家市场+真实 chat，三账号实测点亮）',
  'Expert_team_use_3': '真实专家团召唤+使用链 ×3（三账号实测点亮）',
  'Hp_Appearance': '设置主题 API + 皮肤生效事件（两账号实测点亮）',
  'black_cat': '夜猫子：23:00–08:00 窗口内 glm-5.2 对话补足（窗口外提示等 23 点排程）',
  'Expert_lighthouse': '真实轻量云专家召唤+使用链（真实对话 requestId，两账号实测点亮）',
  'skill_1': '真实对话 + skill_info 技能加载事件（实测点亮）'
};

function openTasks(uid) {
  taskUID = uid;
  $('taskWho').textContent = uid.slice(0, 16);
  $('taskVeil').classList.add('on');
  $('btnTaskReload').hidden = false;
  loadTasks();
}
function closeTasks() { $('taskVeil').classList.remove('on'); taskUID = null; }
$('btnCloseTask').onclick = closeTasks;
$('btnTaskReload').onclick = loadTasks;

// 全部接受：把该账号未接受的任务一次性报名（幂等，跳过已接受/已领取）。
$('btnTaskAcceptAll').onclick = async () => {
  if (!taskUID) return;
  const btn = $('btnTaskAcceptAll');
  btn.disabled = true; btn.textContent = '接受中…';
  try {
    const r = await api('accounts/' + encodeURIComponent(taskUID) + '/tasks/accept_all', { method: 'POST' });
    const n = r.accepted || 0;
    if (r.failed && r.failed.length) {
      toast(`已接受 ${n} 个，${r.failed.length} 个被上游拒绝（可重试）`, 'err');
    } else {
      toast(n ? `已接受 ${n} 个任务` : (r.message || '所有任务均已接受'), 'ok');
    }
  } catch (e) { toast(e.message, 'err'); }
  finally { btn.disabled = false; btn.textContent = '全部接受'; loadTasks(); }
};

// 一键完成全部可自动任务（耗时较长：含真实对话，逐项回读验证）。
$('btnTaskAutoAll').onclick = async () => {
  if (!taskUID) return;
  const btn = $('btnTaskAutoAll');
  if (!confirm('将依次执行：补报对话事件、领取 Buddy、glm-5.2 对话、尝试上报。\n过程约 1-2 分钟（含真实对话），确认继续？')) return;
  btn.disabled = true; btn.textContent = '执行中…';
  try {
    const r = await api('accounts/' + encodeURIComponent(taskUID) + '/tasks/auto_all', { method: 'POST' });
    const okN = (r.results || []).filter(x => x.status === 'done').length;
    const skipN = (r.results || []).filter(x => x.status === 'skipped').length;
    const errN = (r.results || []).filter(x => x.status === 'error').length;
    toast(`执行完成：成功 ${okN} 项，跳过 ${skipN} 项${errN ? '，失败 ' + errN + ' 项' : ''}`, errN ? 'err' : 'ok');
    console.log('auto_all results:', r.results);
  } catch (e) { toast(e.message, 'err'); }
  finally { btn.disabled = false; btn.textContent = '一键完成可自动任务'; loadTasks(); }
};

async function loadTasks() {
  if (!taskUID) return;
  const st = $('taskState'), tb = $('taskTable');
  st.hidden = false;
  st.className = 'state';
  st.innerHTML = '<span class="dots">查询中</span>';
  tb.hidden = true;
  try {
    const d = await api('accounts/' + encodeURIComponent(taskUID) + '/tasks');
    const list = d.tasks || [];
    if (!list.length) {
      st.className = 'state';
      st.textContent = '该账号暂无任务';
      return;
    }
    // 有进度或可领取的排前面，已领取沉底——一眼看到"现在该做什么"。
    list.sort((a, b) => (a.claimed - b.claimed) || (b.claimable - a.claimable) || String(a.task_code).localeCompare(String(b.task_code)));
    $('taskBody').innerHTML = list.map(t => {
      // 进度：current 可能缺失（0 或被上游省略）——用 ?? 兜底，避免渲染成 "undefined / N"
      const cur = t.current ?? 0, tgt = t.target ?? 0;
      const prog = tgt ? cur + ' / ' + tgt : (tgt === 0 && cur > 0 ? String(cur) : '—');
      const parts = [];
      if (t.credit) parts.push('+' + t.credit + ' 分');
      if (t.energy) parts.push('+' + t.energy + ' 能');
      if (t.reward_buddy) parts.push('Buddy');
      const reward = parts.length ? parts.join(' ') : '—';
      const badge = t.claimed ? '<span class="tag ok">已领取</span>'
        : t.claimable ? '<span class="tag warn">可领取</span>'
        : t.locked ? '<span class="tag mute">未解锁</span>'
        : t.accept_status === 'accepted' ? '<span class="tag mute">进行中</span>'
        : '<span class="tag mute">未接受</span>';
      const acted = t.claimed || t.locked ? ''
        : t.claimable ? '<button class="xs primary" data-t="claim" data-c="' + esc(t.task_code) + '">领取</button>'
        : AUTO_TASKS[t.task_code] ? '<button class="xs primary" data-t="auto" data-c="' + esc(t.task_code) + '" title="' + esc(AUTO_TASKS[t.task_code]) + '">一键完成</button>'
        : t.accept_status === 'accepted' ? ''
        : '<button class="xs" data-t="accept" data-c="' + esc(t.task_code) + '">接受</button>';
      // 操作指引（description/task_desc）挂 title 提示：如何完成交给用户看
      const tip = [t.title, t.task_desc || t.description, t.jump_url ? '跳转：' + t.jump_url : ''].filter(Boolean).join('\n');
      return '<tr title="' + esc(tip) + '"><td class="mark" aria-hidden="true"><i></i></td>' +
        '<td class="who"><div class="nm">' + esc(t.title || t.task_code) + '</div><div class="id">' + esc(t.task_code) + (t.tag ? ' · ' + esc(t.tag) : '') + '</div></td>' +
        '<td class="num">' + esc(prog) + '</td>' +
        '<td class="num">' + esc(reward) + '</td>' +
        '<td>' + badge + '</td>' +
        '<td class="acts">' + acted + '</td></tr>';
    }).join('');
    st.hidden = true;
    tb.hidden = false;
  } catch (e) {
    st.className = 'state err';
    st.textContent = e.message;
  }
}

$('taskBody').addEventListener('click', async ev => {
  const b = ev.target.closest('button[data-t]');
  if (!b || !taskUID) return;
  const kind = b.dataset.t, code = b.dataset.c;
  b.disabled = true;
  try {
    if (kind === 'auto') {
      // 一键完成：后端执行动作 → 回读进度 → 汇报（耗时可到分钟级，含真实对话）
      b.textContent = '执行中…';
      const r = await api('accounts/' + encodeURIComponent(taskUID) + '/tasks/auto', {
        method: 'POST', body: JSON.stringify({ task_code: code })
      });
      if (r.skipped) {
        toast(r.message || '已跳过', 'ok');
      } else {
        const advanced = r.progress_before !== r.progress_after;
        let msg = r.message || '已执行';
        if (r.progress_after) msg += `（进度 ${r.progress_before} → ${r.progress_after}）`;
        if (r.claimed) msg += '，奖励已自动到账';
        else if (r.claimable) msg += r.claim_error ? '，可点「领取」重试' : '';
        else if (r.attempt && !advanced) msg += '；进度未动，该任务可能需要官方客户端';
        toast(msg, (r.claimed || advanced) ? 'ok' : 'err');
      }
      loadOverview(true);
    } else {
      const path = 'accounts/' + encodeURIComponent(taskUID) + '/tasks/' + (kind === 'claim' ? 'claim' : 'accept');
      const body = kind === 'claim' ? { task_code: code } : { task_codes: [code] };
      await api(path, { method: 'POST', body: JSON.stringify(body) });
      toast(kind === 'claim' ? '已领取奖励' : '已接受任务', 'ok');
      if (kind === 'claim') loadOverview(true);
    }
  } catch (e) { toast(e.message, 'err'); }
  finally { loadTasks(); }
});

/* ── 任务中心：开学季 + 全账号扫描/队列 ──────────────────────────── */
const SCHOOL_META = [
  ['share_invite', '分享'],
  ['desktop_chat_1_time', '桌面'],
  ['chat_3_times', '对话×3'],
  ['expert_use', '专家'],
  ['task_student_verify', '认证'],
];
// 开学季任务单元：✓ 已领（绿）｜◐ x/y 进行中（琥珀）｜○ 未做（灰）
function staskHTML(t) {
  if (!t) return '<span class="stask todo"><span class="mark">·</span>—</span>';
  if (t.status === 'claimed') return '<span class="stask ok"><span class="mark">✓</span>已领</span>';
  if (t.status === 'completed') return '<span class="stask warn"><span class="mark">◆</span>可领</span>';
  if (t.status === 'in_progress') {
    const fr = t.target_count ? '<span class="fr">' + t.progress + '/' + t.target_count + '</span>' : '';
    return '<span class="stask warn"><span class="mark">◐</span>' + fr + '</span>';
  }
  return '<span class="stask todo"><span class="mark">○</span>未做</span>';
}
const LUCK_SVG = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M3.2 5.2 5 1.8l3 2.4 3-2.4 1.8 3.4-1.4 2.6 1.4 2.6-3.4 2.2H6l-3.4-2.2 1.4-2.6z" opacity=".9"/><circle cx="8" cy="9" r="1.1" fill="currentColor" stroke="none"/></svg>';
async function loadSchoolStatus(quiet) {
  const st = $('schoolState'), list = $('schoolList');
  if (!quiet) { st.hidden = false; st.className = 'state'; st.innerHTML = '<span class="dots">查询中</span>'; list.innerHTML = ''; }
  try {
    const d = await api('school/status');
    const arr = d.accounts || [];
    if (!arr.length) {
      st.hidden = false; st.className = 'state'; st.textContent = '暂无可用账号';
      list.innerHTML = ''; return;
    }
    let allDone = 0;
    const head = '<div class="shead"><div class="who">账号</div><div class="stasks">' +
      SCHOOL_META.map(([, name]) => '<span>' + esc(name) + '</span>').join('') +
      '</div><div class="luck">剩余抽奖</div></div>';
    // 外层滚动壳：表头 + 数据行一起横向平移（窄屏表宽 ~560px，见 index.html 注释）。
    list.innerHTML = '<div class="swrap-scroll"><div class="swrap-table">' + head + arr.map(v => {
      const by = {};
      (v.tasks || []).forEach(t => by[t.task_code] = t);
      const cells = SCHOOL_META.map(([code]) => {
        const t = by[code];
        const html = code === 'task_student_verify'
          ? '<span class="stask todo"><span class="mark">—</span>不做</span>'
          : staskHTML(t);
        return '<span title="' + esc(SCHOOL_TITLES[code] || code) + '">' + html + '</span>';
      }).join('');
      const done = SCHOOL_META.filter(([code]) => code !== 'task_student_verify' && by[code] && by[code].status === 'claimed').length;
      allDone += done === 4 ? 1 : 0;
      return '<div class="srow">' +
        '<div class="who"><div class="nm" title="' + esc(v.nickname || '') + '">' + esc(v.nickname || '未命名') + '</div><div class="id">' + esc(v.uid) + '</div></div>' +
        '<div class="stasks">' + cells + '</div>' +
        '<div class="luck" title="剩余抽奖次数">' + LUCK_SVG + (v.chances == null ? '—' : v.chances) + '</div>' +
        (v.error ? '<div class="err">' + esc(v.error) + '</div>' : '') +
        '</div>';
    }).join('') + '</div></div>';
    $('schoolSummary').textContent = allDone === arr.length ? '今日全部完成 🎉' : allDone + '/' + arr.length + ' 个账号今日全部完成';
    st.hidden = true;
  } catch (e) {
    st.hidden = false; st.className = 'state err'; st.textContent = e.message;
  }
}
const SCHOOL_TITLES = {
  share_invite: '分享活动 +100c', desktop_chat_1_time: '桌面端体验 +100c（单次）',
  chat_3_times: '和 AI 对话 3 次 +50c', expert_use: '召唤开学季专家 +50c',
  task_student_verify: '学生认证 +100c（需真实认证，不做）',
};
$('btnSchoolRefresh').onclick = () => loadSchoolStatus(false);
$('btnSchoolRunAll').onclick = async () => {
  if (!confirm('将对全部账号执行开学季闭环（分享/桌面/对话/专家 + 抽奖），约 1-2 分钟。确认继续？')) return;
  try {
    await api('school/run_all', { method: 'POST' });
    toast('开学季闭环已开始，结果看任务日志', 'ok');
    setTimeout(() => loadSchoolStatus(true), 15000);
  } catch (e) { toast(e.message, 'err'); }
};

/* ── 精简 QR 编码器（券码二维码用）────────────────────────────────────
   规格子集：byte 模式、ECC L、版本 1-5（全部单纠错块，免块交织）、固定掩码 0。
   完整性：规范允许任选掩码（解码器按格式信息位自行去掩码），固定掩码不影响
   可扫描性；已用 python qrcode 库对多输入多版本做逐像素交叉验证（强制 byte
   模式 + mask 0，5/5 全部 diff=0）。面板 CSP 只允许 self，外链 QR 服务不可用。 */
// qr_gen.js —— 精简 QR 编码器（浏览器用 + node 可跑交叉验证）
// 规格子集：byte 模式、ECC L、版本 1-5（全部单纠错块，免块交织）、固定掩码 0。
// 完整性说明：规范允许编码器任选掩码（解码器按格式信息位自行去掩码），
// 固定掩码不影响可扫描性；券码为短文本，v1-5（26 字节起）绰绰有余。

// GF(256) 对数/指数表（本原多项式 0x11d）
const QR_EXP = new Array(512), QR_LOG = new Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) { QR_EXP[i] = x; QR_LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
  for (let i = 255; i < 512; i++) QR_EXP[i] = QR_EXP[i - 255];
})();
const gmul = (a, b) => (a && b) ? QR_EXP[QR_LOG[a] + QR_LOG[b]] : 0;

// 各版本参数（下标 = 版本-1）：[数据码字数, 纠错码字数]，ECC L 单块
const QR_V = [[19, 7], [34, 10], [55, 15], [80, 20], [108, 26]];
// 对齐图案中心坐标（v2+；与定位图案重叠的位置在放置时跳过）
const QR_ALIGN = [[], [6, 18], [6, 22], [6, 26], [6, 30]];
const QR_MASK = (r, c) => (r + c) % 2 === 0; // 掩码模式 0

// 生成多项式（最高次系数在前，g[0] 恒为 1）
function qrGenPoly(deg) {
  let g = [1];
  for (let i = 0; i < deg; i++) {
    const a = QR_EXP[i], ng = new Array(g.length + 1).fill(0);
    ng[0] = g[0];
    for (let j = 1; j < g.length; j++) ng[j] = g[j] ^ gmul(a, g[j - 1]);
    ng[g.length] = gmul(a, g[g.length - 1]);
    g = ng;
  }
  return g;
}

// Reed-Solomon 求余（综合除法），返回 deg 个纠错码字
function rsRem(data, deg) {
  const g = qrGenPoly(deg);
  const res = data.concat(new Array(deg).fill(0));
  for (let i = 0; i < data.length; i++) {
    const f = res[i];
    if (f) for (let j = 0; j < g.length; j++) res[i + j] ^= gmul(g[j], f);
  }
  return res.slice(data.length);
}

// 文本 → 码字流（byte 模式：0100 + 8 位计数 + 数据 + 终止符 + 0xEC/0x11 填充）
function qrDataCodewords(text, dataCap) {
  const bytes = Array.from(new TextEncoder().encode(text));
  const bits = [];
  const push = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >> i) & 1); };
  push(4, 4);            // byte 模式
  push(bytes.length, 8); // v1-9 计数 8 位
  for (const b of bytes) push(b, 8);
  const cap = dataCap * 8;
  push(0, Math.min(4, cap - bits.length));   // 终止符
  while (bits.length % 8) bits.push(0);
  const out = [];
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0; for (const b of bits.slice(i, i + 8)) v = (v << 1) | b;
    out.push(v);
  }
  for (let p = 0; out.length < dataCap; p ^= 1) out.push(p ? 0x11 : 0xEC);
  return out;
}

// 主入口：text → 布尔矩阵（true=深色模块）
function qrMatrix(text) {
  const bytes = Array.from(new TextEncoder().encode(text));
  // 版本选择：需求 ≈ 2 码字头 + 文本长度，取首个放得下的版本
  let ver = 0;
  for (let v = 0; v < QR_V.length; v++) { if (bytes.length + 2 <= QR_V[v][0]) { ver = v + 1; break; } }
  if (!ver) throw new Error('QR: text too long (>' + QR_V[4][0] + ' bytes)');
  const [dataCap, ecCap] = QR_V[ver - 1];
  const n = 17 + 4 * ver;

  const M = Array.from({ length: n }, () => new Array(n).fill(false));
  const F = Array.from({ length: n }, () => new Array(n).fill(false)); // 功能模块占位

  const setF = (r, c, v) => { M[r][c] = v; F[r][c] = true; };
  // 定位图案 + 分隔带
  const finder = (r0, c0) => {
    for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) {
      const rr = r0 + r, cc = c0 + c;
      if (rr < 0 || cc < 0 || rr >= n || cc >= n) continue;
      const dark = r >= 0 && r <= 6 && c >= 0 && c <= 6 && (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
      setF(rr, cc, dark);
    }
  };
  finder(0, 0); finder(0, n - 7); finder(n - 7, 0);
  // 校正图形（仅贯穿两定位图案之间：8..n-9，不得覆盖定位图案本体）
  for (let r = 8; r <= n - 9; r++) setF(r, 6, r % 2 === 0);
  for (let c = 8; c <= n - 9; c++) setF(6, c, c % 2 === 0);
  // 对齐图案（v2+，跳过与定位重叠处）
  const align = QR_ALIGN[ver - 1] || [];
  for (const ar of align) for (const ac of align) {
    if (F[ar][ac]) continue;
    for (let r = -2; r <= 2; r++) for (let c = -2; c <= 2; c++)
      setF(ar + r, ac + c, Math.max(Math.abs(r), Math.abs(c)) !== 1);
  }
  // 暗模块 + 格式信息（ECC L=01，掩码 0）——BCH(15,5) + 0x5412 异或。
  // 位序遵循规范（与 python qrcode 逐位对齐验证）：bit i 从 LSB 起数，
  // 副本一走左上角 L 形、副本二走右下 L 形。
  let fmt = (1 << 3) | 0; // L<<3 | mask
  let rem = fmt << 10;
  for (let i = 14; i >= 10; i--) if ((rem >> i) & 1) rem ^= 0x537 << (i - 10);
  fmt = ((fmt << 10) | rem) ^ 0x5412; // 15 位
  const fb = i => (fmt >> i) & 1;
  // 副本一（左上）：位 0..5 → (i,8)；6 → (7,8)；7 → (8,8)
  for (let i = 0; i <= 5; i++) setF(i, 8, !!fb(i));
  setF(7, 8, !!fb(6)); setF(8, 8, !!fb(7));
  // 副本一续 + 副本二（右下）：位 8..14 → (n-15+i, 8)；位 0..7 → (8, n-1-i)；8 → (8,7)；9..14 → (8,14-i)
  for (let i = 8; i <= 14; i++) setF(n - 15 + i, 8, !!fb(i));
  for (let i = 0; i <= 7; i++) setF(8, n - 1 - i, !!fb(i));
  setF(8, 7, !!fb(8));
  for (let i = 9; i <= 14; i++) setF(8, 14 - i, !!fb(i));
  // 暗模块（恒为深色，位于副本一垂直段末端）
  setF(n - 8, 8, true);


  // 数据码字 + 纠错码字 → 位流
  const dcw = qrDataCodewords(text, dataCap);
  const cw = dcw.concat(rsRem(dcw, ecCap));
  const bits = [];
  for (const b of cw) for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);

  // 蛇形放置（成对列，从右向左，跳过第 6 列），写数据时直接异或掩码
  let bi = 0, up = true;
  for (let x = n - 1; x > 0; x -= 2) {
    if (x === 6) x--;
    for (let i = 0; i < n; i++) {
      const r = up ? n - 1 - i : i;
      for (const c of [x, x - 1]) {
        if (F[r][c]) continue;
        const bit = bi < bits.length ? bits[bi++] : 0;
        M[r][c] = bit ? !QR_MASK(r, c) : QR_MASK(r, c);
      }
    }
    up = !up;
  }
  return M;
}

// 矩阵 → SVG（quiet zone 4 模块）
function qrSVG(M, px) {
  const n = M.length, q = 4, total = n + q * 2;
  let s = '<svg viewBox="0 0 ' + total + ' ' + total + '" width="' + px + '" height="' + px + '" shape-rendering="crispEdges" role="img" style="background:#fff">';
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++)
    if (M[r][c]) s += '<rect x="' + (c + q) + '" y="' + (r + q) + '" width="1" height="1"/>';
  return s + '</svg>';
}

/* ── 开学季券码查询（弹窗，仿活动页 #/prizes?tab=vouchers）──────────── */
/* copyText：clipboard API 只在 secure context（https/localhost）可用，
   远程 http 面板会拿不到 navigator.clipboard → 降级 execCommand。 */
function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  return new Promise((resolve, reject) => {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy') ? resolve() : reject(new Error('copy failed')); }
    catch (e) { reject(e); }
    finally { ta.remove(); }
  });
}

function vcCard(v) {
  const expired = v.valid_to && new Date(v.valid_to) < new Date();
  return '<div class="vc' + (expired ? ' expired' : '') + '">' +
    '<div class="hd"><span class="nm">' + esc(v.prize_name || v.sku_code || '券') + '</span>' +
    (expired ? '<span class="tag bad">已过期</span>' : '<span class="tag ok">可使用</span>') + '</div>' +
    '<div class="meta">' +
      (v.valid_to ? '有效期至 ' + esc(v.valid_to) : '长期有效') +
      (v.granted_at ? ' · ' + esc(v.granted_at.slice(0, 10)) + ' 抽中' : '') +
    '</div>' +
    '<div class="sep"></div>' +
    '<div class="ft"><span class="lab">券码</span><code>' + esc(v.code || '-') + '</code>' +
    '<span class="acts">' +
      (v.code ? '<button class="xs ghost" data-qr="' + esc(v.code) + '">二维码</button>' : '') +
      '<button class="xs ghost" data-copy="' + esc(v.code || '') + '">复制</button>' +
    '</span></div>' +
    '</div>';
}

async function loadSchoolVouchers() {
  const body = $('vcBody');
  $('vcVeil').classList.add('on');
  body.innerHTML = '<div class="state"><span class="dots">查询中</span></div>';
  $('vcNote').textContent = '';
  try {
    const d = await api('school/vouchers');
    const arr = d.accounts || [];
    const ok = arr.filter(a => !a.error);
    const total = ok.reduce((n, a) => n + (a.vouchers || []).length, 0);
    body.innerHTML = ok.filter(a => (a.vouchers || []).length).map(a =>
      '<div class="vc-acct"><span class="nm">' + esc(a.nickname || a.uid) + '</span>' +
      '<span>' + a.vouchers.length + ' 张</span></div>' +
      a.vouchers.map(vcCard).join('')
    ).join('') || '<div class="empty"><div class="big">🎟️</div>还没有抽到券</div>';
    $('vcNote').textContent = total ? total + ' 张券 · ' + ok.filter(a => !(a.vouchers || []).length).length + ' 个账号未抽中' : '';
    const errs = arr.filter(a => a.error);
    if (errs.length) {
      body.insertAdjacentHTML('beforeend', '<div class="note" style="color:var(--warn);margin-top:8px">查询失败：' +
        errs.map(a => esc(a.nickname || a.uid.slice(0, 8)) + '（' + esc(a.error) + '）').join('、') + '</div>');
    }
    body.querySelectorAll('button[data-copy]').forEach(b => b.onclick = async () => {
      try { await copyText(b.dataset.copy); toast('券码已复制', 'ok'); }
      catch (e) { toast('复制失败，请手动选择券码', 'err'); }
    });
    // 二维码：券码本体编码为 QR（到店出示扫描），点击切换显示/隐藏
    body.querySelectorAll('button[data-qr]').forEach(b => b.onclick = () => {
      const card = b.closest('.vc');
      const old = card.querySelector('.vc-qr');
      if (old) { old.remove(); return; }
      const box = document.createElement('div');
      box.className = 'vc-qr';
      try { box.innerHTML = qrSVG(qrMatrix(b.dataset.qr), 148); }
      catch (e) { box.innerHTML = '<span class="note">二维码生成失败：' + esc(e.message) + '</span>'; }
      card.appendChild(box);
    });
  } catch (e) {
    body.innerHTML = '<div class="state err">' + esc(e.message) + '</div>';
  }
}
$('btnSchoolVouchers').onclick = loadSchoolVouchers;
$('btnVcClose').onclick = () => $('vcVeil').classList.remove('on');
$('btnVcRefresh').onclick = loadSchoolVouchers;

/* 成长任务队列。lastQueueSeq 记录本页启动过的队列代次：执行结束后的残留 items
   （running=false 但 seq 停在旧值）不再回写视图——否则扫描结果 3 秒后被上一轮
   队列状态覆盖。 */
let queueTimer = null, lastQueueSeq = 0;
// scanHold：用户刚点「扫描待办」后为 true，暂停自动轮询回写队列视图，
// 避免扫描结果被后端上一轮队列的残留数据覆盖（见 pollQueueOnce 注释）。
// 点「执行全部待办」启动新队列、或切走视图时清除。
let scanHold = false;
const GROWTH_TITLES = {}; // code → 展示名（扫描时从任务列表带出）
$('btnScanAll').onclick = async () => {
  const b = $('btnScanAll');
  b.disabled = true; b.textContent = '扫描中…';
  try {
    const d = await api('tasks/scan_all', { method: 'POST' });
    // 扫描结果展示后进入"保持"状态，防止 5 秒一次的自动轮询用后端残留队列数据覆盖它。
    scanHold = true;
    renderQueue(groupItems(d), null, '没有待办任务 🎉', '全部账号的成长任务与开学季活动都已完成，明日再来。');
  } catch (e) { toast(e.message, 'err'); }
  finally { b.disabled = false; b.textContent = '扫描待办'; }
};
$('btnRunQueue').onclick = async () => {
  const conc = Number($('qcConc').value) || 1;
  if (!confirm('扫描全部账号待办并排队执行（账号并发 ' + conc + '，账号内串行）。\n含真实对话的任务耗时较长，确认继续？')) return;
  const b = $('btnRunQueue');
  b.disabled = true; b.textContent = '启动中…';
  try {
    const r = await api('tasks/run_queue', { method: 'POST', body: JSON.stringify({ concurrency: conc }) });
    if (!r.started) { toast(r.message || '没有待办任务', 'ok'); return; }
    lastQueueSeq = r.seq || 0;
    scanHold = false;   // 启动新队列，恢复自动轮询回写
    toast('队列已启动：' + r.total + ' 项（并发 ' + conc + '）', 'ok');
    startQueuePolling();
  } catch (e) { toast(e.message, 'err'); }
  finally { b.disabled = false; b.textContent = '执行全部待办'; }
};
// 扫描结果 → 分组条目（无执行状态）
function groupItems(d) {
  const groups = [];
  for (const a of (d.accounts || [])) {
    const rows = [];
    for (const t of (a.growth || [])) {
      GROWTH_TITLES[t.task_code] = t.title || t.task_code;
      rows.push({ kind: 'growth', code: t.task_code, prog: t.target ? t.current + '/' + t.target : '—', status: 'scan' });
    }
    for (const t of (a.school || [])) {
      if (t.task_code === 'task_student_verify') continue; // 需真实认证，永不出现在待办
      rows.push({ kind: 'school', code: t.task_code, prog: t.target_count ? t.progress + '/' + t.target_count : '—', status: 'scan' });
    }
    if (rows.length) groups.push({ uid: a.uid, nick: a.nickname, rows });
  }
  return groups;
}
const ST_WORDS = { done: '完成', running: '执行中', error: '失败', skipped: '跳过', pending: '排队', scan: '待执行' };
function qrowHTML(it) {
  const isSchool = it.kind === 'school';
  const title = isSchool ? '开学季闭环' : (GROWTH_TITLES[it.code] || it.code);
  const dotCls = it.status === 'scan' ? 'wait' : it.status === 'running' ? 'run' : it.status === 'error' ? 'err' : it.status === 'skipped' ? 'skip' : it.status === 'done' ? 'done' : 'wait';
  const stWord = it.status === 'scan' ? '待执行' : (ST_WORDS[it.status] || it.status);
  return '<div class="qrow" title="' + esc(it.message || '') + '">' +
    '<span class="code">' + esc(it.code) + '</span>' +
    '<span class="name"><span class="t">' + esc(title) + '</span>' + (isSchool ? '<span class="tag mute">开学季</span>' : '') + '</span>' +
    '<span class="prog">' + esc(it.prog || '') + '</span>' +
    '<span class="st"><span class="qdot ' + dotCls + '"></span>' + stWord + '</span>' +
    '<span class="msg">' + esc(it.message || '') + '</span>' +
    '</div>';
}
function renderQueue(groups, progress, emptyTitle, emptyDesc) {
  const empty = $('tcEmpty'), list = $('qcList');
  if (!groups.length) {
    empty.style.display = '';
    if (emptyTitle) empty.querySelector('.t').textContent = emptyTitle;
    if (emptyDesc) empty.querySelector('.d').textContent = emptyDesc;
    list.innerHTML = '';
    $('qProg').hidden = true; $('qcSummary').textContent = '';
    return;
  }
  empty.style.display = 'none';
  let total = 0;
  // 两层结构：.qscroll(滚动壳) > .qtable(内容)。窄屏下表比屏幕宽，整表一起
  // 横向滑动，滑一次即可对齐看完所有行的说明。桌面端不产生滚动条
  // （CSS 只在 max-width:760px 断点给 .qscroll overflow-x:auto）。
  // 外层还有左右箭头按钮，供手势不可靠的环境（部分 WebView）点按翻页。
  list.innerHTML = '<div class="qscroll"><div class="qtable">' + groups.map(g => {
    total += g.rows.length;
    return '<div class="qgroup"><header><span class="nm">' + esc(g.nick || g.uid.slice(0, 12)) + '</span><span class="cnt">' + g.rows.length + ' 项待办</span></header>' +
      g.rows.map(qrowHTML).join('') + '</div>';
  }).join('') + '</div></div>';
  $('qcSummary').textContent = total + ' 项';
  updateProgress(progress);
}
function updateProgress(q) {
  if (!q || !q.items) { $('qProg').hidden = true; return; }
  const total = q.items.length;
  const done = q.items.filter(it => it.status === 'done' || it.status === 'error' || it.status === 'skipped').length;
  $('qProg').hidden = false;
  $('qBarFill').style.width = (total ? Math.round(done / total * 100) : 0) + '%';
  $('qProgText').textContent = (q.running ? '执行中 ' : '已结束 ') + done + ' / ' + total;
}

// 队列状态 → 分组（执行时轮询）
function groupsFromQueue(items) {
  const by = new Map();
  for (const it of items) {
    if (!by.has(it.uid)) by.set(it.uid, { uid: it.uid, nick: it.nickname, rows: [] });
    by.get(it.uid).rows.push({
      kind: it.kind, code: it.code,
      prog: it.kind === 'school' ? '—' : '',
      status: it.status, message: it.message,
    });
  }
  return Array.from(by.values());
}
async function pollQueueOnce() {
  try {
    const q = await api('tasks/queue');
    if (!q.started) return;
    // 只渲染本页启动过的那轮队列（q.running 时也要同代次——刷新页面后不再接管旧队列）。
    if (lastQueueSeq && q.seq !== lastQueueSeq) return;
    // ★ 用户刚点过「扫描待办」：此时视图里是扫描结果（列 = 全部待办），
    //   不能被后端上一轮队列的残留 items 覆盖。此前仅靠 lastQueueSeq 判断，
    //   但从未点过「执行全部待办」时它恒为 0，保护失效 →
    //   扫描结果最多 5 秒后（refTimer）即被残留数据冲掉，表现为"任务出现一会又消失"。
    //   这里显式拦住：扫描后自动轮询不再回写，直到用户启动新队列或切走视图。
    if (scanHold) return;
    renderQueue(groupsFromQueue(q.items || []), q);
  } catch (e) { /* 静默 */ }
}
function startQueuePolling() {
  if (queueTimer) clearInterval(queueTimer);
  queueTimer = setInterval(async () => {
    await pollQueueOnce();
    try {
      const q = await api('tasks/queue');
      if (!q.running) {
        clearInterval(queueTimer); queueTimer = null;
        toast('任务队列执行结束', 'ok');
        loadSchoolStatus(true);
      }
    } catch (e) { /* 忽略 */ }
  }, 3000);
}

/* ── 用量 ─────────────────────────────────────────────────────────── */
/* 图表用原生 SVG 手绘：面板是 go:embed 单文件、无构建步骤，引入图表库
   就得带上打包器，得不偿失。这里只需要堆叠柱状图，二十行足够。 */

function fmtTok(n) {
  n = Number(n || 0);
  if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}
function fmtMs(ms) {
  ms = Number(ms || 0);
  if (!ms) return '—';
  if (ms >= 1000) return (ms / 1000).toFixed(2) + 's';
  return Math.round(ms) + 'ms';
}
function fmtRate(r) { return r ? Number(r).toFixed(1) + ' tok/s' : '—'; }

function usStat(v, k, cls) {
  return '<div class="stat ' + (cls || '') + '"><div class="v">' + esc(v) +
         '</div><div class="k">' + esc(k) + '</div></div>';
}

function usBar(prompt, completion, total) {
  const t = Number(total || 0);
  if (!t) return '';
  const pp = Math.max(0, Math.min(100, Number(prompt || 0) / t * 100));
  const pc = Math.max(0, Math.min(100, Number(completion || 0) / t * 100));
  return '<span class="us-wrapbar">' +
    '<span class="bar bar-p" style="width:' + (pp * 0.8).toFixed(1) + 'px" title="prompt"></span>' +
    '<span class="bar bar-c" style="width:' + Math.max(2, pc * 0.8).toFixed(1) + 'px" title="completion"></span>' +
    '</span>';
}

/* usRow 生成一行。mid 是插在「名称」之后、请求数之前的额外单元格（如「域」列）。
   withPerf 控制是否追加延迟/速率两列——只有「按账号」表的表头带这两列；
   模型表与域表没有，多输出会造成列错位。早先靠「mid 是否为 undefined」隐式
   判断，调用方稍一改动就会错列，故改为显式参数。 */
function usRow(name, sub, a, mid, withPerf) {
  return '<tr>' +
    '<td class="mark" aria-hidden="true"></td>' +
    '<td>' + esc(name) + (sub ? '<div class="note">' + esc(sub) + '</div>' : '') + '</td>' +
    (mid || '') +
    '<td class="num">' + fmtTok(a.requests) + '</td>' +
    '<td class="num">' + (a.errors ? '<span style="color:var(--warn)">' + fmtTok(a.errors) + '</span>' : '—') + '</td>' +
    '<td class="num">' + fmtTok(a.prompt_tokens) + '</td>' +
    '<td class="num">' + fmtTok(a.completion_tokens) + '</td>' +
    '<td class="num">' + fmtTok(a.total_tokens) + '</td>' +
    (withPerf
      ? '<td class="num">' + fmtMs(a.avg_latency_ms) + '</td>' +
        '<td class="num">' + fmtRate(a.avg_tokens_per_second) + '</td>'
      : '') +
    '</tr>';
}

function renderUsage(d) {
  const t = d.totals || {};
  $('usStats').innerHTML =
    usStat(fmtTok(t.requests), '请求数') +
    usStat(fmtTok(t.total_tokens), '总 token') +
    usStat(fmtTok(t.prompt_tokens), 'prompt') +
    usStat(fmtTok(t.completion_tokens), 'completion') +
    usStat(t.errors ? String(t.errors) : '0', '失败尝试', t.errors ? 'warn' : '') +
    usStat(fmtMs(t.avg_latency_ms), '平均延迟');

  $('usNote').textContent = (d.buckets || 0) + ' 个分桶 · ' +
    (d.since ? '自 ' + d.since.slice(0, 10) : '无数据') +
    (d.file_bytes ? ' · ' + (d.file_bytes / 1024).toFixed(1) + ' KB' : '');

  $('usAccBody').innerHTML = (d.by_account || []).map(x =>
    usRow(x.key.slice(0, 8), x.extra || '', x,
      '<td class="num">' + esc(x.realm || '') + '</td>', true)
  ).join('') || '<tr><td colspan="10" class="empty">暂无数据</td></tr>';

  $('usModelBody').innerHTML = (d.by_model || []).map(x => {
    // 模型行：拆出域与裸名（key 形如 "global:deepseek-v4.1-flash"）。
    // 域单独成列——同名模型跨域倍率/上下文可能不同，混在一起看会误判。
    const i = x.key.indexOf(':');
    const realm = i > 0 ? x.key.slice(0, i) : '';
    const bare = i > 0 ? x.key.slice(i + 1) : x.key;
    return usRow(bare, '', x,
      '<td class="num"><span class="realm-tag' + (realm === 'global' ? ' gl' : '') + '">' +
      esc(realm || '—') + '</span></td>', true);
  }).join('') || '<tr><td colspan="9" class="empty">暂无数据</td></tr>';

  $('usRealmBody').innerHTML = (d.by_realm || []).map(x =>
    usRow(x.key, '', x, '', false)).join('') || '<tr><td colspan="7" class="empty">暂无数据</td></tr>';

  renderUsageChart(d.series || []);
}

/* renderUsageChart 画堆叠柱状图。日点与小时点混用 x 轴，因此按数据序号等距
   排布（不按真实时间比例），并在标签上区分粒度——用量面板看的是相对高低，
   不是精确的时间刻度。 */
function renderUsageChart(series) {
  const host = $('usChart');
  if (!series.length) {
    host.innerHTML = '<div class="us-empty">暂无用量数据。发起一次对话后再刷新。</div>';
    return;
  }
  const W = 760, H = 170, PL = 46, PR = 10, PT = 12, PB = 26;
  const iw = W - PL - PR, ih = H - PT - PB;

  const max = Math.max(1, ...series.map(p => Number(p.total_tokens || 0)));
  const bw = Math.max(2, Math.min(26, iw / series.length - 3));

  let out = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" role="img">';
  // y 轴网格 + 刻度（4 档）
  for (let i = 0; i <= 4; i++) {
    const v = max * i / 4;
    const y = PT + ih - (ih * i / 4);
    out += '<line class="gl" x1="' + PL + '" y1="' + y + '" x2="' + (W - PR) + '" y2="' + y + '"/>';
    out += '<text class="tk" x="' + (PL - 6) + '" y="' + (y + 3.5) + '" text-anchor="end">' + fmtTok(v) + '</text>';
  }
  out += '<line class="ax" x1="' + PL + '" y1="' + (PT + ih) + '" x2="' + (W - PR) + '" y2="' + (PT + ih) + '"/>';

  const step = iw / series.length;
  series.forEach((p, i) => {
    const pt = Number(p.prompt_tokens || 0), ct = Number(p.completion_tokens || 0);
    const tt = Number(p.total_tokens || 0) || (pt + ct);
    const x = PL + i * step + (step - bw) / 2;
    const hTot = ih * (tt / max);
    const hP = tt ? hTot * (pt / tt) : 0;
    const hC = Math.max(tt && ct ? 1 : 0, hTot - hP);
    const yBase = PT + ih;
    if (hP > 0) out += '<rect x="' + x.toFixed(1) + '" y="' + (yBase - hP).toFixed(1) +
      '" width="' + bw.toFixed(1) + '" height="' + hP.toFixed(1) + '" fill="var(--accent)" rx="1.5"/>';
    if (hC > 0) out += '<rect x="' + x.toFixed(1) + '" y="' + (yBase - hP - hC).toFixed(1) +
      '" width="' + bw.toFixed(1) + '" height="' + hC.toFixed(1) + '" fill="var(--ok)" rx="1.5"/>';
    // 只给稀疏的几根画标签，避免拥挤
    const every = Math.ceil(series.length / 8);
    if (i % every === 0) {
      const lab = p.scope === 'day' ? p.t.slice(5) : p.t.slice(11) + ':00';
      out += '<text class="tk" x="' + (x + bw / 2).toFixed(1) + '" y="' + (H - 8) +
        '" text-anchor="middle">' + esc(lab) + '</text>';
    }
    out += '<title>' + esc(p.t) + ' (' + esc(p.scope) + ')  ' +
      fmtTok(p.prompt_tokens) + ' prompt / ' + fmtTok(p.completion_tokens) + ' completion / ' +
      (p.requests || 0) + ' 次</title>';
  });
  out += '</svg>';
  host.innerHTML = out;
}

function fmtTokTip(v) { return fmtTok(v); }

async function loadUsage() {
  const hours = ($('usWindow') && $('usWindow').value) || 72;
  try {
    const d = await api('usage?hours=' + encodeURIComponent(hours));
    renderUsage(d);
  } catch (e) {
    $('usChart').innerHTML = '<div class="us-empty">读取用量失败：' + esc(e.message) + '</div>';
  }
}

if ($('btnUsage')) $('btnUsage').onclick = loadUsage;
if ($('usWindow')) $('usWindow').onchange = loadUsage;

/* ── 积分构成 ─────────────────────────────────────────────────────── */
/* 一个账号的余额是若干积分包之和。包按来源命名（「国内运营裂变包」「拉新权益包」
   「个人体验版」…），面额从 6 到 1500 不等，且**按次发放**。所以两个任务完成度
   完全一致的账号，余额可能差上千——差别只在包里。这里把逐包明细摊开，并给每个
   包名一个稳定配色，跨账号对比时同色即同类。 */

const PK_COLORS = ['#4f8cff', '#25b08b', '#e8a33d', '#c96bd6', '#e2607a',
                   '#5aa9e6', '#8fbf3f', '#b58b5a', '#7d8fa8', '#d4785c'];

function pkColor(i) { return PK_COLORS[i % PK_COLORS.length]; }

/* pkBySource 把包按名称归并，得到「来源 → 面额/余额/个数」。这是对比的关键视图：
   两个号的差异一定体现在某几个来源的面额上。 */
function pkBySource(packs) {
  const m = new Map();
  for (const p of packs) {
    // 分组键用 code + name，而不是只 name：上游给「首登赠送」和普通活动包用了
    // **同一个 PackageName 和同一个 PackageCode**，只按 name 会把两类混成一类，
    // 那正是当初「两个号为何差 1500」看不出来的原因。这里至少把 code 带进键里，
    // 并在卡片上显示最早的发放时间。
    const k = (p.package_code || '') + '|' + (p.name || '(未命名)');
    const e = m.get(k) || {
      key: k, name: p.name || '(未命名)', code: p.package_code || '',
      n: 0, remain: 0, size: 0, used: 0, minEnd: '', minCreated: '',
    };
    e.n += 1;
    e.remain += Number(p.remain || 0);
    e.size += Number(p.size || 0);
    e.used += Number(p.used || 0);
    const t = (p.end_time || '').slice(0, 10);
    if (t && (!e.minEnd || t < e.minEnd)) e.minEnd = t;
    const c = (p.created_at || '').slice(0, 10);
    if (c && (!e.minCreated || c < e.minCreated)) e.minCreated = c;
    m.set(k, e);
  }
  return [...m.values()].sort((a, b) => b.size - a.size);
}

function renderPackages(d) {
  const list = (d.accounts || []);
  if (!list.length) {
    $('pkSummary').innerHTML = '<div class="empty">没有账号</div>';
    return;
  }

  // 包名 → 稳定色号（跨账号一致，方便肉眼对齐）
  const names = [];
  for (const a of list) for (const s of pkBySource(a.packages || [])) {
    if (!names.includes(s.key)) names.push(s.key);
  }
  names.sort((x, y) => {
    const sz = n => Math.max(...list.map(a => {
      const f = pkBySource(a.packages || []).find(s => s.key === n);
      return f ? f.size : 0;
    }));
    return sz(y) - sz(x);
  });
  const colorOf = n => pkColor(names.indexOf(n));
  // 键 → 展示名，供卡片与明细表共用（同一来源必然同色同名）。
  const labelOf = {};
  for (const a of list) for (const s of pkBySource(a.packages || [])) labelOf[s.key] = s;

  const maxRemain = Math.max(1, ...list.map(a => Number(a.remain || 0)));

  $('pkSummary').innerHTML = list.map(a => {
    if (a.error) {
      return '<div class="pk-card"><div class="who"><span class="nm">' +
        esc((a.nickname || a.uid.slice(0, 8))) + '</span>' +
        '<span class="realm">' + esc(a.realm || '') + '</span></div>' +
        '<div class="err">查询失败：' + esc(a.error) + '</div></div>';
    }
    const srcs = pkBySource(a.packages || []);
    const total = Math.max(1, Number(a.size || 0));
    const bar = srcs.map(s =>
      '<i style="width:' + (s.size / total * 100).toFixed(2) + '%;background:' +
      colorOf(s.key) + '" title="' + esc(s.name) + ' ' + fmtTok(s.size) + '"></i>'
    ).join('');
    const legend = srcs.map(s =>
      '<span><i style="background:' + colorOf(s.key) + '"></i>' +
      esc(s.name.replace(/^CodeBuddy/, '')) + ' x' + s.n + ' · ' + fmtTok(s.size) +
      (s.minCreated ? ' · 首发 ' + esc(s.minCreated.slice(5)) : '') + '</span>'
    ).join('');
    return '<div class="pk-card">' +
      '<div class="who"><span class="nm">' + esc(a.nickname || a.uid.slice(0, 8)) + '</span>' +
      '<span class="realm">' + esc(a.realm || '') + '</span></div>' +
      '<div class="big">' + fmtTok(a.remain) + '</div>' +
      '<div class="sub">共 ' + fmtTok(a.size) + ' · ' + (a.packages || []).length +
      ' 个包 · 占最高 ' + (Number(a.remain || 0) / maxRemain * 100).toFixed(0) + '%</div>' +
      '<div class="mixbar">' + bar + '</div>' +
      '<div class="pk-legend">' + legend + '</div>' +
      '</div>';
  }).join('');

  $('pkNote').textContent = list.length + ' 个账号 · 实时查询上游';

  // 逐包明细：每个账号一个表，包的**面额**列是重点
  $('pkDetail').innerHTML = list.map(a => {
    if (a.error) return '';
    const packs = (a.packages || []);
    const rows = packs.map(p => {
      const k = (p.package_code || '') + '|' + (p.name || '(未命名)');
      const sub = (p.sub_product_code || '').replace(/^sp_tcaca_codebuddyide_?/, '') ||
                  (p.package_code || '').replace(/^TCACA_/, '');
      return '<tr><td class="mark" aria-hidden="true"><i style="background:' +
        colorOf(k) + '"></i></td>' +
      '<td>' + esc(p.name || '(未命名)') +
        (sub ? '<div class="note">' + esc(sub) + '</div>' : '') + '</td>' +
      '<td class="num">' + fmtTok(p.size) + '</td>' +
      '<td class="num">' + fmtTok(p.remain) + '</td>' +
      '<td class="num">' + fmtTok(p.used) + '</td>' +
      '<td class="num">' + esc((p.created_at || '').slice(0, 16).replace('T', ' ') || '—') + '</td>' +
      '<td class="num">' + esc((p.end_time || '').slice(0, 10) || '—') + '</td>' +
      '</tr>';
    }).join('');
    return '<div class="box"><header><h3>' +
      esc(a.nickname || a.uid.slice(0, 8)) + ' · ' + esc(a.realm || '') +
      '</h3><span class="grow"></span><span class="note">余额 ' + fmtTok(a.remain) +
      ' / 总额 ' + fmtTok(a.size) + ' · ' + packs.length + ' 个包（按面额降序）</span>' +
      '</header><div class="tbl-wrap"><table class="acc"><thead><tr>' +
      '<th class="mark" aria-hidden="true"></th><th>包名 / 来源</th>' +
      '<th class="num">面额</th><th class="num">剩余</th><th class="num">已用</th>' +
      '<th class="num">发放</th><th class="num">到期</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table></div></div>';
  }).join('');
}

async function loadPackages() {
  $('pkSummary').innerHTML = '<div class="empty">查询中…（逐账号向上游实时查询）</div>';
  $('pkDetail').innerHTML = '';
  try {
    const d = await api('packages');
    renderPackages(d);
  } catch (e) {
    $('pkSummary').innerHTML = '<div class="empty">读取失败：' + esc(e.message) + '</div>';
  }
}

if ($('btnPk')) $('btnPk').onclick = loadPackages;

/* ════════════════════════════════════════════════════════════════════════
   白名单密钥编辑器（多 key + 按 realm 分组的模型白名单）

   需求：除主密钥 api_key 外，可增删多个受限密钥；每个密钥勾选允许的模型，
        且国内(cn) / 国际(global) 模型分开选，只能选账号池里实际存在的模型。
        用该 key 调接口时，非白名单模型一律 403。

   为什么单独一套 DOM 逻辑、不复用 CFG_MAP：
     CFG_MAP 是「表单字段 → config 路径」的扁平映射，而 keys 是**数组**，
     每项还带动态的模型列表，无法用固定 input id 表达。故独立渲染 + 收集。

   与保存流程的衔接（关键）：
     saveConfig 会从 KEDIT.collect() 取 keys 一并提交。
     注意必须**始终提交 keys**（哪怕是空数组）——config 保存是 merge 语义，
     缺键会保留旧值，导致"删掉的密钥又回来"。

   数据形态：
     { key: "sk-xxx", name: "备注", allow: ["cn:model-a", "global:model-b"] }
     allow 为空数组 = 不限制（等价主密钥）。裸名默认 cn，与 resolveModel 一致。
   ════════════════════════════════════════════════════════════════════════ */
const KEDIT = (() => {
  // 本地草稿状态：与 config.json 的 keys[] 一一对应。
  // 每项：{ key, name, allow: Set<string>, tab: 'cn'|'global', query: string }
  let drafts = [];
  // 账号池模型缓存：{ cn: [模型名...], global: [模型名...] }
  // 拉取失败时置 null，UI 退化为"手输模型名"提示，不阻塞其它配置编辑。
  let modelCache = null;
  // loadAll 为 true 表示当前列表来自「加载所有账号」（合并多账号、不去重）。
  let loadAll = false;
  let loading = false;

  const CANON = (realm, name) => (realm === 'global' ? 'global:' : 'cn:') + name;

  // 裸名（无 realm 前缀）按 cn 归一，与后端 resolveModel 保持一致。
  function parseAllow(list) {
    const out = [];
    for (const raw of list || []) {
      const s = String(raw).trim();
      if (!s) continue;
      out.push(s.includes(':') ? s : 'cn:' + s);
    }
    return out;
  }

  function genKey() {
    // 面板生成：32 字节十六进制，避免用户手填弱 key。
    // crypto.getRandomValues 在 http 下也可用（非安全上下文的例外）。
    const a = new Uint8Array(24);
    crypto.getRandomValues(a);
    return 'sk-' + Array.from(a, b => b.toString(16).padStart(2, '0')).join('');
  }

  /* 手动添加模型名：取该卡片底部输入框的值，按当前 tab 补 realm 前缀后加入白名单。
     允许添加账号池列表里没有的模型（用户按需手填）。加入后由 render 统一渲染为
     已勾选项（含"手动"标记），因此刷新后依然可见、可取消勾选删除。 */
  function addModelFromInput(i) {
    const d = drafts[i];
    if (!d) return;
    const card = $('keyList').children[i];
    const input = card && card.querySelector('[data-act=addmodel-input]');
    if (!input) return;
    let raw = (input.value || '').trim();
    if (!raw) return;
    // 已带 realm 前缀则尊重用户输入，否则按当前 tab 补前缀。
    const id = raw.includes(':') ? raw : CANON(d.tab, raw);
    d.allow.add(id);
    input.value = '';
    render();
  }

  /* 拉取账号池模型。默认按 realm 各一次（cn / global 各取一个账号的目录）；
     传入 all=true 时改调 models?all=1，汇总**全部账号**的模型、按 realm 分组、
     **不去重**（同名模型在多账号间重复出现属预期）。任一失败则整体降级。 */
  async function ensureModels(all) {
    if (modelCache && (all === loadAll)) return modelCache;
    try {
      if (all) {
        const r = await api('models?all=1');
        modelCache = { cn: r.cn || [], global: r.global || [] };
      } else {
        const [cn, gl] = await Promise.all([api('models'), api('models?realm=global')]);
        modelCache = { cn: cn.models || [], global: gl.models || [] };
      }
      loadAll = !!all;
    } catch (e) {
      modelCache = { cn: [], global: [], err: e.message };
    }
    return modelCache;
  }

  function render() {
    const list = $('keyList');
    if (!list) return;
    $('keyEmpty').hidden = drafts.length > 0;
    list.innerHTML = drafts.map((d, i) => {
      const models = (modelCache && modelCache[d.tab]) || [];
      const q = (d.query || '').toLowerCase();
      // 模型是对象（{id,name,...}，见 panel.go 的 models 端点），取 id 匹配；
      // all=1 模式下 cn/global 已是 "cn:xxx" 字符串（已带 realm 前缀）。
      const mid = m => (typeof m === 'string' ? m : (m && m.id) || '');
      // 已带前缀的字符串直接用，否则按当前 tab 补前缀（与后端 resolveModel 一致）。
      const canonOf = m => { const s = mid(m); return s.includes(':') ? s : CANON(d.tab, s); };
      const shown = q ? models.filter(m => mid(m).toLowerCase().includes(q)) : models;
      // 先渲染账号池列表项；id 集合用于判定"已选但不在池中"的手动项。
      const seen = new Set();
      let opts = shown.map(m => {
        const id = canonOf(m);
        seen.add(id);
        return '<label><input type="checkbox" data-act="model" data-i="' + i +
          '" value="' + esc(id) + '"' + (d.allow.has(id) ? ' checked' : '') +
          '><span>' + esc(mid(m)) + '</span></label>';
      }).join('');
      // 关键：把 allow 里"不在当前 tab 账号池列表"的项（如手动添加的模型）
      // 也渲染出来并保持勾选——否则刷新后看不见、也无法取消勾选删除。
      // 仅在无搜索词时展示这些额外项，避免干扰搜索。
      if (!q) {
        const extra = [...d.allow].filter(id => {
          if (seen.has(id)) return false;
          const rid = id.includes(':') ? id.slice(0, id.indexOf(':')) : 'cn';
          return (rid === 'global' ? 'global' : 'cn') === d.tab;
        });
        opts += extra.map(id => '<label><input type="checkbox" data-act="model" data-i="' + i +
          '" value="' + esc(id) + '" checked><span>' + esc(id) +
          ' <em class="kmanual">手动</em></span></label>').join('');
      }
      if (!opts) opts = '<div class="kempty">' +
        (modelCache && modelCache.err ? '模型列表读取失败：' + esc(modelCache.err)
                                      : '该 realm 暂无可用模型') + '</div>';
      const nSel = [...d.allow].filter(a => a.startsWith(d.tab + ':')).length;
      return '' +
        '<div class="keycard">' +
          '<div class="krow">' +
            '<input type="text" class="kname" placeholder="备注名（可选）" data-act="name" data-i="' + i + '" value="' + esc(d.name) + '">' +
            '<button type="button" class="mini" data-act="gen" data-i="' + i + '">随机生成</button>' +
            '<button type="button" class="mini danger" data-act="del" data-i="' + i + '">删除</button>' +
          '</div>' +
          '<div class="krow">' +
            '<input type="text" placeholder="密钥（sk-…）" data-act="key" data-i="' + i + '" value="' + esc(d.key) + '">' +
          '</div>' +
          '<div class="klabel">允许模型（<b>不勾选 = 该密钥禁止使用任何模型</b>）' +
            '<span style="float:right">已选 ' + d.allow.size + ' 个</span></div>' +
          (d.allow.size === 0
            ? '<div class="kwarn">⚠ 未配置任何模型，该密钥将无法调用任何模型（403）。请至少勾选或手动添加一个模型。</div>'
            : '') +
          '<div class="ktabs">' +
            '<button type="button" data-act="tab" data-i="' + i + '" data-v="cn"' + (d.tab === 'cn' ? ' class="on"' : '') + '>国内</button>' +
            '<button type="button" data-act="tab" data-i="' + i + '" data-v="global"' + (d.tab === 'global' ? ' class="on"' : '') + '>国际</button>' +
            '<span style="flex:1"></span>' +
            '<span style="font-size:12px;opacity:.6;align-self:center">本组已选 ' + nSel + '</span>' +
          '</div>' +
          '<input type="text" class="ksearch" placeholder="搜索模型…" data-act="query" data-i="' + i + '" value="' + esc(d.query || '') + '">' +
          '<div class="kmodels">' + opts + '</div>' +
          '<div class="kaddrow">' +
            '<input type="text" placeholder="手动添加模型名（如 deepseek-v4.1-flash）" data-act="addmodel-input" data-i="' + i + '">' +
            '<button type="button" class="mini" data-act="addmodel" data-i="' + i + '">添加</button>' +
          '</div>' +
        '</div>';
    }).join('');
  }

  /* 事件委托：避免每次 render 都重新绑定（render 会整块替换 innerHTML）。 */
  function bind() {
    const list = $('keyList');
    if (!list || list._bound) return;
    list._bound = true;
    list.addEventListener('click', async ev => {
      const el = ev.target.closest('[data-act]');
      if (!el) return;
      const i = +el.dataset.i;
      const d = drafts[i];
      if (!d) return;
      const act = el.dataset.act;
      if (act === 'del') {
        if (!confirm('删除该密钥？使用它的客户端将立即失效。')) return;
        drafts.splice(i, 1);
        render();
      } else if (act === 'gen') {
        d.key = genKey();
        render();
      } else if (act === 'tab') {
        d.tab = el.dataset.v;
        d.query = '';
        render();
      } else if (act === 'addmodel') {
        addModelFromInput(i);
      }
    });
    list.addEventListener('keydown', ev => {
      if (ev.key !== 'Enter') return;
      const el = ev.target.closest('[data-act=addmodel-input]');
      if (!el) return;
      ev.preventDefault();
      addModelFromInput(+el.dataset.i);
    });
    list.addEventListener('input', ev => {
      const el = ev.target.closest('[data-act]');
      if (!el) return;
      const i = +el.dataset.i;
      const d = drafts[i];
      if (!d) return;
      const act = el.dataset.act;
      if (act === 'name') d.name = el.value;
      else if (act === 'key') d.key = el.value.trim();
      else if (act === 'query') {
        // 搜索只影响可见项，不重绘整个卡片，否则输入框会失焦。
        d.query = el.value;
        const box = el.nextElementSibling;
        const q = el.value.toLowerCase();
        const models = (modelCache && modelCache[d.tab]) || [];
        let any = false;
        [...box.querySelectorAll('label')].forEach(lb => {
          const name = lb.querySelector('span').textContent.toLowerCase();
          const hit = !q || name.includes(q);
          lb.style.display = hit ? '' : 'none';
          if (hit) any = true;
        });
        return;
      }
    });
    list.addEventListener('change', ev => {
      const el = ev.target.closest('input[data-act=model]');
      if (!el) return;
      const d = drafts[+el.dataset.i];
      if (!d) return;
      if (el.checked) d.allow.add(el.value);
      else d.allow.delete(el.value);
      // 只更新计数，不整块重绘（保留滚动位置与勾选焦点）。
      const card = el.closest('.keycard');
      if (card) {
        card.querySelector('.klabel span').textContent = '已选 ' + d.allow.size + ' 个';
        const nSel = [...d.allow].filter(a => a.startsWith(d.tab + ':')).length;
        const tabCnt = card.querySelector('.ktabs span span');
        if (tabCnt) tabCnt.textContent = '本组已选 ' + nSel + ' 个';
      }
    });
  }

  /* 用 config.json 的 keys 重置草稿（进入配置页时调用）。 */
  function load(keys) {
    drafts = (keys || []).map(k => ({
      key: k.key || '',
      name: k.name || '',
      allow: new Set(parseAllow(k.allow)),
      tab: 'cn',
      query: '',
    }));
    ensureModels().then(render);
    render(); // 先渲染骨架，模型到位后再补
  }

  /* 收集为可提交的 keys[]。空 key 条目丢弃（用户加了卡没填）。 */
  function collect() {
    return drafts
      .filter(d => d.key.trim())
      .map(d => {
        const o = { key: d.key.trim() };
        if (d.name.trim()) o.name = d.name.trim();
        if (d.allow.size) o.allow = [...d.allow];
        return o;
      });
  }

  bind();
  if ($('btnKeyAdd')) {
    $('btnKeyAdd').onclick = e => {
      e.preventDefault();
      drafts.push({ key: genKey(), name: '', allow: new Set(), tab: 'cn', query: '' });
      render();
    };
  }
  // 「⚡ 加载所有账号模型」：汇总全部账号（不去重），刷新两侧列表。
  if ($('btnKeyLoadAll')) {
    $('btnKeyLoadAll').onclick = async e => {
      e.preventDefault();
      if (loading) return;
      loading = true;
      const btn = $('btnKeyLoadAll');
      const old = btn.textContent;
      btn.textContent = '加载中…';
      btn.disabled = true;
      try {
        modelCache = null;      // 强制重新拉取
        await ensureModels(true);
        // 顺手把当前卡片里搜索框的过滤重置，让新增项可见。
        drafts.forEach(d => { d.query = ''; });
        render();
      } finally {
        loading = false;
        btn.textContent = old;
        btn.disabled = false;
      }
    };
  }

  return { load, collect, render };
})();
