#!/usr/bin/env bash
#
# update.sh —— workbuddy2api 一键更新脚本
#
# 用途：从 GitHub 拉取最新代码并重建容器，自动处理两个已知问题：
#   1) 长命令（git fetch / docker build）耗时>1分钟，SSH 会话可能被掐断
#      → 脚本把全过程写日志文件，可事后用 `./update.sh logs` 查看
#   2) 国内网络拉 proxy.golang.org / dl-cdn.alpinelinux.org 超时
#      → 已由 Dockerfile 内的 GOPROXY / 阿里云 apk 源解决
#
# 用法：
#   ./update.sh          拉取代码 + 重建 + 重启（交互确认）
#   ./update.sh -y       同上，跳过确认（适合无人值守）
#   ./update.sh logs     查看上次更新的完整日志
#   ./update.sh status   查看当前容器与版本状态
#   ./update.sh rollback 回退到上一个提交并重建
#
set -uo pipefail

# ---------- 配置 ----------
REPO_DIR="${REPO_DIR:-/opt/workbuddy2api}"
SERVICE="${SERVICE:-wb2api}"
BRANCH="${BRANCH:-main}"
LOG_FILE="${REPO_DIR}/.update.log"
REQUIRED_UID="${REQUIRED_UID:-10001}"   # config.json 需要的属主

# GitHub 加速前缀：国内直连 github.com 极不稳定（TLS 常被中断）。
# 直连失败时自动改用此代理重试；置空则禁用 fallback。
GH_PROXY="${GH_PROXY:-https://gh-proxy.com/}"

# ---------- 颜色 ----------
if [ -t 1 ]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[36m'; N=$'\033[0m'
else
  R=; G=; Y=; B=; N=
fi
info() { printf '%s[信息]%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '%s[成功]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[警告]%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%s[错误]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

# 所有关键命令的输出同时进终端和日志文件
# 用法: run "描述" 命令 参数...
run() {
  local desc="$1"; shift
  echo ">>> ${desc}: $*" >> "$LOG_FILE"
  "$@" 2>&1 | tee -a "$LOG_FILE"
  return "${PIPESTATUS[0]}"
}

cd "$REPO_DIR" 2>/dev/null || die "目录不存在: $REPO_DIR"

# 带代理回退的 git fetch：
#   1) 先用当前 remote（通常是直连 github.com）试一次
#   2) 失败且配置了 GH_PROXY → 临时改用 <GH_PROXY><原始github URL> 重试
#   3) 仍失败 → 报错并给出排查提示
# 不修改 remote 配置，代理仅在本次 fetch 生效。
git_fetch_with_fallback() {
  local gh_url proxy_url
  echo ">>> fetch origin/$BRANCH (直连)" >> "$LOG_FILE"
  if git fetch origin "$BRANCH" --depth=1 2>&1 | tee -a "$LOG_FILE"; then
    return 0
  fi
  # 直连失败：拿原始 GitHub URL（剥掉可能已有的代理前缀）
  gh_url="$(git remote get-url origin)"
  gh_url="${gh_url#https://gh-proxy.com/}"
  gh_url="${gh_url#https://ghproxy.net/}"
  gh_url="${gh_url#https://gh.llkk.cc/}"
  if [ -z "$GH_PROXY" ]; then
    return 1
  fi
  proxy_url="${GH_PROXY}${gh_url}"
  warn "直连 github.com 失败（国内网络常见），改用加速代理重试…"
  warn "  代理: $proxy_url"
  echo ">>> fetch (经代理 $GH_PROXY)" >> "$LOG_FILE"
  if git fetch "$proxy_url" "${BRANCH}:refs/remotes/origin/${BRANCH}" --depth=1 2>&1 | tee -a "$LOG_FILE"; then
    return 0
  fi
  return 1
}

# ---------- 子命令：logs ----------
if [ "${1:-}" = "logs" ]; then
  [ -f "$LOG_FILE" ] || die "还没有更新日志（先跑一次 ./update.sh）"
  less -R "$LOG_FILE"
  exit 0
fi

# ---------- 子命令：status ----------
if [ "${1:-}" = "status" ]; then
  echo "=== 代码版本 ==="
  git log --oneline -1 2>/dev/null || echo "  (无法获取)"
  echo "  分支: $(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
  echo "  远端: $(git remote get-url origin 2>/dev/null)"
  echo
  echo "=== 容器 ==="
  docker compose ps 2>/dev/null || echo "  (compose ps 失败)"
  echo
  echo "=== 健康 ==="
  CID="$(docker compose ps -q "$SERVICE" 2>/dev/null | head -1)"
  if [ -n "$CID" ]; then
    docker inspect --format '{{.State.Status}} / {{if .State.Health}}{{.State.Health.Status}}{{else}}无健康检查{{end}}' "$CID" 2>/dev/null
  else
    echo "  容器未运行"
  fi
  exit 0
fi

# ---------- 子命令：rollback ----------
ROLLBACK=0
if [ "${1:-}" = "rollback" ]; then
  ROLLBACK=1
  shift
fi

# ---------- 参数 ----------
ASSUME_YES=0
[ "${1:-}" = "-y" ] && ASSUME_YES=1

# ---------- 环境检查 ----------
command -v git    >/dev/null || die "未安装 git"
command -v docker >/dev/null || die "未安装 docker"
docker compose version >/dev/null 2>&1 || die "docker compose 不可用"
[ -f docker-compose.yml ] || die "找不到 docker-compose.yml"

OLD_REV="$(git rev-parse --short HEAD 2>/dev/null || echo '未知')"

# ---------- 确认 ----------
if [ "$ROLLBACK" -eq 1 ]; then
  warn "将回退到上一个提交 (HEAD~1) 并重建"
  git log --oneline -2 2>/dev/null
  if [ "$ASSUME_YES" -ne 1 ]; then
    printf '确认回退? [y/N] '; read -r a
    [ "$a" = y ] || { info "已取消"; exit 0; }
  fi
  TARGET="HEAD~1"
else
  info "当前版本: ${OLD_REV}"
  if [ "$ASSUME_YES" -ne 1 ]; then
    printf '将从 origin/%s 拉取最新代码并重建容器，继续? [y/N] ' "$BRANCH"
    read -r a
    [ "$a" = y ] || { info "已取消"; exit 0; }
  fi
  TARGET="origin/${BRANCH}"
fi

# ---------- 日志头 ----------
{
  echo "=================================================="
  echo "更新开始: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "更新前版本: ${OLD_REV}   目标: ${TARGET}"
  echo "=================================================="
} | tee "$LOG_FILE"

# ---------- 1. 代码 ----------
if [ "$ROLLBACK" -eq 1 ]; then
  info "步骤 1/4: 回退代码"
  run "回退到 HEAD~1" git reset --hard HEAD~1 || die "回退失败"
else
  info "步骤 1/4: 拉取代码"
  git_fetch_with_fallback \
    || die "git fetch 失败：直连与代理（${GH_PROXY:-已禁用}）均不可用，请检查网络"
  run "reset --hard origin/$BRANCH" git reset --hard "origin/${BRANCH}" \
    || die "reset 失败"
fi
NEW_REV="$(git rev-parse --short HEAD)"
ok "代码就绪: ${OLD_REV} -> ${NEW_REV}"

# ---------- 2. 数据保护 ----------
info "步骤 2/4: 检查运行时数据"
[ -f config.json ] || warn "config.json 不存在（新部署? 否则请从备份恢复）"
if [ -f config.json ]; then
  owner="$(stat -c %u config.json 2>/dev/null || echo '')"
  if [ "$owner" != "$REQUIRED_UID" ]; then
    warn "config.json 属主为 ${owner:-空}，应为 $REQUIRED_UID，正在修正..."
    chown "${REQUIRED_UID}:${REQUIRED_UID}" config.json 2>/dev/null \
      || warn "chown 失败（可能需要 sudo）"
  else
    echo "config.json 属主正确 ($owner)" | tee -a "$LOG_FILE"
  fi
fi
echo "auths: $(ls auths 2>/dev/null | wc -l) 个 | data: $(ls data 2>/dev/null | wc -l) 个" | tee -a "$LOG_FILE"
ok "运行时数据检查完成"

# ---------- 3. 构建 ----------
info "步骤 3/4: 构建镜像（首次或依赖变更可能较慢，请耐心等待）"
if ! run "docker compose build $SERVICE" docker compose build "$SERVICE"; then
  die "构建失败。代码已更新到 ${NEW_REV}，但镜像未重建（旧容器仍在运行）。
     排查：查看日志 $LOG_FILE
     回退：./update.sh rollback"
fi
ok "镜像构建完成"

# ---------- 4. 重启 ----------
info "步骤 4/4: 重启容器"
run "docker compose up -d $SERVICE" docker compose up -d "$SERVICE" || die "重启失败"
ok "容器已重启"

# ---------- 健康检查 ----------
info "等待服务就绪..."
HEALTHY=0
CID="$(docker compose ps -q "$SERVICE" | head -1)"
for _ in $(seq 1 30); do
  st="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CID" 2>/dev/null || echo unknown)"
  case "$st" in
    healthy|running) HEALTHY=1; break ;;
  esac
  sleep 2
done

echo | tee -a "$LOG_FILE"
echo "==================================================" | tee -a "$LOG_FILE"
if [ "$HEALTHY" -eq 1 ]; then
  ok "更新成功！版本 ${OLD_REV} -> ${NEW_REV}，状态: $st"
  echo "  完整日志: $LOG_FILE" | tee -a "$LOG_FILE"
else
  warn "容器已启动但健康检查未通过（状态: $st）"
  echo "  查看日志: docker compose logs --tail 50 $SERVICE" | tee -a "$LOG_FILE"
  echo "  回退命令: ./update.sh rollback" | tee -a "$LOG_FILE"
fi
echo "==================================================" | tee -a "$LOG_FILE"
