#!/usr/bin/env bash
# 在目标机上铲除原有业务，为白帝独占部署腾地（root 运行）。
# 保守策略：先盘点 → 备份 nginx 配置 → 停并禁用业务服务 + 停删 docker 容器 → 释放 80/443。
# 不盲目 rm 数据目录（/var/www、/opt/* 等只停服务并提示，需人工确认后再删）。
set -uo pipefail
ts="$(date +%Y%m%d-%H%M%S)"
BK="/root/pre-baidi-backup-$ts"

echo "==================== 铲除前盘点 ===================="
echo "--- 对外监听端口 ---"; ss -lntup 2>/dev/null | grep -vE '127.0.0.1|::1|:22 ' | head -30
echo "--- 运行中业务服务 ---"; systemctl list-units --type=service --state=running 2>/dev/null \
  | grep -ivE 'systemd|dbus|cron|ssh|networkd|resolved|polkit|rsyslog|getty|accounts|udisks|snapd|unattended|multipath|chrony|cloud-init|irqbalance|packagekit' | head -25
echo "--- docker 容器 ---"; docker ps 2>/dev/null | head || echo "(无 docker)"
echo "--- web 根 / 应用目录 ---"; ls -d /var/www/* /opt/* 2>/dev/null | head -20

echo "==================== 备份 + 停服务 ===================="
mkdir -p "$BK"
[ -d /etc/nginx ] && cp -a /etc/nginx "$BK/nginx"
echo "==> nginx 配置已备份到 $BK/nginx"

# 停 + 禁用 nginx（白帝 install 会重配并接管 443）
systemctl stop nginx 2>/dev/null || true
# 停删所有 docker 容器（镜像/卷保留）
if command -v docker >/dev/null 2>&1; then
  docker ps -q 2>/dev/null | xargs -r docker stop 2>/dev/null || true
  docker ps -aq 2>/dev/null | xargs -r docker rm 2>/dev/null || true
fi
# 清空 nginx 站点（已备份），由白帝 install 重建
rm -f /etc/nginx/sites-enabled/* /etc/nginx/conf.d/* 2>/dev/null || true

# 停 + 禁用 旧业务 systemd 单元（保留系统/ssh）；名单可按盘点结果增删
for svc in $(systemctl list-units --type=service --state=running --plain --no-legend 2>/dev/null \
    | awk '{print $1}' | grep -ivE 'systemd|dbus|cron|ssh|networkd|resolved|polkit|rsyslog|getty|accounts|udisks|snapd|unattended|multipath|chrony|cloud-init|irqbalance|packagekit|nginx|docker|baidi'); do
  echo "==> 停并禁用 $svc"; systemctl stop "$svc" 2>/dev/null || true; systemctl disable "$svc" 2>/dev/null || true
done

# 释放 80/443：停服务后若仍被占用，杀掉占用进程（flk 等可能是裸进程/非 systemd）
for p in 80 443; do
  pids="$(ss -lntpH "sport = :$p" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | tr '\n' ' ')"
  if [ -n "${pids// /}" ]; then
    echo "==> 端口 $p 仍被占用，结束进程：$pids"
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true; sleep 1; kill -9 $pids 2>/dev/null || true
  fi
done

echo "==================== 完成 ===================="
echo "✓ 原业务已停 + nginx 站点已清空（备份在 $BK）；80/443 已释放，白帝可独占部署。"
echo "  数据/应用目录(如 /var/www、/opt/* 非 baidi)未删除——如需彻底铲除，确认后人工 rm。"
