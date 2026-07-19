# 白帝部署（systemd + nginx + SQLite）

appliance 式单机部署：`baidi-control`（Go 单二进制，监听 127.0.0.1:8090）+ console 静态产物，由 nginx 对外提供 HTTPS 并反代 `/api`。鉴权由白帝自身 JWT 负责（无 nginx basic-auth）。参照烛龙部署机 `124.223.225.77`（systemd+nginx+sqlite）。

## 架构

```
浏览器 ──HTTPS──> nginx(:443) ──┬─ /            → @PREFIX@/web（SPA：管理台 + /portal/*）
                                ├─ /api/        → 127.0.0.1:8090（baidi-control）
                                │                      └─ SQLite @PREFIX@/data/baidi.db
                                └─ /downloads/  → control 白名单分发客户端安装包（产物先跑 clients/build-artifacts.sh 汇集）
```

## 产物布局（_out/ 与服务器 @PREFIX@）

```
bin/baidi-control       linux/amd64 单二进制（CGO_ENABLED=0，纯 Go SQLite）
web/                    console 构建产物（vite dist）
data/baidi.db           SQLite（首启自动建表+播种，WAL）
etc/baidi.env           BAIDI_JWT_SECRET（install 时随机生成，0600）
etc/tls/server.{crt,key} TLS（首装自签，生产换正式证书）
downloads/              客户端安装包 + manifest.json（先跑 clients/build-artifacts.sh 汇集到 deploy/artifacts/downloads，build.sh 携带进 _out）
```

## 一键部署

```bash
cd deploy
cp config.env.example config.env      # 填 SERVER_SSH / 前缀 / 端口
./deploy.sh                           # 本地构建 → rsync → 远程 install-remote.sh
```

或分步：`./build.sh` 出 `_out/`，再把 `_out/` 拷到服务器执行 `sudo ./install-remote.sh`。

## 运维

```bash
systemctl status baidi-control        # 服务状态
journalctl -u baidi-control -f        # 日志
systemctl restart baidi-control       # 重启（SQLite 数据保留）
```

入口：控制台 `https://<server>/`（首次跳 `/login`，演示 `admin / baidi@123`）；终端用户门户 `https://<server>/portal/login`。

## 生产化清单（上线前）

- [ ] `etc/tls` 换正式证书（替换自签）
- [ ] `etc/baidi.env` 的 `BAIDI_JWT_SECRET` 已随机生成；如需轮换，改后 `restart`
- [ ] 把管理员登录从演示口令换成真实校验（接 IdP / 本地用户表 + 强口令）
- [ ] `data/baidi.db` 纳入定期备份（WAL，可热备 `.backup`）
- [ ] 安全组放行 443（仅 nginx 对外；8090 仅本机）
