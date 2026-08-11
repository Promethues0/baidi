# 白帝部署（systemd + nginx + SQLite）

appliance 式单机部署：`baidi-control`（Go 单二进制，监听 127.0.0.1:8090）+ console 静态产物，由 nginx 对外提供 HTTPS 并反代 `/api`。鉴权由白帝自身 JWT 负责（无 nginx basic-auth）：令牌由 control 的 Ed25519 私钥签发，
数据面只持公钥、在密码学上不具备签发能力；网关机器身份走 mTLS 客户端证书（内部 CA 签发，指纹白名单可即刻吊销）。参照烛龙部署机 `124.223.225.77`（systemd+nginx+sqlite）。

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
etc/baidi.env           control 专属 env（0600；仅 HS256 逃生舱备用密钥）
etc/keys/               ★control 身份私钥（0700）：jwt-ed25519.pem 签会话令牌、
                          jwt-ed25519-knock.pem 只签敲门令牌。首启自动生成，公钥写同名 .pub
etc/pki/                ★内部 CA（0700，标准 X.509/P-256）：签发网关 mTLS 客户端证书
etc/gwcerts/            网关身份材料（仅 WITH_GATEWAY=1）：gw.crt/key.pem + ca.crt.pem + knock.pub
etc/baidi-gateway.env   网关专属 env（0640）——只有验证材料，没有任何签发能力
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

## 控制面温备（warm standby，PRD 15.5）

**温备不是双活**：SQLite 是单写者，两个 control 同时写同一个库会在写冲突时**静默丢配置**。
备机只做一件事——周期性把主机的加密配置备份拉过来、校验、落盘，并回报"我这份是什么时候的"；
它**不开任何监听、不接管任何流量**。切换由人工触发，**没有自动选主**
（两节点没有仲裁第三方，自动选主必然脑裂 = 两个控制面同时签发令牌、下发相反的策略）。

**RPO = 同步间隔**（默认 10 分钟）：最后一次成功同步之后的配置改动，切换后不存在。

### 装一台备机

```bash
# ① 主机：配备份口令（两侧同一把）并重启 control
echo 'BAIDI_STANDBY_PASSPHRASE=<至少 12 位>' >> /opt/baidi/etc/baidi.env
systemctl restart baidi-control

# ② 主机：离线签一张 CN 以 standby- 开头的 mTLS 客户端证书（前缀是分权判据，写错一路 403）
/opt/baidi/bin/baidi-control -issue-gateway-cert standby-1 -out /opt/baidi/etc/standbycerts

# ③ 把 standbycerts/{gw.crt.pem,gw.key.pem,ca.crt.pem} 拷到备机，起同步进程
BAIDI_STANDBY_PASSPHRASE=<同一把> /opt/baidi/bin/baidi-standby \
  -primary https://<主机>:8092 \
  -cert standby.crt.pem -key standby.key.pem -ca ca.crt.pem \
  -dir /var/lib/baidi-standby -interval 10m
```

主机的管理台「系统管理 → 集群」会显示这台备机的同步新鲜度；`/diag` 的同名检查同源。
主机的 mTLS 口（`BAIDI_MTLS_ADDR`，默认 `127.0.0.1:8092`）默认只听回环，备机在别的机器上时
要么改成可达地址，要么走 SSH 隧道——**这条链上跑的是整套信任材料，不要图省事挂到公网**。

### 切换（提升备机为主机）

```bash
# 干跑：只校验备份完整性 + 打印将要覆盖的清单，不停服务、不碰任何文件
sudo BAIDI_STANDBY_PASSPHRASE=… /opt/baidi/bin/promote-standby.sh --dry-run
# 正式：停服务 → 快照现有材料 → 覆盖 → 起服务 → /healthz 自检
sudo BAIDI_STANDBY_PASSPHRASE=… /opt/baidi/bin/promote-standby.sh
```

脚本替不了的三件事，成功输出里也会再说一遍：

1. **确认老主机已停机**——两台同时跑就是脑裂；
2. 各网关的 `-control` 指向新主机（mTLS 证书随库一起恢复了，白名单仍然有效）；
3. 切换后跑一次 `/diag` 与「审计链校验」，后者能证明审计链密钥恢复正确。

## 生产化清单（上线前）

- [ ] `etc/tls` 换正式证书（替换自签）
- [ ] `etc/keys/` 与 `etc/pki/` 已生成且 0700；**私钥绝不下发给网关**（网关只拿 `knock.pub` 与自己的客户端证书）
- [ ] 网关证书可随时吊销：`POST /api/v1/pki/gateway-certs/{fingerprint}/revoke`（指纹白名单是执行点，下次握手即被拒）
- [ ] 备份 `etc/keys/` 与 `etc/pki/`：**丢了这两个目录，所有已分发公钥的网关会全部拒绝敲门**，且日志只显示「令牌无效」而非「密钥换了」
- [ ] 把管理员登录从演示口令换成真实校验（接 IdP / 本地用户表 + 强口令）
- [ ] `data/baidi.db` 纳入定期备份（WAL，可热备 `.backup`）
- [ ] 要冗余就装温备（上一节）；装了之后**定期看一眼系统页的同步新鲜度**——备机静默落后与没有备机，只在切换那天才区分得出来
- [ ] 安全组放行 443（仅 nginx 对外；8090 仅本机）
