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

## 环境要求（install-remote.sh 装机前自检，FR-DEPLOY-01）

`install-remote.sh` 在**任何写操作之前**（useradd / mkdir / install 全在它后面）核对一遍目标机的
环境基线，输出「达标 / 不达标」结论。中止时这台机器一个字节都没被改过，扩容后原样重跑即可。

阈值分两档，刻意不是一刀切：**硬下限**低于即中止，只收「连一次部署都做不完 / 起来必被 OOM 杀」
的量；**推荐值**低于只警告。**只有内存与磁盘两项会中止**，其余三项永不中止——理由逐条写在下表，
共同的一条是：这段代码跑在远端生产机上，一次假阳性 = 一次本可成功的部署被自己的脚本挡在门外，
而运维此刻手里没有第二条路。「判不了 ≠ 不达标」同样适用（与 posture 采集三态、
`gateway_metrics` 不补 0 是同一条纪律）：读不出 `/proc/meminfo`、机器上一个 DNS 工具都没有、
没有 `timedatectl` —— 一律记为警告，绝不当成不达标。

| 检查项 | 取数方式 | 硬下限（中止） | 推荐值（警告） | 不达标的后果 |
|---|---|---|---|---|
| CPU 核数 | `nproc`，回退 `getconf _NPROCESSORS_ONLN` | 无（永不中止） | ≥ 2 | 只是慢：TLS/TLCP 握手、SM2 签验、用户态 ESP 加解密都在 CPU 上，单核时与 control 抢同一个核 |
| 内存总量 | `/proc/meminfo` 的 `MemTotal` | **400 MiB** | ≥ 1900 MiB | 低于硬下限时装得上但跑不住：OOM killer 挑 RSS 最大的（通常正是 `baidi-control`），表现为「部署显示成功、服务过几分钟自己没了」，journal 里只有一行 Killed |
| 可用磁盘 | `df -Pk` 查 **`BD_PREFIX` 所在分区** | **600 MiB** | ≥ 4096 MiB | 失败点在 `cp -R` 中途，留下半棵 `web/` 目录树而不是一次干净的失败 |
| DNS 解析 | `getent hosts` 优先，回退 `host` / `dig` / `nslookup` | 无（永不中止） | 能解析 `BD_DNS_PROBE_HOST` | 装机期：本机没有 nginx 时 `apt-get`/`yum` 取包失败；运行期：认证源（LDAP/OIDC）、消息通道（SMTP/webhook）、审计外送（syslog/HTTP）里凡按域名填的目标都连不上，页面上表现为「保存成功、就是不发/不通」 |
| 时间同步 | `timedatectl show -p NTPSynchronized`，回退 `systemctl is-active chrony/chronyd/systemd-timesyncd/ntp/ntpsec/openntpd` | 无（永不中止） | 有一项在跑 | 见下方「为什么时钟这项写得这么长」 |

### 阈值是怎么定的

不是抄 PRD 的数字，是从这个仓库的实测产物与真实常量推出来的：

- **磁盘 600 MiB 硬下限** = 实测峰值 334 MiB 的约 1.8 倍。峰值这么算：`deploy/_out` 实测
  127 MiB（`bin/` 45 = control 15.2 + gateway 10.7 + ipsec 10.5 + standby 6.4 + gmca 4.8，
  `web/` 2.3，`downloads/` 80 = dmg 21 + apk 62），落到 `BD_PREFIX` 一份 127，
  `deploy.sh` 先 rsync 到 `/tmp/baidi-deploy` 的暂存副本再一份 127，客户端包**原子切换**
  （先落 `downloads.new` 再瞬时 `mv`）期间第二份 80 —— 合计 334。
- **磁盘 4096 MiB 推荐值**留的是长期量：审计默认存 180 天（`BAIDI_AUDIT_RETENTION_DAYS`）、
  告警 90 天、攻击源 30 天、设备指标 72 小时（每网关每 15s 一行，是全系统唯一的高频写入口），
  外加 journald 与 `POST /api/v1/upgrade/backup` 产出的配置备份归档。
- **内存 400 MiB 硬下限 / 1900 MiB 推荐值**：这两个数是**按常驻进程数与 Go 运行时量级估的，
  不是实测 RSS**（本仓库没有做过 RSS 基准，别把它当测量值引用）。常驻的是
  `baidi-control` + `nginx`，`WITH_GATEWAY=1` 再加 `baidi-gateway`、`WITH_IPSEC=1` 再加
  `baidi-ipsec`；control 用的是纯 Go SQLite（modernc），页缓存与 GC 都吃内存。
  两个数都刻意**避开整数边界**：`MemTotal` 报的是内核可用内存，固件与内核预留会吃掉一截，
  标称 2 GiB 的云主机通常只报 1.9 GiB 出头（具体值随机型浮动），推荐值写 2048 会让
  **每一台** 2G 机器都无谓报警；同理标称 512 MiB 的机器报不到 500，硬下限写 512
  会把一台能跑的机器直接拦死 —— 400 这道闸收的是 256 / 384 MiB 那一档。
- **CPU 推荐 2 核、且永不中止**：1C 云主机是演示/测试环境最常见的形态，核少只会慢，
  不会装不上也不会起不来。为它中止是纯粹的误杀。

### 为什么时钟这项写得这么长

控制面按**自己的钟**签敲门令牌，网关按**它自己的钟**校验有效期。两边漂过 **90 秒**
（`knockTTL`，`control/internal/api/api.go:36`）之后，合法客户端的每一次敲门都会以
「令牌过期」被拒，而现场看不出是时钟问题：SPA 是单包无回应，客户端**看不到任何错误**；
控制面的签发日志一切正常；网关那边只累积「验签失败」。三处都不指向时钟。
管理台 `/diag` 的「控制面与网关时钟一致性」（`|偏差| ≥ 90s` 判 fail、`> 10s` 判 warn）
就是为这个失败形态加的，装完记得去看一眼。装机时补一个守护进程即可：

```bash
apt-get install -y chrony            # 或
systemctl enable --now systemd-timesyncd
```

### 覆盖与调阈值

```bash
# 强行装（跳过硬下限中止，警告照样打印）
sudo BD_FORCE=1 BD_PREFIX=/opt/baidi … bash install-remote.sh
# 单项放宽 / 收紧
sudo BD_MIN_MEM_MB=256 BD_MIN_DISK_MB=300 … bash install-remote.sh
# 内网没有公网 DNS，换成能解析的内部域名再判
sudo BD_DNS_PROBE_HOST=idp.corp.example … bash install-remote.sh
```

| 变量 | 默认 | 说明 |
|---|---|---|
| `BD_FORCE` | `0` | `=1` 跳过硬下限中止；`FORCE=1` 是兼容别名 |
| `BD_MIN_CPU` | `2` | CPU 推荐核数（调高也只是抬高警告门槛，仍不中止） |
| `BD_MIN_MEM_MB` / `BD_REC_MEM_MB` | `400` / `1900` | 内存硬下限 / 推荐值（MiB） |
| `BD_MIN_DISK_MB` / `BD_REC_DISK_MB` | `600` / `4096` | 可用磁盘硬下限 / 推荐值（MiB） |
| `BD_DNS_PROBE_HOST` | `archive.ubuntu.com` | DNS 自检探的域名 |

> ★**这几个变量必须给在远端那条命令上**。`deploy.sh` 只显式转发固定几个变量
> （`BD_PREFIX`/`BD_USER`/`CONTROL_PORT`/`WITH_GATEWAY`/`WITH_IPSEC`/…），**不含**上表任何一项——
> 写进 `config.env` 到不了远端，且不会有任何提示。要走 `deploy.sh` 又要覆盖，
> 得先给 `deploy.sh` 的 ssh 命令行补上转发。

### 这道自检**没有**覆盖的

- **`/tmp` 所在分区**：`deploy.sh` 的暂存副本落在 `/tmp/baidi-deploy`，而检查只看
  `BD_PREFIX` 所在分区。`/tmp` 单独挂一块小盘或挂成 tmpfs（吃的是内存）时不在判定范围内。
- **认证源 / IdP / SMTP 的可达性**：部署时点这些还没配，判不了，刻意不做。
- **时钟准不准**：判据只是「有没有同步守护进程在跑」。真实偏差要等网关连上来之后，
  由 `/diag` 的时钟一致性检查回答。

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
