# 白帝部署（systemd + nginx + SQLite）

appliance 式单机部署：`baidi-control`（Go 单二进制，监听 127.0.0.1:8090）+ console 静态产物，由 nginx 对外提供 HTTPS 并反代 `/api`。鉴权由白帝自身 JWT 负责（无 nginx basic-auth）：令牌由 control 的 Ed25519 私钥签发，
数据面只持公钥、在密码学上不具备签发能力；网关机器身份走 mTLS 客户端证书（内部 CA 签发，指纹白名单可即刻吊销）。参照烛龙部署机 `124.223.225.77`（systemd+nginx+sqlite）。

## 架构

```
浏览器 ──HTTPS──> nginx(:443) ──┬─ /            → @PREFIX@/web（SPA：管理台 + /portal/*）
                                ├─ /healthz     → 127.0.0.1:8090（存活探测，精确匹配、免认证）
                                ├─ /api/        → 127.0.0.1:8090（baidi-control）
                                │                      └─ SQLite @PREFIX@/data/baidi.db
                                └─ /downloads/  → control 白名单分发客户端安装包（产物先跑 clients/build-artifacts.sh 汇集）
```

★`/healthz` 这条必须是**精确匹配**（`location = /healthz`），而且必须真的 `proxy_pass` 到 control。
少了它，`/healthz` 会落进第一条的 SPA history 回退恒回 200 HTML，于是「控制面整个停掉」与
「控制面健康」在 HTTP 层面完全同形——客户端那格「控制中心可达」就成了永真指示灯。
控制面不在时这条通路回 502（本站刻意不设 `error_page`，给它加 5xx 兜底会把这条改回恒 200）。
`build.sh` 有构建期自检守着这两点，删掉任何一半都当场红。

## 产物布局（_out/ 与服务器 @PREFIX@）

```
bin/baidi-control       linux/amd64 单二进制（CGO_ENABLED=0，纯 Go SQLite）
web/                    console 构建产物（vite dist）
data/baidi.db           SQLite（首启自动建表+播种，WAL）
etc/baidi.env           control 专属 env（0600；仅 HS256 逃生舱备用密钥）
etc/keys/               ★control 身份私钥（0700）：jwt-ed25519.pem 签会话令牌、
                          jwt-ed25519-knock.pem 只签敲门令牌、jwt-ed25519-web.pem 只签七层 Web 代理票据。
                          首启自动生成，公钥写同名 .pub（网关 SPA 口只装 knock 公钥、L7 口只装 web 公钥）
etc/pki/                ★内部 CA（0700，标准 X.509/P-256）：签发网关 mTLS 客户端证书
etc/gwcerts/            网关身份材料（仅 WITH_GATEWAY=1）：gw.crt/key.pem + ca.crt.pem + knock.pub + web.pub
                          （两把公钥分口装：SPA 敲门口只装 knock.pub、L7 七层 Web 口只装 web.pub——
                           拿错票据在对面连签名都验不过，见 install-remote.sh 的 BAIDI_GW_JWT_PUBKEY / BAIDI_GW_WEB_JWT_PUBKEY）
etc/baidi-gateway.env   网关专属 env（0640）——只有验证材料，没有任何签发能力
etc/tls/server.{crt,key} TLS（首装自签，生产换正式证书；**自签这一对从不删**——它是 ACME 续不上时的回退目标）
etc/tls/le.{crt,key,csr}  Let's Encrypt IP 地址证书（仅 WITH_ACME_IP_CERT=1）；etc/acme/ 是 lego 的账户与状态目录
                          （开关、四条硬约束与续期/回退语义见下方「HTTPS 证书」一节）
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

## HTTPS 证书

**默认是自签**（`install-remote.sh` 首装时签一张 CN=baidi、SAN 含 `PUBLIC_HOST` 的证书，
`[ ! -f ]` 守卫，重复部署不覆盖）。自签**不是「能凑合用」**：每一个第一次接入的客户端都会撞墙，
且三端的报错长得完全不一样（桌面端登录在 TLS 握手阶段就断、移动端 WebView 拒绝加载、
Go 数据面报 `x509: certificate signed by unknown authority` 而隧道进程本身起着）。
有域名、且域名能正常解析到这台机器时，最省事的路仍然是**换一张常规的受信证书**
（本脚本不代办，换完把 `etc/tls/server.{crt,key}` 替掉即可）。

### 大陆云主机 + 没有备案域名：只剩 LE 的 IP 地址证书这一条路

2026-09-08 在演示站 `101.43.125.131`（腾讯云大陆机）实测出来的结论，逐条都是踩出来的：

- **未备案域名指向大陆机器会被 DNSPod 在 HTTP 层拦掉**——`sslip.io` / `nip.io` 这类
  wildcard DNS 同样算。ACME 的 HTTP-01 挑战取回的是一张 webblock 页而不是挑战文件，
  于是**域名路线根本签不下来**。错的不是 ACME 配置、也不是 nginx，别在那两处反复调。
- **Let's Encrypt 的 IP 地址证书可行**：挑战时 Host 头就是 IP，不触发备案拦截。
  实测拿到 `The server validated our request` 并正式签发。

开启方式（`config.env`）：

```bash
WITH_ACME_IP_CERT=1
ACME_EMAIL=you@example.com      # LE 账户邮箱，首次注册必填（仅用于到期提醒）
# ACME_SERVER=…                 # 默认 LE 正式环境；调试期可指向 staging
```

四个前置条件，任一不满足**只警告不中止**——站点保持自签、照常可用，原因原样打进结尾摘要：

| 前置 | 不满足时 |
|---|---|
| `PUBLIC_HOST` 是**裸 IPv4** | 拒。有域名就别用这个开关：域名走常规 HTTP-01/DNS-01 更好（90 天有效期，不必两天一续） |
| `BD_HTTPS_PORT=443`（独占整机） | 拒。HTTP-01 挑战必须由本机 **80 端口**应答，而共存机的 80 归烛龙的 `default_server`，白帝的共存契约是绝不去争它 |
| `ACME_EMAIL` 非空 | 拒。LE 账户注册必须给邮箱，它也是到期提醒的唯一去处 |
| 部署包里有 `bin/lego` | 拒。取不到 `github.com/go-acme/lego` 模块时 `build.sh` **只跳过 lego、不让整个构建失败**（一个可选组件不该拖垮全部交付），此时自己交叉编译一个 linux/amd64 的放进 `deploy/_out/bin/lego` 再部署 |

`PUBLIC_HOST` 同时是证书 SAN、nginx 的 `server_name`、以及续期脚本找 lego 产物用的文件名
（lego 按 CSR 里的第一个标识命名产物），三处必须是同一个值。

### 四条硬约束（每条都对应一个具体的失败）

| 约束 | 违反时的现场 |
|---|---|
| IP 证书**只能**走 `shortlived` profile，有效期 **6 天 15 小时** | 用默认 profile 直接被 LE 拒签 |
| CSR 里 IP **不能出现在 Common Name**，只能进 SAN | LE 回 `badCSR :: CSR contains IP address in Common Name`。故须 `openssl req -subj "/" -addext "subjectAltName=IP:<ip>"` 自造 CSR，再 `lego --csr` 拿去签 |
| **certbot 2.9（Ubuntu 自带那版）不支持 `--preferred-profile`** | 选不到 `shortlived`，这条路走不通。改用 **lego**（单二进制、纯 Go、无依赖，`build.sh` 交叉编译后随部署包带上；版本钉死在 `LEGO_VERSION=v4.35.2`——ACME profile 是 2025 年才进 lego 的，v4.21 以前的版本根本没有 `--profile`）。★别打算在目标机上现装：演示站访问 `codeload.github.com` 超时，那次是在开发机上交叉编译好再上传的 |
| lego 的 **`--csr` 是全局参数**（写在 `lego` 之后、`run`/`renew` 之前），**`--profile` 是 `run`/`renew` 子命令的参数** | 放错报 `flag provided but not defined` —— 与「证书签不下来」看起来是两回事，最容易把人带偏 |

还有一条在 nginx 侧：**80 端口的 server 块不能写 server 级 `return 301`**。它在 rewrite 阶段执行、
**早于 location 选择**，会把 ACME 挑战一起重定向掉。正确写法是把 return 挪进 `location /`，
并另加一条 `location ^~ /.well-known/acme-challenge/ { root /var/www/html; }`
（已落在 `deploy/nginx/baidi.conf` 里）。

### 机上落点

| 路径 | 是什么 |
|---|---|
| `$BD_PREFIX/bin/lego` | ACME 客户端（单二进制） |
| `$BD_PREFIX/etc/tls/le.crt` · `le.key` · `le.csr` | LE 证书 / 私钥 / 自造的 CSR（CN 空、IP 在 SAN） |
| `$BD_PREFIX/etc/tls/server.crt` · `server.key` | **自签那一对，原样保留、从不删** —— 它是回退目标 |
| `$BD_PREFIX/etc/acme/` | lego 的账户与状态目录 |
| `$BD_PREFIX/bin/acme-renew.sh` | 续期脚本（模板 `deploy/acme-renew.sh`，占位由 `install-remote.sh` 渲染） |
| `baidi-acme-renew.timer` / `.service` | 每日两次拉起续期（`OnCalendar=*-*-* 03,15:17:00` + 随机延迟 30min + `Persistent=true`） |

### 续期与回退（fail-safe 的语义与代价）

`acme-renew.sh` 每次跑做三件事，判据只有一个——**nginx 配置文件里真正写着哪条 `ssl_certificate`
路径**（不记任何额外状态；多一份状态就多一次两边不一致的机会，而不一致时的症状正是本功能要消灭的
那一种：证书天天续着、nginx 却在用自签，处处正常）：

1. 剩余 **> 96h** → 不续，但仍然确认一次 nginx 真的指着 LE 证书（少了这一句，一次重新部署把配置
   指回自签之后就再没人发现）；
2. 剩余 **≤ 96h** → 调 lego 续；成功就装文件 + 指向 LE + `nginx -t` 通过才 reload；
3. 续不上 **且** 剩余 **< 24h** → **切回自签**（`fallback_to_self_signed`，真改配置真 reload）。
   理由：**过期证书比自签更糟**——自签浏览器还给一个「继续访问」的出口，过期在多数客户端上同样拦、
   而且更容易被读成「站点整个挂了」。最坏结果因此是退回到没启用 ACME 之前的状态，而不是 TLS 直接不可用。

`nginx -t` 不过就把改动退回去，绝不留一个会让 nginx 起不来的配置（这台机可能与烛龙共存，
半残配置会毒化对方的下一次 reload）。续期失败时 `.service` 单元**就该是 failed**——刻意不加
`Restart`、不吞退出码，因为 `systemctl --failed` / `systemctl status baidi-acme-renew`
是这件事在机器上**唯一**的可见面（控制台不呈现证书状态）。

**代价必须写在明处**：

- **6 天 15 小时的有效期意味着「机器长期关机、开回来必然已过期」**。`Persistent=true` 会在开机后补跑
  一次，但那时多半已经过期、且已经切回自签 —— 站点能开，只是又回到浏览器警告 + 客户端要导信任锚。
- 定时器被停掉、或 80 端口被安全组/上游挡住，同样是六天后过期。**这两件事在控制台上看不出来**，
  只能上机看单元状态。
- **它不替代客户端侧的信任材料**。受信只在这一台机器上成立：换任何一台自签部署，桌面端仍要把证书
  导进本机信任库（`baidi-tun` 那半边可以用 `-control-ca`，登录那半边没有入口）、安卓仍要
  `-PbaidiControlCa`。详见 docs/ARCHITECTURE.md 第七节「控制中心信任锚」的逐端表。

**`install-remote.sh` 判「这次到底成没成」用的是同一条判据**（它的结论与 `acme-renew.sh` 的
`current_crt()` 逐字同款）——不看 `le.crt` 在不在、也不看 lego 的退出码，因为那两样都可能为真
而站点仍在用自签。装机顺序也是有意的：**先装续期脚本与定时器，后签发**——首签失败之后**更需要**
那个每日两次的重试，反过来「签成功才装定时器」会让首签失败变成一个再也不会自愈、
且机器上没有任何东西记得要重试的状态。

把开关关掉、但机器上还留着上一轮的 LE 证书时，`install-remote.sh` 会当面告警（本次部署已把站点
指回自签，而定时器还在续）。彻底关闭：

```bash
systemctl disable --now baidi-acme-renew.timer
rm -f $BD_PREFIX/etc/tls/le.crt $BD_PREFIX/etc/tls/le.key $BD_PREFIX/etc/tls/le.csr
```

排查一句话：`curl -sS -o /dev/null -w '%{http_code}\n' https://<PUBLIC_HOST>/`（**不带 `-k`**）
回 200 才算此刻受信。

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

- [ ] `etc/tls` 换正式证书（替换自签）——**自签不是"能凑合用"，是每个客户端第一次接入必然失败**：
      桌面端登录在 TLS 握手阶段就断（拿不到 HTTP 状态码，界面显示成"网络错误"）、移动端 WebView 拒绝加载、
      数据面报 `x509: certificate signed by unknown authority` 而隧道进程本身是起着的。
      **裸 IP 部署也能拿到公共 CA 证书**（此前这里写的是「拿不到」，已被 2026-09-08 的实测推翻）：
      Let's Encrypt 签 IP 地址证书，代价是只能走 `shortlived` profile、有效期 6 天 15 小时、
      必须有定时器续着——开关与全部约束见上方「HTTPS 证书」一节。
      走不了那条路（没有公网 80、或不接受 6 天有效期）时才退到第二条：把 `etc/tls/server.crt`
      当信任锚分发给客户端，代价是它带 `CA:TRUE`（导入系统信任库 = 信任它今后签发的任意证书）。指纹核对：
      `openssl x509 -in <crt> -outform der | openssl dgst -sha256`。
      ★这个指纹与**隧道钉扎**无关：那是网关自签的另一张证书，指纹由网关上报、经接入剖面自动下发，不需人工填。
      `install-remote.sh` 每次部署都会当面把这段告警打出来（含 SAN 与本次 `PUBLIC_HOST` 是否一致）。
- [ ] `etc/keys/` 与 `etc/pki/` 已生成且 0700；**私钥绝不下发给网关**（网关只拿 `knock.pub` / `web.pub` 两把公钥与自己的客户端证书）
- [ ] 网关证书可随时吊销：`POST /api/v1/pki/gateway-certs/{fingerprint}/revoke`（指纹白名单是执行点，下次握手即被拒）
- [ ] 备份 `etc/keys/` 与 `etc/pki/`：**丢了这两个目录，所有已分发公钥的网关会全部拒绝敲门**，且日志只显示「令牌无效」而非「密钥换了」
- [ ] 首登强制改密**已默认强制**（`BAIDI_SEED_MUST_CHANGE` 缺省 1，`deploy.sh` 与 `install-remote.sh` 两处一致）；演示机在 `config.env` 里显式关掉的，注意它**只在首次建库时生效**：演示机若已建库，开回该值无效，需重建库（删 `data/baidi.db` 重灌种子）或手工给种子账号置首登改密——种子口令 `baidi@123` 是公开的
- [ ] `data/baidi.db` 纳入定期备份（WAL，可热备 `.backup`）
- [ ] 要冗余就装温备（上一节）；装了之后**定期看一眼系统页的同步新鲜度**——备机静默落后与没有备机，只在切换那天才区分得出来
- [ ] 安全组放行 443（仅 nginx 对外；8090 仅本机）
