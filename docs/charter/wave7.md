# 白帝 · 第七波行动清单（PRD 缺口重扫产物）

> 产出方式：2026-08-13 用 33-agent 工作流对照 PRD 重扫 22 章（8 组并行扫章 →
> 24 条候选缺口逐条对抗证伪（0 条被推翻）→ 同根合并收敛）。上一份全量审计（08-10）
> 因其后七波实现已系统性失真，修正意见见文末。
> 判据：SCOPE.md 已豁免的不算缺口；每条都有 PRD 条目号与代码证据。

# 白帝 · 第七波行动清单（基于 24 条证伪存活缺口）

## 〇、同根合并说明

24 条存活缺口合并为 15 条行动 + 6 条边界建议。合并关系：

- **A 组「网关安全事件上报管道」**：FR-MON-05（SPA 攻击源统计，ch5）+ FR-AUDIT-02（数据面拒绝不进中心审计，ch16）——同一条缺失管道（网关拒绝事件既不计数也不上报），一次实现两章闭环。
- **B 组「审计在线检索」**：NFR-OBS-02/PERF-06（ch20）+ FR-AUDIT-01/03/05（ch16）——同一件事被两波各报一次，`store.Audit` 的 LIMIT 200 是唯一根因。
- **C 组「外部身份属性消费」**：FR-USER-17/18/22（ch6）+ FR-AUTH-08 的组/邮箱半边（ch7）——同根于 `BindExternalUser` 零消费 `ext.Groups/ext.Email`。
- **D 组「外部账号生命周期」**：FR-AUTH-04/08 状态回验（ch7）+ FR-USER-07/20 目录同步整簇（ch6）——同根于「外部身份权威变更传导不进白帝」，分两步走（本波做回验，全量同步记档延后）。
- **E 组「终端排障闭环」**：NFR-OPS-02 本地假诊断（ch20）为本波行动；FR-EP-17/18/19 远程收集（ch9）列边界候补。
- **F 组「批量导入导出」**：FR-USER-15（用户，ch6）+ FR-EP-03/04（终端，ch9）——同族同形，一并做。

---

## 一、行动清单（主线价值 > 静默失效风险 > effort）

### 第一梯队：身份与持续验证（零信任主线核心）

**1. OIDC 登录入口接线（FR-AUTH-02/05）— M ✅ 已落地**
- 做什么：新增 `/api/v1/auth/oidc/{id}/authorize` + `/callback` 两端点（state/nonce 服务端会话、复用已有 `AuthURL/Exchange/PKCE`），回调成功后并入既有 `BindExternalUser → secondFactor → 签令牌` 同一链路；门户/管理台登录页按 `auth_sources` 真实行渲染 OIDC 入口按钮。
- 改哪里：`control/internal/api`（新 handler，消费 `authsrc.RedirectAuthenticator`）、`console/src/views/PortalLogin.vue` / `Login.vue`。
- 为什么值得：协议客户端 30 用例全绿、探测通过、配置页齐全，却没有任何用户能经它登录——本项目最忌的 config-only 静默失效的教科书案例；且 D 组的登出/回验洞要先「有人能登」才有意义。
- 注意：回调路径同样要过 `secondFactor`（passkey 强制断言排在策略前的既有纪律不许被新入口绕过）。

**2. 外部身份组/属性消费（C 组）— M ✅ 已落地**
- 做什么：`BindExternalUser` 消费 `ext.Groups`——upsert 为外部来源用户组（建议加 `kind=external`，只读、按登录刷新）并接进既有 `SubjectIndex`；落 `ext.Email`；**去掉「已绑定即提前返回」**，改为每次登录刷新组与属性。
- 改哪里：`control/internal/store/authsrc_sqlite.go`（BindExternalUser）、`store/orgs.go`（GroupKind 枚举）、users 表补 email 列+回填。
- 为什么值得：「按 AD 安全组授权应用/差异化 MFA」是企业接目录后的第一个真实诉求；采集侧（GroupAttr/EmailAttr）与承接侧（allow_groups/ScopeGroups/SubjectIndex）全部现成，只缺中间一行消费——全清单杠杆最高的一条。
- 注意：外部组绝不能进 `admin_roles` 语义；手机号映射不做（见边界第 6 条）。

**3. 外部账号状态回验（D 组第一步）— M ✅ 已落地**
- 做什么：后台循环（仿 alerts/auditforward 模式）对 LDAP 源按 `Subject=entryDN` 周期查账号状态，禁用/过期即置 `users.status` 并并入既有撤销名单（撤窗断隧道 + 拒敲门链路现成）；OIDC 源暂无回验通道，如实标注。
- 改哪里：`control/internal/authsrc/ldapsrc`（按 DN 查状态）、`control` 主循环、复用 `api` 撤销通道。
- 为什么值得：ARCHITECTURE.md 自认「目前最需要补的一个洞」——AD 禁号后 8h 会话及其派生（敲门令牌、JIT）继续有效，直接击穿「持续验证」第一性主张。把失效窗从 8h 压到回验周期，成本远小于全量同步。
- 第二步（记档延后，L）：目录导入/立即与周期同步/同步日志/属性映射配置面（FR-USER-07/20 完整形态），本波不做但写进 TODO 档，别再让它悬在「未表态」。

**4. TOTP 真二因子 + 摘除假方法选择器（FR-AUTH-03/12/16）— S+M ✅ 已落地**
- 落地记（2026-08-14）：`internal/totp` 自研 RFC 6238（RFC 4226/6238 官方向量钉住）；`totp_secrets` 密文行（secret 盒 AAD 绑账号）+ `ConsumeTotpCounter` 原子防重放；secondFactor 顺序 passkey>TOTP>策略，legacy 123456 仅在「RP 未配且未注册 TOTP」可达；门户/管理台/桌面/移动四端登录都接 `needTotp`（TOTP 是 C/S 客户端唯一可用的标准二因子）；方法多选由 `authpolicy.SecondaryMethods` 驱动置灰，sms/radius/cert/http 保存拒收+迁移清洗。浏览器实测全流程（注册→独立 Python 实现算码确认互通→强制登录→动态码放行）。
- 做什么：两步。①当天可做（S）：认证策略抽屉的 PC/移动 Secondary 多选按 `capabilities` 置灰（与 enhance/exempt 勾选框同款门），摘掉「能选 sms/totp/radius/cert 却全不生效」的假开关——违反自家「界面上任何一个勾都必须真能生效」的纪律。②TOTP 实现（M）：RFC 6238 标准库可写（本项目自研 JWT/IKEv2 的先例），注册（门户 /portal/security 与 passkey 并列）+ `secondFactor` 增加 totp 路径 + 替换 legacyDemoCode 回落。
- 改哪里：`console/src/views/Auth.vue`、`control/internal/api/webauthn.go`（secondFactor）、新 `control/internal/totp`。
- 为什么值得：裸 IP 部署（含演示站 101.43.125.131）目前唯一「二因子」是 123456——TOTP 是不依赖可注册域名的唯一标准因子，这条修完演示站才有真 MFA。

### 第二梯队：拒绝留痕与证据链

**5. 网关安全事件上报管道（A 组：FR-MON-05 + FR-AUDIT-02）— M**
- 做什么：网关侧给 SPA 五种敲门拒绝（spa.go:228-261）、L4 五种代理拒绝（proxy.go:130-177）、L7 十种拒绝（webproxy/server.go）加计数与事件入队（扩 `QueueEvent` 的 kind，按 (来源IP,类别) 节流——仿 `auditGrayObserved` 的 5min 纪律，否则 UDP 敲门噪声会刷爆审计）→ 心跳捎带 → 控制面 `gwEvent` 扩 kind 映射（verdict 不再硬编码 "ok"）落 `audit_log` dataplane 类 + 攻击源计数表；安全概览「设备防线」换成真实攻击源统计（IP 数/趋势/TOP5），替掉现在顶包的 trusted_devices 台账。
- 改哪里：`gateway/internal/spa`、`proxy`、`webproxy`、`cplane`；`control/internal/api/api.go`（gwEvent、心跳体）、`store/overview_sqlite.go`。
- 为什么值得：SPA 隐身是第一卖点，「谁在敲门」是隐身在挡攻击的唯一可见证据；零信任的「拒绝」比「放行」更需要留痕——现在网关一重启拒绝痕迹即灭失，180 天留存对数据面事件是空话。两个 P0 一条管道解决。

**6. 审计在线检索（B 组）— S ✅ 已落地**
- 做什么：`store.Audit` 加过滤参数（actor/category/src_ip/from/to/关键词 + limit/offset 分页，列全在，纯缺 WHERE），`handleAudit` 读参，`Audit.vue` 检索控件接真——顺带把那排根本没接进过滤逻辑的时间快选 pill 接上（现在是装饰件）。
- 改哪里：`control/internal/store/audit_sqlite.go`、`api/api.go:1713`、`console/src/views/Audit.vue`。
- 为什么值得：按账号/IP 拉证据链是审计中心存在的第一理由，现状「查某账号历史只能全量导出自行 grep」把 180 天留存的取用价值折掉大半。导出口三参现成可搬，全清单性价比最高。

**7. License 到期/容量告警（FR-MON-22 半类）— S ✅ 已落地**
- 做什么：`alertKindSpecs` 加两条 kind（到期前 15 天 / 席位将满），`alertSnapshot` 补 license 快照字段（ExpiresAt/Mode/席位占用全部现算可得），`Evaluate` 加两个 case；License 页顺带加剩余天数倒计时。
- 改哪里：`control/internal/store/alerts.go`、`internal/alerting`、`api/alerts.go`、`System.vue`。
- 为什么值得：license 已 fail-closed（过期即拒建号拒签网关证书），无预警等于定时故障——把「会突然咬人」补成「先叫后咬」，成本一个 kind。口径按命名席位如实写，别照抄 PRD 的「在线用户数」。

### 第三梯队：静默失效对症与运维闭环

**8. last_login 写入方 + 闲置账号治理（FR-MON-19/20）— S+M（① ✅ 已落地，② 待做）**
- 做什么：①先补 `users.last_login` 写入方（S）：本地与外部登录成功路径各一处 UPDATE——现在全仓零写入方，用户页「最后登录」整列停在建号时刻，是清单里最典型的展示失真；②再做闲置治理（M）：阈值配置 + 识别列表端点 + 批量锁定，接进用户页。
- 改哪里：`control/internal/api/api.go`（两条登录成功路径）、`store`、`Users.vue`。
- 为什么值得：僵尸账号是最便宜的攻击面；license 席位提示已在说「删除闲置账号释放席位」，系统却给不出哪些账号闲置——自相矛盾当场解决。

**9. 网关→后端可达性预检（FR-SCEN-26）— M**
- 做什么：网关侧对注册资源的 backend 周期拨测（TCP connect，低频+抖动），结果随心跳 metrics 同模式上报 → 落库 → `/diag` 新增检查项 + 资源页/发布向导显示逐资源可达性。拨测必须在网关做（control 未必可达业务网段）。
- 改哪里：`gateway/internal/cplane`（心跳捎带）、新采集点、`control/internal/api/diag.go`、`Resources` 页。
- 为什么值得：直接对症 CLAUDE.md 记载的「历史上最迷惑失败形态」——把「点开应用才炸」的静默失败提前到部署/诊断期可见。与行动 5 共用心跳扩展，合并实现边际成本低。

**10. 桌面端自助诊断真化（E 组第一步，NFR-OPS-02）— M**
- 做什么：Diagnostics.vue 的「网关连通」「专用 DNS 解析」两项从恒 ok 改为真实探测（经 Tauri 命令拨网关隧道口 / 向解析器 VIP 发一次真实查询）；`collect()` 从假 toast 改为真 Tauri 命令打包本地日志（tunnel 日志 + posture 快照 + 剖面快照 + 诊断结果 → zip 落桌面）。
- 改哪里：`clients/desktop/src/views/Diagnostics.vue`、`src-tauri/src/main.rs`（新增命令）。
- 为什么值得：假绿诊断比没有诊断更糟——它替坏链路背书，与「隧道显示已接入实际不通」静默失效族直接冲突。该文件自初始壳提交后六波未碰，是全客户端最陈旧的假代码。

**11. 客户端灰度最后一跳（FR-UPG-19）— S**
- 做什么：桌面端登录后调一次 `GET /api/v1/client/update`（已有登录态与版本号），有新版显示横幅指向门户下载中心；**同一提交修正 SCOPE.md:11「客户端灰度真跑通」的夸大口径**为「服务端判定+终端提示闭环」。
- 改哪里：`clients/desktop/src/lib/api.ts` + `Connect.vue`、`docs/SCOPE.md`。
- 为什么值得：服务端分桶/名单/Coverage 全真且有测试，就差终端一跳；补上后 AC-12 才可能在真机上发生，`Coverage` 计数也才有消费意义。

**12. 部署前环境基线自检（FR-DEPLOY-01）— S**
- 做什么：install-remote.sh 预检段加 nproc/MemTotal/df 核对 + DNS 解析自检，输出「达标/不达标」结论（不达标默认中止、可 FORCE 覆盖）；deploy/README.md 补环境要求清单。NTP 可达性看有无 chrony/timedatectl 即可，认证源可达性部署时点判不了、不做。
- 改哪里：`deploy/install-remote.sh`、`deploy/README.md`。
- 为什么值得：PRD 列 P0，十几行 shell 的事，防「装上了跑不动」。

**13. 图形验证码：接真或摘除（FR-SCEN-13）— S**
- 做什么：二选一当场定，不许再悬着。推荐接真：登录失败 N 次（阈值低于锁定阈值）后触发服务端生成的图形挑战，与 lockout.Guard 同链路；若判定不值得，同一提交摘掉 Policy.vue 那行演示开关并在 ARCHITECTURE 第七节声明（理由：锁定闸已真，验证码只补分布式低频撞库）。
- 改哪里：`console/src/views/Policy.vue:380`、（若接真）`control/internal/api` 登录链路。
- 为什么值得：FR-SCEN-13 集合内独此一项是壳；假开关是审计陷阱的种子。

**14. 用户/终端批量导入导出（F 组）— S**
- 做什么：①当场处理 Users.vue:10 无 @click 的「批量导入」死按钮（自家纪律明令禁止的装饰件）；②users 与 devices 各加 CSV 导出端点（照 audit/export 的流式+BOM+公式注入中和现成模板）；③导入端点：用户建号复用现有校验，设备预登记注意 MaxDevicesPerAccount=20 与 trusted_devices↔posture_reports 对应约定（导入行无 posture 报告，与 strict 缺报即拒有交互，导入时如实标注）。
- 改哪里：`control/internal/api`（4 个端点）、`Users.vue`、`Devices.vue`。
- 为什么值得：设备导入是 strict 准入模式上线前完成预授信的唯一路径（现在只能 observe 模式下逐台上报再批准）；导出服务资产盘点。

**15. 终端资产分类与标签（FR-EP-06~09）— M**
- 做什么：`trusted_devices` 加 `asset_class`（企业/个人/企业纳管个人）与 `tags` 列（补列+回填，老规矩），Devices 页可编辑；执行方落在**准入闸粒度**——`deviceAdmissionGate` 按分类差异化（如个人资产仅 observe、或对该账号并入 degrade 类摘高敏名单）。
- 改哪里：`control/internal/store/devices.go`、`api/devices.go`、`Devices.vue`、`deviceAdmissionGate`。
- 为什么值得：ZTNA「设备支柱」的后半段；对接既有 degrade/sensitivity 机制不必新造执行方。**明确边界**：真按设备区分资源需把指纹贯穿数据面（撤销通道无设备维度），本波只做账号/准入闸粒度，文档如实写。

---

## 二、建议永久列为边界（写进 SCOPE.md 对应章 + ARCHITECTURE.md 第七节）

完成度的另一半是把「不做」说清楚。以下各补一条声明，杜绝「未表态悬置」：

1. **解密流量旁路镜像（FR-AUDIT-16/17）**：形态依赖硬件化网关与专用镜像口，与白帝进程形态不匹配；SIEM 深度审计需求已由带 seq/mac 的审计外送承接。
2. **SNMP（NFR-OPS-03/OBS-03）**：网关指标 + 业务告警 + syslog/SIEM 外送已覆盖可观测性主诉求；将来有 NMS 生态需求再评估只读暴露 gateway_metrics。
3. **自定义 HTTPS 认证目录（FR-USER-05）**：私有认证服务器无稳定 Subject，绑定只能退回按用户名——正是本项目在认证源实现里指认过的冒充漏洞；与已明拒的 RADIUS/短信/证书一并写明。
4. **企业微信/钉钉/浙政钉/飞书目录连接器（FR-USER-08 后半）**：依赖外部平台租户与实机验证，本项目环境无法诚实交付；标准路径是这些平台的 OIDC 出口（行动 1 落地后部分可达）。
5. **终端日志远程收集（FR-EP-17/18/19）**：需要新造服务端→客户端指令下发通道（现架构客户端只拉不收），改造面大于收益；本地一键日志打包（行动 10）落地后价值进一步降低。**记档延后而非否决**，措辞与其他边界区分。
6. **LDAP 手机号字段映射（FR-AUTH-08 子项）**：短信网关已明拒，手机号在系统内无任何消费方，映射进来即孤儿数据。

另：外部目录**全量同步**（D 组第二步）不列永久边界——价值不低，是 L 级延后项，已在行动 3 记档。

---

## 三、对 2026-08-10 审计的修正意见

那份「总体 20-25%」已整体不可用，失真是系统性的而非个别章：

**分数大面积失真（低估 40 分以上量级）的章**：
- **ch3 架构 / ch15 系统管理**：多活+故障转移、温备+切换脚本、License、升级、诊断、时钟一致性全部落地——旧审计写的形态已不存在，需整章重写而非改分。
- **ch4 升级管理**：从近 0 到只差终端一跳（行动 11）。
- **ch5 监控中心**：设备状态/在线用户/用户状态/业务告警/三道防线全真，余下三条缺口（攻击源、闲置、license 告警）全在本清单。
- **ch7 认证管理**：WebAuthn、认证策略真接线、LDAP/AD、防爆破、口令治理全真——旧审计的「认证源完全是界面」结论已彻底过时。
- **ch8（Web 代理）/ ch12（SPA/基线处置）/ ch16（审计链/外送/留存）/ ch18（NAT）/ ch21（消息通道/联动）**：核心能力从 config-only 或零变为有测试守着的真实现。

**失真较轻、缺口仍集中的章**：ch6（外部目录同步/组映射簇）、ch9（FR-EP-01~09/17~19 半章仍空，但 10~16 已真）、ch2/ch19/ch20（散点缺口，主体已实现）。

**旧审计四个系统性根因的现状**：「审计失效」已被 HMAC 链+外送+全端点落审计解决；「无回执」已被 QueueEvent 指令回执与 last_status 只由真发送写入的纪律解决；「diag 背书」已被十项真体检+如实说连不上的纪律解决；「嵌入陷阱（config-only）」**仍是活的**——本波 24 条存活缺口里 7 条是 config-only（OIDC 入口、方法选择器、memberOf、灰度终端、假诊断、死按钮、假验证码），且全部集中在「链路最后一跳」形态：后端真、协议真、就差接线。下一份审计的检查重心应从「表和 UI 存不存在」改为「每条链路顺着消费方摸到头」。

**两处文档随行动同步修正**：SCOPE.md:11「客户端灰度真跑通」（行动 11）；ARCHITECTURE.md 第九节「下一步建议」仍有「认证源完全是界面」等六波前的过时表述，整节按本清单重写。

**建议**：不要再对旧审计打补丁分——以本清单「15 条行动 + 6 条边界」为新基线，MEMORY 里的 prd-completion-audit.md 标记为已过时并指向本清单。
