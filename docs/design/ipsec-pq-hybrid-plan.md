# IPSec 后量子混合密钥交换（ML-KEM-768 × IKEv2）· 施工方案

> **状态：方案，未实施。** 2026-09-07 由「功能面上『本版本未实现』太多」这条盘查产出。
> 站点组网页上那个 **PQ 开关此刻是 disabled 的诚实形态**——本文回答的是「要把它做成真判据要动哪些地方、值不值得」，
> 不是「已经做了」。ARCHITECTURE.md 第七节的真伪清单在本方案落地前**不变**。
>
> 结论摘要：能做，密码学部分极薄（ML-KEM-768 在 Go 标准库里），工作量在协议机械（IKE_INTERMEDIATE + IntAuth 链 +
> ADDKE 变换 + IKE SA 重协商）。建议只做「档一」（初始交换 + IKE SA 重协商，4~6 人日），停在档一；
> 不做回落、不落私有码点。若不打算投入，**现状什么都不用改**。
>
> 相邻决策的对照：`suite=gm` 落私有码点是因为 IANA 从未给 SM 系列分配码点；ML-KEM 已有 IANA 分配（35/36/37），
> 再造私有码点只会白白放弃将来互通——两者是同一条原则的两个结果，不是相反。★施工前须上 IANA 注册表复核码点。

---

# 原方案正文（workflow「PQ 混合方案」轨道产出，未改任何代码）

> 轨道约束核对：本轨**零文件改动**。`git diff --stat` 里出现的 `control/go.mod` / `control/go.sum`（+`layeh.com/radius` 间接依赖，mtime 10:21）不是本轨所为，属并行轨道，我未触碰。

## 0. 现状盘点（读代码得到的事实，方案以此为基）

| 事实 | 出处 |
|---|---|
| 交换类型只认 34/35/36/37；`onRequest` 有**已认证闸**：IKE_AUTH 之外的交换在 `SAHalfOpen` 一律拒 | `ike/const.go:45-50`，`ike/engine.go:438-497` |
| Transform Type 只定义 1~5；`SelectProposal/matchProposal` **只比本端要的类型**，对端提案里多出的未知 Transform Type 会被无声放过 | `ike/const.go:151-157`，`ike/suite.go:551-665` |
| KE 抽象是 `DHGroup{Generate}→DHPrivate{Public,Shared}`：**对称 DH 模型**，公钥定长 `PubLen()`，解析层按它校长度 | `ike/dh.go:436-451`，`ike/payload_ke.go:390-394` |
| 四条派生公式全在 `keys.go`，纯函数 + 快照锁死；`DeriveRekeyedIKEKeys` 的 SKEYSEED = `prf(SK_d旧, g^ir新‖Ni‖Nr)` | `ike/keys.go:685-731` |
| AUTH 待签串 = `RealMessage ‖ 对端 nonce ‖ MACedID`，`SignedOctets` 三参 | `ike/auth.go:76-93` |
| SK 加密：GCM 的 **AAD = 报文首字节 ~ IV 末字节**；`EncryptSK` 超 65535 直接拒且注释点名「不做 IKE 分片」 | `ike/payload_sk.go:117-121,138` |
| `initMsgRaw/respMsgRaw` 只由 `resendSAInit`/`onSAInitRequest` 写；MID：SA_INIT=0，IKE_AUTH 取 `sa.nextTxMID`（=1）；响应方 `expectRxMID=1` | `ike/initiator.go:131-140,362`，`ike/responder.go:725` |
| 窗口固定 1（`startExchange` 有 pending 即拒）；`exchange.kind` 决定响应走哪条分支 | `ike/engine.go:560-570`，`ike/sa.go:781-814` |
| IKE SA rekey：CREATE_CHILD_SA 一次往返 + `promoteRekeyedIKE` 立刻顶替；Child rekey 同交换类型按 Protocol 区分 | `ike/rekey.go:254-388,542-648` |
| `pqHybrid` 现状：控制面列 `ipsec_sites.pq_hybrid` + DTO `PqHybrid` → `sync.go` 塞进 `ipsec.ExtraOptions` → `config.go:checkExtra` **装载期拒绝**（文案「RFC 9370 / PPK 完全未实现」）；`site/backend_test.go:313-334` 钉住拒绝；`api/ipsec.go:157` 告警；`Ipsec.vue:195/396/693` 标「PQ 未实现」+ 开关 disabled | 上表各处 |
| `siteFingerprint` 不含 pqHybrid（因为它不在 `SiteConfig` 里）；`buildSite` 是「字符串→码点」的唯一入口，只调 `SpecFromPhase(phase, suite, forChild)` | `ike/engine.go:808-889` |
| 传输层收包缓冲 65535；MemNet 有 `SetFilter` 钩子可做丢包/改包 | `transport_udp.go:73`，`transport_mem.go:32` |
| gateway 走 **go 1.26.3**，`crypto/mlkem` 在标准库：`GenerateKey768 / NewDecapsulationKey768(seed) / (dk).EncapsulationKey().Bytes() / NewEncapsulationKey768 / (ek).Encapsulate() (ss, ct) / (dk).Decapsulate(ct)`；`SharedKeySize=32`、`SeedSize=64`、ek 1184 B、ct 1088 B | `go doc crypto/mlkem` |
| docs/ARCHITECTURE.md:619 把「后量子混合」列在不实现清单，措辞「字段保留但无效，装载期告警」 | 原文 |

一条**顺带发现**（不在本轨改，但与本方案的 IntAuth 范围定义直接相关）：`EncryptSK` 的 GCM AAD 覆盖到 **IV 末字节**，而 RFC 5282 §5.1 规定 AAD 止于 **SK 载荷通用头的最后一字节（不含 IV）**。白帝↔白帝对称无影响；若将来对 strongSwan 走 GCM 会恒「解密失败」。RFC 9242 的 `IntAuth_*A` 范围**明文定义为「与 RFC 5282 AAD 同范围」**，所以本方案里 IntAuth_A **不能**直接复用现有 AAD 切片，得单独按 RFC 切（见 §3.3）。建议记进 ARCHITECTURE「互通风险点」，与「显式发 INTEG=NONE」那条并列。

## 1. 结论先行

- **能做，且密码学部分极薄**：ML-KEM-768 在标准库里，Go 1.26 的实现是 FIPS 203 定稿版（与 strongSwan 6.0 同源标准）。真正的工作量在**协议机械**：IKE_INTERMEDIATE（RFC 9242）+ 其 `IntAuth` 链 + ADDKE 变换类型（RFC 9370）+ IKE SA 重协商的 IKE_FOLLOWUP_KE。这些与算法无关，是白帝 IKE 状态机第一次要接「三步握手」。
- **码点取舍**：ML-KEM-768 用 **IANA 正式码点 36**（Transform Type 4「Key Exchange Method」注册表，35/36/37 = ML-KEM-512/768/1024，来自 draft-ietf-ipsecme-ikev2-mlkem 的早期分配），**不落私有段**。这与 `suite=gm` 的既有决定是**同一条原则**而非相反：gm 落 1024+ 是因为 IANA 从未给 SM 系列分配码点；ML-KEM IANA 已分配，再造私有码点只会白白放弃将来互通的可能。故 `pqHybrid` **不受 `suite` 闸约束**：`standard` 与 `gm` 都可开（后者 = SM2P256 + ML-KEM-768，仍只白帝↔白帝）。★施工前上 IANA 注册表复核 35/36/37 数字与该草案是否已成 RFC——早期分配不会变号，但要确认。
- **混合形态**：Type 4 = 经典群（group19/group14/sm2p256，配置照旧），**ADDKE1（Type 6）= ML-KEM-768**，经 IKE_SA_INIT 之后**一次** IKE_INTERMEDIATE 承载。只做 ADDKE1，不做 ADDKE2~7（Type 7~12 定义码点但拒绝多个）。**不提供 NONE 备选、不做回落**：一端开了 pqHybrid 而对端不支持/未开 → 谈崩并两端各给一句点名 ML-KEM 的原因——与 `matchDH`「静默降级必须谈崩」同一纪律。
- **值不值得做**：值得做**第一半**（初始交换 + IKE SA 重协商），前提是团队想把「PQ」从「诚实的 disabled 开关」变成「真判据」。它的安全收益是明确且完整的：ESP 全部 KEYMAT 都由 `SK_d` 派生，`SK_d` 一旦混入 ML-KEM 秘密，**所有业务流量的机密性都获得抗量子保护**（harvest-now-decrypt-later 场景），Child SA PFS 保持经典并不削弱这一点（详见 §6）。第二半（Child SA PFS 混合）与第三半（IKE 分片解 MTU）可不做。若团队不打算投入 4~6 人日，**现状已是诚实形态，不需要为它做任何事**。

## 2. 报文流变化

### 2.1 初始交换（pqHybrid=true）

```
发起方                                                    响应方
IKE_SA_INIT req  MID=0（明文）
  SA{ENCR,PRF,INTEG,DH(19),ADDKE1(36)} KE(19) Ni N(NAT…) N(INTERMEDIATE_EXCHANGE_SUPPORTED)
                                                    ──►  SelectProposal 要求 ADDKE1=36 命中
                                                         且对端带 INTERMEDIATE_EXCHANGE_SUPPORTED，缺一即
                                                         NO_PROPOSAL_CHOSEN + failSite（原因点名 ML-KEM）
IKE_SA_INIT resp MID=0（明文）
  SA{…ADDKE1(36)} KE(19) Nr N(NAT…) N(INTERMEDIATE_EXCHANGE_SUPPORTED)   ◄──
两端：SKEYSEED(0)=prf(Ni‖Nr, g^ir) → SK_*(0)              ← 现有 DeriveIKEKeys 逐字不变
发起方：无 INTERMEDIATE_EXCHANGE_SUPPORTED 或回选提案缺 ADDKE1 → failSite（不回落）

IKE_INTERMEDIATE req  MID=1，SK(0) 加密
  SK{ KE(group=36, data=ek 1184B) }                  ──►  ek 合法性由 NewEncapsulationKey768 校验
                                                         Encapsulate → (SK(1), ct)
IKE_INTERMEDIATE resp MID=1，SK(0) 加密
  SK{ KE(group=36, data=ct 1088B) }                  ◄──  respond()（缓存原样字节供重传回放）
两端：IntAuth_i1 / IntAuth_r1（用 SK_pi(0)/SK_pr(0)，见 §3.3）
两端：SKEYSEED(1)=prf(SK_d(0), SK(1)‖Ni‖Nr) → SK_*(1)，替换 sa.Keys（IV 计数器不清零，继续单调）
发起方：Decapsulate(ct) → SK(1)  ★ML-KEM 解封装对合法长度的 ct 永不报错（隐式拒绝→伪随机秘密），
        篡改只会在 IKE_AUTH 以「AUTH 校验失败」现形——auth.go 的六根因清单要加第七条

IKE_AUTH req  MID=2，SK(1) 加密
  SK{ IDi IDr AUTH SA TSi TSr N(INITIAL_CONTACT) }    ──►  AUTH = prf(prf(PSK,pad), RealMessage1‖Nr‖MACedIDForI‖IntAuth)
IKE_AUTH resp MID=2，SK(1) 加密                        ◄──  MACedID 用 SK_p*(1)；IntAuth = IntAuth_i1‖IntAuth_r1
```

变化点归纳：① IKE_SA_INIT **本身不变大**（仍是 ECP-256 的 64 B），这正是 RFC 9242 的意图；② 多一轮加密往返，MID 顺延（SA_INIT 0 / INTERMEDIATE 1 / AUTH 2）——现有代码用 `sa.nextTxMID` 与 `expectRxMID` 递增，天然顺延，**不需要改 MID 逻辑**；③ `initMsgRaw/respMsgRaw` 仍是 IKE_SA_INIT 的两条原始字节，**不变**；④ IKE_AUTH 之前多一个可被对端触发的加密交换，半开配额 `halfOpenTTL` 要覆盖多一次 RTT。

### 2.2 IKE SA 重协商（pqHybrid 站点必须做，否则「配了 A 跑了 B」）

```
CREATE_CHILD_SA req  SK{ SA{IKE, SPI=新SPIi, …ADDKE1(36)} Ni KE(19) }
CREATE_CHILD_SA resp SK{ SA{IKE, SPI=新SPIr, …ADDKE1(36)} Nr KE(19) N(ADDITIONAL_KEY_EXCHANGE, link) }
    两端：SKEYSEED(0)=prf(SK_d旧, g^ir新‖Ni‖Nr) → SK_*(0)   ← 现有 DeriveRekeyedIKEKeys 逐字不变
    ★新 SA 此时不 promote，旧 SA 继续承载
IKE_FOLLOWUP_KE req   MID=旧SA下一个，SK(旧) 加密：SK{ N(ADDITIONAL_KEY_EXCHANGE, link) KE(36, ek) }
IKE_FOLLOWUP_KE resp                              SK{ N(ADDITIONAL_KEY_EXCHANGE, link) KE(36, ct) }
    两端：SKEYSEED(1)=prf(SK_d(0), SK(1)‖Ni‖Nr) → SK_*(1)   ← 与 §2.1 同一函数
    然后 promoteRekeyedIKE（MID 归零、迁 Child、旧 SA 延迟删除，逐字不变）
```

- IKE_FOLLOWUP_KE（Exchange 44）跑在**旧 IKE SA**上、用旧密钥保护；`link` 是响应方在 CREATE_CHILD_SA 响应里给的不透明数据，发起方原样带回，响应方据此找到「哪条待完成的重协商」。窗口 1 下两个交换串行，`exchange.kind` 加 `exFollowupKE`，`exchange.ikeNew` 沿用。
- 撞车判定沿用 `TEMPORARY_FAILURE`：`answerRekeyIKE` 与 `answerFollowupKE` 都要看 `sa.rekeying || pending.kind ∈ {exRekeyIKE, exFollowupKE}`。
- Ni/Nr 用 CREATE_CHILD_SA 的那两个；SPIi/SPIr 用新 SA 的；三者任一沿用旧值 = 重协商后静默断流（`keys.go:715-718` 那条纪律的 PQ 版本）。

### 2.3 Child SA PFS（第一半**不做**，明确声明）

pqHybrid 站点的 Child SA 重协商仍只带经典 KE（`spec2.DHID`），`KEYMAT = prf+(SK_d, g^ir‖Ni‖Nr)` 不变。理由与边界见 §6.2；页面与文档要**当面写**「PQ 保护作用于 IKE SA 及由其派生的全部 ESP 密钥；Child SA 的前向保密仍是经典 DH」。第二半若做，走 CREATE_CHILD_SA(ESP) + IKE_FOLLOWUP_KE，`KEYMAT = prf+(SK_d, g^ir‖SK(1)‖Ni‖Nr)`（RFC 9370 §2.2.3，施工前复核拼接顺序）。

### 2.4 码点清单（**待新增**，今天 `ike/const.go` 里一个都没有）

```go
ExchangeIKEIntermediate ExchangeType = 43   // RFC 9242
ExchangeIKEFollowupKE   ExchangeType = 44   // RFC 9370
TransformAddKE1 … TransformAddKE7 TransformType = 6 … 12   // RFC 9370；本实现只发/只收 6，7~12 认得出但拒绝
KEMlKem768 uint16 = 36   // IANA Type-4 注册表；35/37 定义但不放进 dhTable（1024 的 ek/ct 各 1568B 必分片，见 §6.3）
NotifyIntermediateExchangeSupported NotifyType = 16438   // RFC 9242（状态类，不认识的实现会忽略——正是回落检测的判据）
NotifyAdditionalKeyExchange         NotifyType = 16441   // RFC 9370（状态类）
```

## 3. 密钥派生：逐条对到现有函数

### 3.1 第 n 次附加 KE 之后（IKE_INTERMEDIATE，n=1）

```
SKEYSEED(n) = prf( SK_d(n-1) , SK(n) ‖ Ni ‖ Nr )
{SK_d ‖ SK_ai ‖ SK_ar ‖ SK_ei ‖ SK_er ‖ SK_pi ‖ SK_pr}(n) = prf+( SKEYSEED(n) , Ni ‖ Nr ‖ SPIi ‖ SPIr )
```

**这与 `DeriveRekeyedIKEKeys(su, oldSKd, dhShared, ni, nr, spii, spir)` 是同一个公式**（`keys.go:719-731`：`su.PRF.Sum(oldSKd, dhShared‖ni‖nr)` → `expandIKEKeys`）。RFC 9370 刻意如此设计。落地方式：新增薄包装 `DeriveAddKEKeys(su, prevSKd, sk_n, ni, nr, spii, spir)`，函数体就是一行调用，注释写明「公式同 rekey，SK(n) 在 g^ir 的位置」，并加一条测试**断言两函数对同一输入逐字节相等**——把「这是同一条公式」钉成可执行事实，而不是靶心在注释里。`checkKeyInputs` 的空秘密拦截自动覆盖 `SK(n)`。

### 3.2 各阶段用哪一代密钥

| 报文 | 加密/完整性 | IntAuth 用的 SK_p | MACedID 用的 SK_p |
|---|---|---|---|
| IKE_INTERMEDIATE #1 req/resp | SK_e/SK_a **(0)** | SK_pi/SK_pr **(0)** | — |
| IKE_AUTH | SK_e/SK_a **(1)** | — | SK_pi/SK_pr **(1)** |
| （若 N>1）INTERMEDIATE #n | (n-1) 代 | (n-1) 代 | — |

★「第 n 次交换用第 n-1 代密钥保护并算 IntAuth；第 n 代密钥在**双方都处理完第 n 次交换后**派生」——这是 RFC 9370 §2.2.2 的语义，施工前逐字复核该节末段。响应方的时序：解密 req（0 代）→ 封装 → 加密 resp（0 代）→ `respond()` 缓存 → **再**派生 1 代并替换 `sa.Keys`。重传回放走缓存字节，不受密钥更替影响（`sa.go:887-895` 那条纪律正好兜住）。

### 3.3 IntAuth（RFC 9242 §3.3.2）与 AUTH 的改法

```
IntAuth_i1 = prf( SK_pi(0) , IntAuth_i1A ‖ IntAuth_i1P )
IntAuth_r1 = prf( SK_pr(0) , IntAuth_r1A ‖ IntAuth_r1P )
（N>1 时链式：IntAuth_in = prf(SK_pi, IntAuth_i(n-1) ‖ IntAuth_inA ‖ IntAuth_inP)）
IntAuth = IntAuth_iN ‖ IntAuth_rN
InitiatorSignedOctets = RealMessage1 ‖ Nr ‖ MACedIDForI ‖ IntAuth
ResponderSignedOctets = RealMessage2 ‖ Ni ‖ MACedIDForR ‖ IntAuth
```

- **A 部分** = 该 IKE_INTERMEDIATE 报文从 IKE 头首字节到 **SK 载荷通用头末字节**（不含 IV），且 IKE 头 `Length` 与 SK `Payload Length` **改写为不计 IV/Padding/PadLen/ICV 的值**（即 `Length = len(A)+len(P)`，`SK Length = 4+len(P)`）。目的是让 IntAuth **与加密套件无关**——GCM 与 CBC 算出同一个值。这是一条极好的测试判据（§5.1）。**不能复用现有 AAD 切片**（它含 IV，见 §0 顺带发现）。
- **P 部分** = 解密后的内层载荷原始字节（不含补齐与 PadLen）。`DecryptSK` 现在把内层解析进 `m.Payloads` 后丢掉了明文字节 → 需在 `Message` 上新增 `InnerRaw []byte` 与 `SKBodyOff int`，由 `DecryptSK` 填；发送侧 `EncryptSK` 已握有 `innerBytes`，新增返回值或提供 `intAuthParts(raw, skOff, inner) (A, P)` 一个纯函数给收发两侧共用——**只此一处实现**（同 `respond()` 的理由：算 A 的长度改写规则散到两处必错一处，且症状只有「认证失败」）。
- `SignedOctets(realMsg, peerNonce, macedID)` 加第四参 `intAuth []byte`；无 PQ 时传 nil，字节串与今天**逐字相同**，`auth_test` 快照全绿不动。`SignedOctetsDigest` 多打一段 `IntAuth=…`，排障时能看出两端差在第四段。
- `auth.go` 顶部「六个根因、一句报错」清单加第 7 条：**IKE_INTERMEDIATE 被篡改 / 两端 ML-KEM 秘密不一致**（ct 篡改不会在解封装处报错）。`onAuthResponse/onAuthRequest` 的 AUTH 失败文案在 pqHybrid 站点上追加「或 pqHybrid 的 IKE_INTERMEDIATE 在途被改」。

### 3.4 IV 计数器与响应缓存

`txIVCounter` 跨代**继续递增不清零**（新密钥下旧 nonce 也不重复，清零反而制造「同 key 同 nonce」的边缘）。`cacheResponse` 只存最后一条：响应方回过 INTERMEDIATE(MID 1) 之后再收到 IKE_SA_INIT 重传，`halfOpenBySPIi(...).replayResponse(0)` 会返回 not-ok 而静默丢——这是正确行为（发起方能发 INTERMEDIATE 说明它已收到 SA_INIT 响应），注释里要写清，别让下一个人「修」成回放。

## 4. 落地文件清单（file:function，每处一句）

> **本节全部是「要动哪些地方」的待做清单，不是变更记录。** 本文产出时**一行代码都没改**：`pqHybrid` 今天仍在 `config.go:checkExtra` 的装载期拒绝里，
> `Ipsec.vue` 的 PQ 开关仍是 `disabled`，`docs/ARCHITECTURE.md` 第七节仍把「后量子混合（`pqHybrid` 字段保留但无效，装载期告警）」列在不实现清单里
> ——**那句话是今天的真实状态，本方案落地之前不得改动它**。下面的「删 / 改 / 新增」全部是祈使句。

**gateway/internal/ipsec/ike**

- `const.go`：加 §2.4 六组码点及其 `String()`；包注释「明确不实现」里把「后量子」条目改写为「ADDKE 只做 1 个、只 ML-KEM-768、Child PFS 仍经典、不做 IKE 分片故要求路径 MTU ≥ ~1300」。
- `dh.go`：`DHGroup/DHPrivate` 是对称 DH 模型，KEM 天然不对称（发起方 ek 1184 / 响应方 ct 1088）。新增角色化接口 `KeyExchange{ID; InitLen; RespLen; SharedLen; Initiate(rand)(KexInitiator,error); Respond(rand, peerInit)(resp, shared, error)}` + `KexInitiator{Public; Finish(peerResp)(shared,error)}`；现有三个 DH 群用适配器实现它（`InitLen==RespLen==PubLen`）。`LookupDH(36)` 返回 KEM 实现。★随机源：`NewDecapsulationKey768(seed)` 的 64 B seed 从 `e.opt.Rand` 取（保住注入随机源的可测性）；`Encapsulate()` 内部走 `crypto/rand`，**不可注入**——握手类测试只能断言「两端相等」，不能钉整条握手字节（现有夹具本就如此）。
- `mlkem.go`（新）：`kemMlKem768` 实现上述接口；`Respond` 用 `NewEncapsulationKey768` 校验 ek（等价于 ECDH 的点校验，失败=对端公钥非法）；`Finish` 调 `Decapsulate`（只校长度）。注释写死「隐式拒绝：坏 ct 不报错，只在 AUTH 现形」。
- `payload_ke.go:parseBody`：长度校验从 `!= PubLen()` 改为「∉ {InitLen, RespLen}」（解析层无角色信息），精确角色长度由状态机再核；错误文案列出两个合法长度。
- `suite.go`：`SuiteSpec` 加 `AddKE1 uint16`；`SpecFromPhase(ph, suite, forChild)` 加 `pq bool`（仍是「字符串/开关→码点」**唯一入口**：`forChild=true` 时 pq 忽略并注释说明）；`IKEProposal` 有 AddKE1 时追加 `Transform{Type:6, ID:36}`；`Build()` 填 `Suite.AddKE`；`SpecFromProposal` 读 Type 6；`String()` 形如 `AES256-GCM16/PRF-HMAC-SHA256/ECP256+ML-KEM-768`（**这串是页面「PQ 实测生效」的唯一真判据**）；新增 `matchAddKE`：本端要 36 → 对端必须有 36；本端不要 → 对端提了非 NONE 的 Type 6~12 → **拒**（镜像 `matchDH` 的「静默降级必须谈崩」，同时修掉今天「未知 Transform Type 被无声放过」的旧漏洞）。
- `keys.go`：`DeriveAddKEKeys`（§3.1）；文件头四公式表补第五条。
- `auth.go`：`SignedOctets` 四参 + `IntAuth(prf, skp, prev, a, p)` + `SignedOctetsDigest` 四段；根因第 7 条。
- `payload_sk.go`：`Message.InnerRaw/SKBodyOff` 回填；`intAuthParts` 纯函数；`EncryptSK` 额外返回（或经新包装）自己发出报文的 A/P。
- `sa.go`：`IKESA` 加 `kexInit KexInitiator`（发起方在途私钥，派生完置 nil，同 `dh` 字段纪律）、`intAuthI/intAuthR []byte`、`addKEDone bool`、`peerIntermediateOK bool`；`SAState` 加 `SAIntermediateSent`（发起方；响应方仍 `SAHalfOpen`），`authenticated()` 对它返回 false；`exchangeKind` 加 `exIntermediate`、`exFollowupKE`；`exchange` 加 `link []byte`。
- `initiator.go`：`buildSAInitRequest` 有 AddKE 时追加 `N(INTERMEDIATE_EXCHANGE_SUPPORTED)`；`onSAInitResponse` 在 `DeriveIKEKeys` 之后分叉：AddKE≠0 → 校 `SelectProposal` 已含 36 + 对端通知存在（缺 → `failSite`「对端不支持 IKE_INTERMEDIATE/ML-KEM 或未开 pqHybrid；本端不回落」）→ `sendIntermediateRequest`；新增 `onIntermediateResponse`（`DecryptSK`(0 代) → KE 校 group/长度 → `Finish` → IntAuth 两条 → `DeriveAddKEKeys` → 替换 Keys → `sendAuthRequest`）；`sendAuthRequest/onAuthResponse` 把 `sa.intAuth()` 传进 `SignedOctets`。
- `responder.go`：`onSAInitRequest` 第⑤步后：spec 含 36 而对端无通知 → `NO_PROPOSAL_CHOSEN` + `failSite`；响应带通知；新增 `onIntermediateRequest`（仅 `SAHalfOpen && !addKEDone && Suite.AddKE!=nil`；解密 → 校 → `Respond` → 加密回 → `respond()` → IntAuth → 派生 → 替换 Keys → `addKEDone=true`）；`onAuthRequest` 开头加「Suite.AddKE≠nil && !addKEDone → 丢弃并 WARN」（解密本会失败，但要让原因可读）。
- `engine.go`：`onRequest` 已认证闸放行 `ExchangeIKEIntermediate`（条件同上，**只在 HalfOpen 且待 ADDKE 时**——这是新增的未认证攻击面，判据要写成白名单不是黑名单）；`switch` 加两个分支；`onResponse` 加两 kind；`buildSite` 把 `cfg.PQHybrid` 传进 `SpecFromPhase`；`siteFingerprint` 加 `PQHybrid`（漏了 = 开关切换后 `AddSite` 判「同一配置」直接 return，永不生效，与 `PeerNATPort` 那条判例同形）；`hasInFlight/reapSAs` 认识新状态。
- `rekey.go`：`rekeyIKE` 提案带 AddKE1；`answerRekeyIKE` 派生 0 代后**不 promote**，回 `N(ADDITIONAL_KEY_EXCHANGE, link)`，把 `next` 挂在 `sa.pendingRekey[link]`；`onRekeyIKEResponse` 读 link → `sendFollowupKE`；新增 `onFollowupKEResponse` / `answerFollowupKE`（找 link → 封装 → 回 → `DeriveAddKEKeys` → `promoteRekeyedIKE`）；`answerRekeyIKE/answerRekeyChild` 撞车判定纳入 `exFollowupKE`。★半程失败（follow-up 超时）只丢 `next`，旧 SA 照常，`abort` 推软生存期——同今天的 restore 纪律。

**gateway/internal/ipsec**

- `config.go`：`SiteConfig` 加 `PQHybrid bool`；`ExtraOptions.PqHybrid` **删除**（留着就是一条永不触发的死拒绝）；`checkExtra` 拒绝分支删；`checkCrypto` 加「PQHybrid && IKEVersion≠v2」等组合校验（若有）。
- `site/backend.go:51-53`、`cmd/baidi-ipsec/sync.go:77-79`、`cmd/baidi-ipsec/main.go:241`：DTO→`SiteConfig.PQHybrid` 直传，注释改写；`site/backend_test.go:313-334` 那条「必须拒 pqHybrid」用例**反向**成「pqHybrid 站点必须被装载且 States 显示 ML-KEM」，另保留 ikeVersion 那半拒绝。

**control**

- `store/ipsec.go:65` 注释改为「ML-KEM-768 混合（RFC 9242+9370）：网关真实现；判据看 negotiatedProposal」。
- `api/ipsec.go:157`：删「未实现」告警；改成真判据告警——`PqHybrid && sa.State==up && !strings.Contains(sa.NegotiatedProposal,"ML-KEM")` → 「配置开了 PQ 混合，但实测协商结果不含 ML-KEM-768」（理论上谈崩会 failed 而不是 up，这条是防「将来有人把 matchAddKE 放宽」的兜底）。
- `api/ipsec_gateway.go:62`：DTO 不变。

**console/src/views/Ipsec.vue**

- `:195`「PQ 未实现」标签删；PQ 状态改由 `negotiatedProposal` 含 `ML-KEM-768` 判定：命中 → 绿标「PQ 混合 · 实测」；配置开而未命中 → 并入既有 `cmpOf` 的 `miss` 红条「实际套件缺少：ML-KEM-768」；无 SA → 不显示（三态，不塌成「已启用」）。**任何一处都不许按 `s.pqHybrid` 直接渲染「已启用」**。
- `:396` 开关去掉 `disabled`；副文案改为「ADDKE1=ML-KEM-768，经 IKE_INTERMEDIATE；仅白帝↔白帝，未与 strongSwan 验证；路径 MTU 需 ≥ ~1300（本实现不做 IKE 分片）；Child SA 前向保密仍为经典 DH」。
- `:693` `unsupportedOf` 删 pq 行。
- 改完 `npm run check-ui` + `npm run type-check` 双绿（规则二会拦死占位，规则三拦 bare catch——本处不新增 catch）。

**docs**

- `docs/ARCHITECTURE.md:619`：「后量子混合」移出不实现清单，新增「能声称/不能声称」小节（§6 全文），并在互通风险点补 AAD-含-IV 那条。
- `gateway/internal/ipsec/ike/const.go` 包注释、`CLAUDE.md`「IPSec 已真实现，但边界很硬」条目补一句 PQ 边界（**不删任何既有边界声明**）。

## 5. 测试策略

### 5.1 单测（纯函数先钉）

| 用例 | 断言 | 变异检查（改回去→必须红） |
|---|---|---|
| `mlkem_test`：往返 | `Respond(ek)` 与 `Finish(ct)` 得同一 32 B；ek 长 1184、ct 1088；`NewEncapsulationKey768` 拒坏 ek | 把 `Finish` 改成返回 `Respond` 的秘密副本（作弊自洽）→ 「两端独立算出」用例红 |
| `mlkem_test`：隐式拒绝 | 翻转 ct 一位 → **不报错**但秘密不同 | 把「不报错」写成期望报错 → 红（钉住这个反直觉事实，免得后人给它加错误分支） |
| `keys_test`：`DeriveAddKEKeys` 快照 + 与 `DeriveRekeyedIKEKeys` 逐字节相等 | — | 在包装里把 `SK(n)‖Ni‖Nr` 顺序调成 `Ni‖Nr‖SK(n)` → 两条都红 |
| `auth_test`：IntAuth 向量 | A 部分长度改写规则；**GCM 与 CBC 两套件对同一明文算出同一 IntAuth**；`SignedOctets(…, nil)` 与旧三参逐字相同 | 让 A 含 IV → 「套件无关」用例红；漏掉长度改写 → 同上 |
| `suite_test`：Type 6 线格式 / `SpecFromProposal` / `String` / `matchAddKE` 双向 | 本端要 36 对端无 → 拒且文案含 `ML-KEM-768`；本端不要而对端提 Type 6 非 NONE → 拒 | 删掉第二个方向 → 「对端偷塞 ADDKE 被放过」用例红 |
| `payload_test`：KE 1184/1088 两长度都过解析，1000 拒 | — | 改回 `!= PubLen` → 红 |
| `config_test`：`PQHybrid` 进 `siteFingerprint`；`ExtraOptions` 不再有 PqHybrid | 切换开关指纹必变 | 去掉指纹项 → 红 |

### 5.2 进程内双端（`handshake_test` / `rekey_test` 夹具，MemNet）

- `TestHandshakePQHybridDerivesIdenticalKeys`：两端 KEYMAT 相等；`hsAssertWireShape` 扩展：**恰好** 三对报文，交换类型 34/43/35，MID 0/1/2；43 的外层只有 SK；`hsAssertSecretsNeverOnWire` 加 ML-KEM 共享秘密、并断言 **ek 与 ct 的字节不在任何明文段出现**（它们在 SK 内）；`NegotiatedProposal` 含 `ECP256+ML-KEM-768`。变异：删 `onIntermediateRequest` 里的派生替换 → IKE_AUTH 解密失败 → 红。
- `TestPQHybridRefusesPeerWithoutPQ`（两方向各一条）：A 开 B 关 → 两端 `failed`、`LastError` 含 `ML-KEM`/`pqHybrid`，**零 Child SA 装载**、零 up；反向同。变异：把 `matchAddKE` 改成缺就放行 → 红（并且会看到一条「PQ 配置、经典协商」的 up 隧道——正是要消灭的形态）。
- `TestPQHybridRejectsPeerLackingIntermediateSupport`：用 `MemNet.SetFilter` 从 SA_INIT 响应里剥掉 16438 通知 → 发起方 failSite 点名。变异：删发起方那道校验 → 红。
- `TestPQHybridTamperedCiphertextFailsAuth`：Filter 翻转 INTERMEDIATE 响应 SK 密文一位 → GCM 直接拒（这只验证了 AEAD）；**更有价值的**：在 MemNet 上模拟 MITM 用自己的 SK(0)……做不到（没密钥）。替代：用测试钩子让 B 的 `Respond` 返回与 ct 不配的秘密 → IKE_AUTH 两端 AUTH 失败且文案含「IKE_INTERMEDIATE」。变异：把 `IntAuth` 从 `SignedOctets` 摘掉**且**同时不派生新密钥 → 这条用例仍红（因为 SK 不同）；所以单独钉 IntAuth 的变异要靠 §5.1 的向量用例 + 一条「两端 IntAuth 相等且非空」的握手断言。
- `TestPQHybridIKERekeyKeepsChildren`：软生存期到 → CREATE_CHILD_SA + IKE_FOLLOWUP_KE → 新 SA 两端密钥相等、Child 迁移、旧 SA 延迟删除；并发重协商 → TEMPORARY_FAILURE 后收敛。变异：`answerRekeyIKE` 提前 promote → 红。
- `TestPQHybridOversizeIntermediateFailsLoudly`：`MemNet.SetFilter` 丢弃 >1280 B 的报文 → 发起方在 INTERMEDIATE 重传耗尽后 `failSite`，文案**点名报文大小与 MTU/分片可能**（不是通用「对端无响应」）。这条把 §6.3 的风险变成可读诊断。
- 半开/DoS：`TestIntermediateOnlyAcceptedInHalfOpenAwaitingAddKE`：Established SA 收到 43 → 忽略；非 PQ 站点的 HalfOpen 收到 43 → 忽略。

### 5.3 端到端（照 `ipsec-e2e.sh` / `cmd/baidi-ipsec-e2e`）

- `ipsec-e2e.sh` 建站点处再建一对 `e2e-pq-a/b`（`pqHybrid:true`，网段另取），`partA` 新增断言：两端 `negotiatedProposal` 含 `ML-KEM-768`；`wiretap` 中出现 Exchange 43 且其外层唯一载荷为 SK；跨隧道 HTTP 照常通；`partB` 的 KEYMAT 相等断言对 PQ 对照样跑。
- 反例：把 `e2e-pq-b` 的 `pqHybrid` 改 false 再 toggle → 两端 `failed` 且 `lastError` 点名；改回 → 重新 up（证明「谈崩」是可恢复状态而非死锁）。
- 每条断言按该文件的规矩写明「排除了哪种假通过」。

## 6. 风险与边界（**档一落地之后**要原样进 ARCHITECTURE 与页面文案）

> 本节描述的是**方案落地后**的形态与措辞，**不是现状**。今天 PQ 一行都没实现：开关 disabled、装载期拒绝、ARCHITECTURE 第七节按不实现列着。
> 在档一真正跑绿之前，把本节任何一句搬到页面或 README 上都构成虚假声称。

### 6.1 互通
- **只白帝↔白帝**。strongSwan 6.0 支持 RFC 9242/9370 + ML-KEM（同 IANA 码点），理论上可通，但**不做实机验证**，与既有 IPSec 边界同性质。而且 §0 顺带发现的 AAD-含-IV 意味着 GCM 路径与 strongSwan 本来就通不了——PQ 不会让互通更近，也不更远。
- RFC 9370 允许 ADDKE 里提 NONE 表示「可选」，本实现**不提、不认**：可选 = 静默降级的合法通道。

### 6.2 安全语义要说准
- **收益**：IKE SA 的 `SK_d` 混入 ML-KEM 秘密后，所有 Child SA 的 KEYMAT（`prf+(SK_d, …)`）与 IKE SA 重协商链（`prf(SK_d旧,…)`）都以它为根——记录全部报文并在未来攻破 ECDH 的攻击者仍拿不到任何 ESP 密钥。这是 harvest-now-decrypt-later 的完整防护。
- **PSK 认证本就抗量子**（对称），本方案不改认证。
- **不做 Child SA PFS 混合的代价**：攻击者若在 SA 存活期内**窃得 IKE SA 的 SK_d**（不是记录流量，是入侵内存），经典 PFS 本可让此前的 Child SA 密钥不可逆推——那层保护在量子对手面前是经典强度。这是「前向保密的抗量子性」而非「机密性的抗量子性」，页面要分清，别写成「全链路后量子」。
- 未经安全审计，与项目整体定位一致。ML-KEM 的正确性靠 Go 标准库（FIPS 203 定稿），白帝只做胶水，不碰任何多项式运算。

### 6.3 报文大小与「不实现 IKE 分片」的冲突（最实际的风险）
- IKE_INTERMEDIATE 请求 ≈ 28 + 4 + 8 + (4+4+1184) + 1 + 16 = **1249 B**，响应 ≈ 1153 B；加 UDP/IP 28 B 与 NAT-T 的 4 B marker → **~1281 B**。以太网 1500 / PPPoE 1492 能过；**IPv6 最小 MTU 1280 / 叠在别的隧道里（MTU 1400 以下常见）时会 IP 分片**，中间设备丢分片是常态。症状：IKE_SA_INIT 全绿、INTERMEDIATE 重传超时——比今天任何一种失败都更像「网络问题」。
- RFC 9242 的设计意图正是把大载荷放进可用 RFC 7383 分片的加密交换里，而白帝**明确不做 IKE 分片**（`const.go` 包注释、`EncryptSK` 那条拒绝）。取舍：**第一半不做分片**，用三件事补偿——① 只放 ML-KEM-768，**不放 1024**（ek/ct 各 1568 B，必分片）；② 失败文案点名大小与 MTU（§5.2 用例守着）；③ 文档与页面写死「需路径 MTU ≥ ~1300」。第三半若做 RFC 7383 才能把这条边界拿掉。
- CPU：ML-KEM-768 keygen/encaps/decaps 各约几十微秒，与 P-256 ECDH 同量级，忽略。带宽：每次 IKE SA 建立/重协商多 ~2.3 KB，忽略。DoS 面：INTERMEDIATE 要先完成 SA_INIT 的 DH 才能被响应方接受，成本对称，半开配额与 COOKIE 照旧覆盖。

### 6.4 实现坑（写进代码注释的候选）
- 隐式拒绝（§3.3）；`Encapsulate` 随机源不可注入；`siteFingerprint` 漏项；响应方派生新代密钥必须在 `respond()` **之后**；`onRequest` 白名单放行；IV 计数器不清零；rekey 的 `next` 半程失败只丢新不动旧。

## 7. 工作量分档与建议

| 档 | 内容 | 估算（含测试） | 拿到什么 |
|---|---|---|---|
| **一（建议做的那一半）** | §2.1 初始交换 + §2.2 IKE SA 重协商（IKE_FOLLOWUP_KE）+ 控制面/控制台/文档同批 | Go 约 1.0~1.4k 行（其中测试 ≥ 一半），4~6 人日 | ESP 全部密钥抗量子机密；页面 PQ 标签有真判据；边界诚实 |
| 二 | Child SA PFS 混合（CREATE_CHILD_SA(ESP)+FOLLOWUP_KE，`KEYMAT` 拼 `SK(1)`） | +1~2 人日 | 前向保密也抗量子（§6.2） |
| 三 | RFC 7383 IKE 分片 + 放开 ML-KEM-1024 | +2~3 人日，且要改 wire 层与重传语义 | 解掉 MTU 边界 |

**施工顺序建议（档一内部再分两半）**：先做**纯函数半**——`KeyExchange` 抽象 + `mlkem.go` + `DeriveAddKEKeys` + `IntAuth`/`intAuthParts` + `SuiteSpec.AddKE1`/`matchAddKE`/线格式，全部带快照与变异检查跑绿；再做**状态机半**——INTERMEDIATE 收发 + 已认证闸 + rekey follow-up + 双端用例 + e2e。理由与本仓其它子系统一致：派生与拼接错了不报错、只报「认证失败」，只有纯函数测得住；状态机半的每一步都能拿前一半的向量去二分。

**值不值得**：若目标是把「PQ」做成能在演示里如实说「白帝↔白帝 IKE SA 已做 ML-KEM-768 混合，ESP 密钥抗量子机密，边界如下」——**值得，做档一，停在档一**。若只是为了消掉页面上一个 disabled 开关——不值得，现状已是诚实形态，什么都不做即可。