# 白帝控制台 · 设计规范与套用手册

给逐页套用的同事看的操作手册。样板页是 `views/Apps.vue`（列表 + 抽屉表单）与 `views/Overview.vue`（KPI + 卡片组）——
先照着样板看一遍，再按第 3 节的清单改自己那页。**只改表现，不改行为 / 文案 / 数据绑定 / 失败转述。**

## 0. 三条硬纪律（先读）

1. **主题是 Arco 原生 ArcoBlue `#165DFF`**。自定义变量一律 `--bd-*`（`styles/tokens.css`），**不覆盖任何 Arco `--primary-*` / `--color-*`**；
   不要把烛龙的黏土橙配色带进来。
2. **每一句状态文案都要有执行方**。不许新增写死的「已完成 / 已启用 / 正常」；不许删掉或弱化任何「本版本未实现」的边界声明——
   打磨只能让它更好看（换成 `.bd-notice--warn`），不能让它消失。
3. **三态不许塌成二值**。`?? 0` / `?? false` 把「不可判定」变成确定值是禁止的；KPI 用 `StatCard`，`value` 传 `null/undefined` 它会画「—」。
   失败必须转述后端原话：`failReason(e)` / `failStatus(e)` 是唯一收口，`catch` 里不许编造归因。
   构建期守卫 `npm run check-ui` + `npm run type-check` **改完必须双绿**。`check-ui` 现在是**七条**规则：一 装饰性搜索框 / 二 死占位 /
   三 bare catch + 编造归因 / 四 nav.ts done 叶子必须在 router.ts BUILT 里 / 五 tokens.css 解析完整性 / 六 `var(--bd-x)` 必须有声明
   （**运行期声明也算**，见 §1）/ **七 Arco 图标名必须真的存在**（见 §1「图标名有守卫了」那段）。五、六、七守的都是同一个缺陷族：**type-check 与 vite build 全绿、
   浏览器零报错、功能是死的**——少一条线、没了底色、图标位置一块空白，与「设计上就是这样」完全同形。

## 1. Token（`styles/tokens.css`）——裸像素间距已从 1566 处收到 453 处，**没有清零**（余下见本节待收口第 5 条）

| 类别 | 变量 | 用法 |
|---|---|---|
| 间距 | `--bd-sp-1..8` = 4 / 8 / 12 / 16 / 20 / 24 / 32 / 40 | 卡片间距 `sp-4`；卡片内边距 `sp-4 sp-5`；页面区块间 `sp-6`。**不要写 14px / 18px / 22px 这类非 4 倍数** |
| 圆角 | `--bd-radius-xs` 4 / `-s` 7 / `--bd-radius` 10 / `-l` 14 / `-pill` | 标签用 xs；按钮、输入框、列表项用 s；卡片用默认；弹窗抽屉用 l |
| 阴影 | `--bd-shadow-1` 静置卡 / `-2` hover、下拉 / `-3` 弹窗抽屉；`--bd-shadow-primary` 主按钮 | 全仓此前 20 种手写阴影，**抬升档**只保留这四档（不等于"手写 `box-shadow` 已清零"，见表下注） |
| 字号 | `--bd-fs-xs` 11 / `-sm` 12 / `-md` 13（正文）/ `-base` 14 / `-lg` 16 / `-xl` 20（页标题）/ `-2xl` 28（KPI） | **禁止 11.5 / 12.5 / 13.5 半档**（此前 171 处） |
| 行高 | `--bd-lh-tight` 1.3 / `--bd-lh` 1.5 / `--bd-lh-loose` 1.7 | 标题 / 正文 / 说明段 |
| 动效 | `--bd-dur-fast` 120ms（颜色）/ `-base` 180ms（位移阴影）/ `-slow` 320ms（进度）+ `--bd-ease` | `transition: background var(--bd-dur-fast) var(--bd-ease)` |
| 焦点 | `--bd-focus-ring` / `--bd-focus-outline` | 全局已给所有可交互元素 `:focus-visible`，自绘控件用 `box-shadow: var(--bd-focus-ring)` |
| 语义色 | `--bd-success/-warning/-danger` + 各自 `-1`（浅底）`-b`（浅边）`-t`（深字） | 底 / 边 / 字**同一族配套用**；`--bd-info-*` 走主色族 |
| 中性 | `--bd-t1..t4` 文本四级；`--bd-border` / `--bd-border-2`（更淡的行线）；`--bd-fill-1..3`；`--bd-bg-1` 白 | 页面底 fill-1，控件底 fill-2，骨架/轨道 fill-3 |
| 控件 | `--bd-ctl-h` 32 / `-l` 36（主按钮）/ `-s` 28（表内）；`--bd-row-y` 12（表格行内边距） | |

**阴影那一格只对"抬升档"成立**：`grep -rnE 'box-shadow[[:space:]]*:' console/src --include='*.vue' --include='*.css' | grep -v tokens.css | grep -v 'var(--bd-shadow' | grep -v 'var(--bd-focus-ring'`
在 2026-09-07 22:13 仍有 **27 处 / 20 种去重值**，但里面只有 `BigScreen` 面板那条 `0 8px 30px rgba(0,0,0,.25)` 是真的抬升阴影
（深色大屏整页豁免，理由见它自己的 `<style scoped>` 开头）；其余是 `box-shadow: none` 复位（8 处，含一处 `!important`）、`0 0 0 Npx var(--bd-*-1)` 光环、
`inset 0 0 0 1px var(--bd-border)` 当描边用、以及 `BigScreen` / `PortalLogin` 深色区的霓虹辉光与呼吸光环——**这几种阶梯里本就没有对应档**。
写"只保留这四档"没问题，**别把它转述成"手写 `box-shadow` 已清零"**：照那句话去 grep 的人会当场看见 27 处。

`--bd-line` / `--bd-fill2` 是**拼写别名**（存量十余处引用此前根本没定义，样式静默失效）——新代码请写 `--bd-border` / `--bd-fill-2`。
tokens.css 的注释里不要写「星号+斜杠」字样（会提前结束注释、整个 `:root` 解析失败、全站 token 归零；type-check / vite build 不报，
`check-ui` 规则五会拦并给出行号）。规则五的下限 `MIN_BD_DECLS`（`scripts/check-dead-ui.mjs`）与 tokens.css 顶部注释里那句「不少于 N 条」
是**同一个数**，改一处要同步改另一处——它拦的是「归零」不是「少了两条」，别把它调成当前值。
**跨组件共用的 token 必须落 tokens.css**：规则六只判「这个名字在 src 下有没有声明」，不判「声明在这条引用的祖先链上是否可达」——
在某个组件的 scoped `<style>` 里声明一个 `--bd-xxx`、再在别的页面引用，守卫照绿而浏览器解不出来。
**运行期写进去的自定义属性现在也算「声明」**：`:style="{ '--bd-x': v }"`、`<script>` 里样式对象的 `'--bd-x':` 键、`el.style.setProperty('--bd-x', v)`
三种形状规则六都认——它们由 Vue / DOM 在运行期写成真实的自定义属性，而「自定义变量一律 `--bd-*`」这条硬纪律正要求把运行期变量也起成这个前缀。
此前守卫只认样式表那一种形状，谁按约定写了个运行期 `--bd-*` 再在 `<style>` 里 `var()` 它，就会被报成"未声明"——**一条会误报的守卫会被人习惯性忽略，
或者逼人把变量改成不带前缀的名字去躲它**，两种结果都比没有守卫更坏。

**门户壳**：`PortalBar.vue` 第二个非 scoped `<style>`（文件里第 79-111 行那块）承载 `.bd-portal / .bd-pmain / .bd-pwrap /
.bd-pwrap--narrow / .bd-pquit / .bd-phead* / .bd-psec*`，门户页面**不得再定义**这些类。
（上一版这份清单把 `.bd-pacct` 数了进来、又漏了 `.bd-psec*`：前者在第一个 **scoped** 块里、属于顶栏自己，后者才是门户四页天天在用的区块标题——
照上一版的清单去看，`.bd-psec__t` 会被当成"可以在页面里自己定义"的类。）
`PortalLogin.vue` 的根也叫 `.bd-portal`，而它**不引入本组件**，所以受约束的是 **PortalBar 那个非 scoped 块**：
它只许声明 PortalLogin 那份 scoped `.bd-portal` 也声明了的属性（min-height / background）——多写一项就串进登录页，
用户从门户页点「退出」后登录卡会掉到首屏之外（理由见 PortalBar 文件头注释）。
★**不要反过来去删 PortalLogin 那份的 `display: flex`**：它声明的是 display / min-height / background 三项，
左品牌区 + 右登录卡的并排布局正靠这一条；scoped 更特异，但也只盖得住它自己写了的这三项。

**图标名有守卫了（规则七），但它只是补丁**：图标是 `main.ts` 里 `app.use(ArcoVueIcon)` **全局注册**的，模板里的 `<icon-xxx>` 对 vue-tsc 只是一个任意
自定义元素，`'icon-xxx'` / `'IconXxx'` 字面量对它只是字符串——**三种写法 type-check 全绿**。浏览器里则是 Vue 解析不到组件、把它当原生自定义元素原样输出
`<icon-pulse></icon-pulse>`，那个位置就是一块空白。模板标签形式至少还伴随一条 `Failed to resolve component` 的 warn（侧栏「运维诊断」卡就这么空了几个月）；
而 `<component :is="'IconAppstore'">` 的**字面量形式连 warn 都没有**（`resolveDynamicComponent` 对字符串刻意不告警，headless 实测控制台零条）——**它比模板标签
形式更静默**。规则七按三种形状扫：① 模板里的 `<icon-xxx` 标签；② 引号里的 `'icon-xxx'`（kebab，`Auth` / `PortalApps` 经 `<component :is>` 用）；
③ 引号里的 `'IconXxx'`（`nav.ts` / `Diag` / `GlobalSearch` 的图标表），`.vue` 与 `.ts` 都扫，图标集取自 `node_modules/@arco-design/web-vue/es/icon` 的目录名。
★**结构性的修法不是守卫**：`nav.ts` / `Diag.vue` / `GlobalSearch.vue` / `Apps.vue` / `PortalApps.vue` / `Auth.vue` 那几张图标常量表用的是**字符串字面量 + `<component :is>`**，
对 tsc 完全不可见；照 `PortalDownloads.vue` 的做法 `import { IconXxx }` 之后把**组件对象**直接放进表里，写错名字 tsc 当场就报，规则七也就不需要了。
**本波没有做这个改造**——规则七是补丁，不是终局，别把它当成"图标这条已经收口了"。

**五条要写在这里的项：四条待收口 + 一条刚收口（写下来是为了别在报告里说成已解决、也别回退）**。
之所以先从两条扩到四条：只点名 15px 的话，这份手册会被引用成「半档已清零 / 裸十六进制已清零」两句**错话**——
前者要把 CSS 与 SVG **两种写法都核过**才刚变成真，**且只对 `.5` 结尾那一族成立**——同样卡在阶梯之间的 `15px` 还有 13 处（见下条），
线宽的 `1.5px` 则本就不在禁列；后者压根不成立（下表 89 行待收口）。
**这两条的数目自己也翻过车**：上一版给半档字号只写了一条只认 `px` 的 grep、给裸十六进制只数了 16 行（实测 101 行），
所以下面每条都把 grep 全文与复核时刻写进去——**清单里的数不写清怎么数出来的，下一个人就没法复核，只能照抄**。
**第 5 条（裸像素）是同一个坑的第三次**：上一版这一节的标题写的是「页面里不再出现裸像素」，而同一节的表格里正写着
「不要写 14px / 18px / 22px 这类非 4 倍数」——**标题宣称已清零，表格却在禁一批还剩 43 处的值**，且这一条既不在待收口清单里、
也从来没给过 grep 判据。方向确实是对的（1566 → 453，收掉七成），但**"收掉七成"和"不再出现"是两句话**，
后一句会被原样引用进报告。补这条时顺手把标题也改成了如实的表述。

- **两个几乎相同的深红**：`--bd-danger-t: #CB2634`（语义族里的"深字"，旧值）与 `--bd-danger-a: #CB272D`（危险按钮 active，Arco red-7）——肉眼分不出、
  用途也开始重叠。收口方向是让 `-t` 也取 Arco red-7 并删掉其中一个名字，但那要逐处核对深红文字在浅底上的对比度，**本波没做**。新代码按用途选：
  文字用 `-t`、按钮按下态用 `-a`，**不要**因为"看起来一样"就随手互换。
- **15px 这个非阶梯字号还在**：它卡在 `--bd-fs-base`(14) 与 `-lg`(16) 之间，属于第 1 节明令禁止的半档。全局层四处优先收——`app.css` 的
  `.bd-section-title` 与 `.bd-notice` 图标、门户壳 `PortalBar.vue` 的 `.bd-plogo__txt` 与 `.bd-psec__t`（它们影响面最大，一改就是全站/整个门户）；
  组件与页面 scoped 里另有若干同值（判据 `grep -rn 'font-size: 15px' console/src`，复核时刻 2026-09-07 21:14 = **13 处**；除上面点名的四处外，还散在
  `AppLayout` / `StatCard` / `Login` / `Apps` / `Audit` / `Users` / `PortalRequests` / `PortalSecurity` / `PortalLogin`）。**新写的样式一律不许再出现 15px**，存量那批留待专轨统一抬到 `-lg`
  或降到 `-base`——那是个要逐处看视觉重心的活，不能批量替换。
- **`.5` 结尾的半档字号：已清零（CSS 与 SVG 两种写法均已核）**（复核时刻 2026-09-07 21:23）。
  ★这条**不包含上一条的 `15px`**——那 13 处同样在阶梯之外，只是不带 `.5`，两条别合并成一句"半档已清零"。**判据是两条 grep，缺一不可**——
  上一版只跑了带 `px` 单位的那条，于是把 SVG 里的**无单位**写法整类漏在外面（`views/Ipsec.vue` 拓扑图那句
  `font-size="11.5"` 当时还在树上，而那份清单已经写着"已清零"）：
  ```
  ① CSS 写法   grep -rnE 'font-size:[^;]*[0-9]\.5px' console/src      → 0 命中
  ② SVG 属性   grep -rnE 'font-size="[0-9]*\.5"'      console/src      → 0 命中
  ```
  ②那条最后一处是 `Ipsec.vue` 站点拓扑图的副标题，本波已抬到 `font-size="12"`。**SVG 的 `font-size` 属性不带单位、
  按用户单位算，视觉上与 `11.5px` 一样是半档**——`.5px` 那条 grep 对它天然不命中，别拿单条 grep 下"已清零"的结论。
  收口前最后剩的 7 处 CSS 写法全在**顶栏组件**里——`components/GlobalSearch.vue` 5 处（`10.5` / `11.5`×3 / `12.5`）与
  `components/NotifyBell.vue` 2 处（`12.5`×2），现已全部换成 `--bd-fs-*`。之所以单列出来：这两个组件挂在 `AppLayout` 上，
  **21 个管理页每页都渲染**，它们从来不是"两个小组件的事"。**新写的样式一律不许出现 `.5` 字号（CSS 与 SVG 两种写法都算）**，
  这条从"待办"转成"别回退"。
  ★`grep -rnE '[0-9]\.5px' console/src` 仍会捞到 **5 行**：4 处是**线宽**不是字号（`NotifyBell` 角标 `1.5px` 描边 /
  `Apps` / `Security` 的 `1.5px` 边框、`DeviceStat` 的 `2.5px` 图例条），第 5 行是 `NotifyBell.vue` 注释里对那道描边的说明。
  第 1 节禁的是半档**字号**，`1.5px` 边框是 1px 与 2px 之间唯一的那一档，**别顺手一起改掉**。
- **裸十六进制远没有清零：全仓 101 行 / 152 处**（复核时刻 2026-09-07 21:23；轨 B 当时正在改 `Ipsec.vue`，故本条按**文件**计数、
  按**符号名**定位，不写行号）。统计口径就一条：
  ```
  grep -rnE '#[0-9A-Fa-f]{3,8}\b' console/src --include='*.vue' --include='*.ts' --include='*.css' | grep -v tokens.css
  ```
  上一版这条只点了 16 行（Apps / Audit / UserState / Online 四页的数据表），把 `Gateway.vue` 27 行、`BigScreen.vue` 28 行、
  `Ipsec.vue` 19 行整段漏在外面，也没落进它自己写的两条例外里——**一份会被引用的自陈清单说错数，比不写更坏**。按去向拆开是：

  | 归类 | 行 | 出处 | 例外？ |
  |---|---|---|---|
  | 注释正文里引述的旧值 | 4 | `app.css` ×2（幽灵+危险叠加的改前实测值 / 斑马纹旧裸值）、`StatCard.vue`（替代形态示例）、`GlobalSearch.vue`（"留一个裸 #fff 就是 21 页同时不合规"） | **是**：是文字不是色值 |
  | 遮罩几何的 `#000` | 6 | `BigScreen.vue` 三处 `-webkit-mask/mask: radial-\|linear-gradient(…, #000 …, transparent)` | **是**：`#000` 在这里是 alpha 停靠点（遮罩只看不透明度），换成主题 token 会改遮罩行为 |
  | `a-progress` 的 `:color` prop | 2 | `Ipsec.vue` 的 `lifePct` 三元、`Overview.vue` 的 `riskHex` | **是**：Arco 组件收的是**色值本身**而不是 CSS 类，改 token 要连 Arco 那侧一起验 |
  | 深色大屏自己的配色体系 | 22 | `BigScreen.vue`：`--c-*` 定义 2 行 + 盾牌标记 2 行 + 三个色值函数（`verdictColor`/`riskHex`/blips）3 行 + 标题渐变 1 行 + scoped 裸值 14 行 | **半是**：整页豁免 `--bd-*` 有文件内理由（`<style scoped>` 开头那段：浅色调色板套进墙屏会与霓虹青撞色），但那套 `--c-*` 只给 7 个色值起了名，**另外 20 行没进这套命名，是本页自己的待收口** |
  | `<script>` 里的数据表色值 | 23 | `Audit.vue` 11（`CAT_COLOR` 与 `catMeta` **两张表**，7 类各一色、整套出现两遍，外加两处 `?? '#…'` 兜底）、`Ipsec.vue` 7（`STATE_META` 七态）、`Apps.vue` 3（`APP_MODES` 三种发布形态各一对 `bg`/`color`）、`UserState.vue` / `Online.vue` 各 1（`palette` / `PALETTE`） | 否，**待收口**：搬进 tokens 或改语义类，不是就地换写法 |
  | SVG 架构图 / 拓扑图 | 38 | `Gateway.vue` 27（网关拓扑，含 `statusColor()`）、`Ipsec.vue` 11（站点拓扑，含 `stateColor()` 喂的 `:stroke`/`:fill`） | 否，**待收口**（理由见下） |
  | 品牌盾牌 SVG | 4 | `Login.vue` ×2、`Diag.vue` ×2（`fill="#fff"` + `stroke="#165DFF"`） | 否，**待收口**（理由见下） |
  | 既喂 prop 又喂 inline background | 2 | `Overview.vue` 的 `brand`（一处 `a-progress :color`，另一处是 `.bd-bar__fill` 的 inline background）与 `verdictColor`（纯 inline background） | 否，**待收口**：上一版把 `brand` 整个记成 prop 例外，漏了它的另一半用法 |

  合计 4 + 6 + 2 + 22 + 23 + 38 + 4 + 2 = 101 行。**真正的例外只有上表标"是"的三类**（注释文字 4 / 遮罩几何 6 / Arco `:color` prop 2），
  其余 89 行都是待收口——报告里别把它们说成"已清零"，也别把 SVG 整类划进例外。
  ★**"SVG 是图形资产所以不算"这条挡箭牌，上一版给得太宽**：`PortalBar.vue` 里同一枚盾牌已经写成
  `style="fill: var(--bd-on-color)"` / `style="stroke: var(--bd-primary)"`——**SVG 的 fill/stroke 走 `style` 就吃得到 `var()`**，
  所以同一枚盾牌在门户里是 token、在 `Login` / `Diag` 里还是裸 `#fff` / `#165DFF`，那是漏网不是资产。
  `Gateway` / `Ipsec` 那两张更不是装饰插画：它们**随实时数据变色**（`statusColor(n.online)` / `stateColor(r.vs)`），
  用的全是 Arco 中性色与语义色（`#1D2129` / `#86909C` / `#00B42A` / `#F53F3F` …），与 `--bd-t1` / `--bd-t3` / `--bd-success` / `--bd-danger`
  一一对得上。（`PortalLogin` 的左品牌区插画确实是纯装饰，但它现在一处裸十六进制都没有，不在这张表里。）
  ★**这条口径只管十六进制，「裸色值」比它大一圈**：`grep -rnE 'rgba?\([0-9]' console/src --include='*.vue' --include='*.css' | grep -v tokens.css`
  另有 47 行（`BigScreen` 40 = 深色体系里的辉光、网格线与面板底；`PortalLogin` 6 = 深色品牌区的半透明玻璃底与呼吸光环；
  `app.css` 1 = `.bd-notice code` 的浅底）。它们是**带 alpha 的叠加色**，token 表里本就没有这一档（语义族只给不透明的底/边/字三色），
  所以不算漏网；但报告里别把"裸十六进制 N 行"转述成"裸色值只剩 N 行"——那是两个口径。
- **裸像素间距：已从 1566 处收到 453 处，没有清零**（复核时刻 2026-09-07 22:21；轨 B/C 当时正在改 `.vue`，故按**处**计、不写行号）。
  ★**这几个数每小时都在动**：本条起草到复核的十几分钟里就从 451/98/1159 走到了 453/100/1162。所以**复核以命令的当次输出为准**——
  数字对不上不算这份清单说错话，**判据与结论**（没有清零、①那 43 处正是表格明令禁的三档）才是这条要钉住的东西。
  真正会变成错话的是"不再出现 / 已清零"这类**既没有数、也没有 grep 的断言**：它不随代码变，永远读起来像已完成。
  "改前"取 **HEAD**——`console/DESIGN.md` 本身还没入库，HEAD 的 `console/src` 就是这一波打磨的起点，两条判据只差 `git … HEAD` 与本地目录：
  ```
  改前（HEAD）  git grep -hoE '(^|[^a-z-])(margin|padding|gap|row-gap|column-gap|grid-gap)[a-z-]*[[:space:]]*:[^;{}"]*' \
                  HEAD -- 'console/src/*.vue' 'console/src/*.ts' 'console/src/*.css' \
                | grep -oE '[0-9]+(\.[0-9]+)?px' | wc -l                              → 1566
  改后（工作区，在 console/ 下跑）
                grep -rhoE '(^|[^a-z-])(margin|padding|gap|row-gap|column-gap|grid-gap)[a-z-]*[[:space:]]*:[^;{}"]*' \
                  src --include='*.vue' --include='*.ts' --include='*.css' \
                | grep -oE '[0-9]+(\.[0-9]+)?px' | wc -l                              → 453
  ```
  正则里 `[^;{}"]*` 是把匹配收在**一条声明内**（不越过 `;`、不跨出规则块、不吃掉 `style="…"` 的收尾引号），
  否则 `padding: 8px 14px; font-size: 14px` 那半条字号会被算进间距。**这条判据的每一段都做过变异实测**（同一时刻）：
  放开 `;` → 565（多算 112 处别的属性）、去掉属性名后的 `[a-z-]*` → 309（`margin-top` / `padding-left` 整类漏掉 144 处）、
  `--include` 只留 `*.vue` → 425（漏掉 `app.css` 那 28 处）；而放开 `{}` 与 `"`、去掉 `(^|[^a-z-])` 前缀**当前都还是 453**——
  它们是防御性的（挡"最后一条声明没写分号溢到下一条规则"与"`style="…"` 后面还有别的属性"），**现在没承重，别因此删掉**。
  这 453 处按档分四类，**互斥、合计 453**——把上面「改后」那条管道的**末段**换成下面四条之一即可各自复核
  （写成代码块而不是表格，是因为表格里的 `|` 得转义成 `\|`，照着抄进 shell 就跑不出来）：
  ```
  ① 14 / 18 / 22px           | grep -oE '\b(14|18|22)px' | wc -l                                    → 43
  ② 落在 4 倍数阶梯上         | grep -oE '[0-9]+px' | awk -Fpx '$1%4==0{n++} END{print n+0}'         → 58
  ③ 1~3px                    | grep -oE '\b[1-3]px' | wc -l                                        → 100
  ④ 其余（阶梯之间的小档）     | grep -oE '[0-9]+px' \
                               | awk -Fpx '$1%4!=0 && $1>3 && $1!=14 && $1!=18 && $1!=22' | wc -l    → 252
  ```
  | 档 | 处 | 例外？ |
  |---|---|---|
  | ① `14 / 18 / 22px` | 43 | **否**：本节表格逐字点名禁的就是这三档，而标题曾宣称已清零——这一条正是那句"错话"的出处 |
  | ② 4 倍数阶梯上（实测只用到 4/8/12/16/20/24/36/48/56/64/72） | 58 | **否**：值本身对，写的却是字面量而不是 `var(--bd-sp-*)`——**改阶梯改不到它们**。这批最该先收，也最机械可换 |
  | ③ `1~3px` | 100 | **是**：`margin-top: 2px` / `3px`（16+14 处）、`gap: 2px`、`.req` 星号的 `margin-left: 2px` 这类光学微调，**阶梯里本就没有这一档**——与上一条"`1.5px` 边框别顺手改掉"同一个理由 |
  | ④ 其余（5/6/7/9/10/11/13/17/34/86px） | 252 | **待定论**：大头是 `6px` 84 处（34 处是图标贴文字的 `gap`）与 `10px` 69 处（26 处是紧凑行的 `padding`），都卡在阶梯之间。要么逐处抬到阶梯上、要么给阶梯补 6/10 两档，**本波不定论**；新写的样式一律先按阶梯写 |

  同一时刻按文件排的前几名：`AppLayout` 46 / `Users` 45 / `BigScreen` 42 / `Auth` 31 / `app.css` 28 / `Security` 24 / `PortalLogin` 23。
  ★**"裸像素"另有一个大一圈的口径，两个数别混着说**：上面那条只管**间距族**（margin/padding/gap），而
  `grep -rnoE '[0-9]+(\.[0-9]+)?px' src --include='*.vue' --include='*.ts' --include='*.css' | grep -v tokens.css | wc -l`
  同时刻是 **1162 处**（HEAD 3120）。多出来的 709 处是线宽、宽高/定位尺寸、圆角、阴影偏移、媒体查询断点与 SVG 几何——
  **其中光 `1px` 就 137 处**（`grep -rnoE '\b1px' src --include='*.vue' --include='*.ts' --include='*.css' | grep -v tokens.css | wc -l`），
  绝大多数是 1px 描边：**线宽、断点、SVG 几何、具体宽高在阶梯里本来就没有对应档**，不属于这一条的待收口；
  字号那一族另见上面两条（15px 13 处 / `.5` 已清零），**别重复计**。
  ★**本节标题里那两个数（1566 / 453）与本条同源同一时刻**，改一处必须同步改另一处——与 `MIN_BD_DECLS` 和 tokens.css 顶部注释那条同款纪律。
  之所以把数写进标题：上一版的标题是一句不带判据的断言（"不再出现裸像素"），**没有数就没人会去核**，于是它在这份手册里活到了第二轮复核。

## 2. 每类元素用什么

| 元素 | 用 | 不要再用 |
|---|---|---|
| 页头 | `<PageHeader title subtitle :live>`，右侧动作放默认插槽；离线文案按本页真实处境传 `off-text`（有演示数据「降级演示」/ 拉不到就不画的页「数据未读取」+ `off-color="red"`）；`live` 不传 = 不画连接标签 | 手写 `.bd-page__head` + `<a-tag :color="live ? 'green' : 'orange'">` |
| KPI 数字 | `<StatCard label :value unit foot tone>`；`value=null` 自动画「—」+ `unknown-text`；进度条放 `#extra`；**只在真有历史时传 `trend`**；兼作筛选入口时 `clickable` + `:active`（选中描边在组件里） | `.bd-kpi` / `.bd-mcard` / `.bd-agg` 各自一套字号 + inline 十六进制 |
| 空态 | `<EmptyState title desc size tone>`：`sm` 嵌表格行或侧栏、`md` 卡片内、`lg` 整页；`tone`：`neutral` 确实没有 / `ok` 没有待办是好事 / `warn` 缺配置或缺上报 / `danger` **读取失败（这不是「没有」）**；主动作放 `#action`。表格里包一层 `<tr class="bd-table__emptyrow"><td colspan=N>` | `<td class="bd-empty">暂无数据</td>` 一行灰字；也不要一句适用所有页的"暂无数据" |
| 首屏加载 | `<SkeletonBlock kind="table|card|stat|text" :rows :cols>`，用 `loaded` 标志在第一次 `load()` 完成前占位 | 空白闪 / 先画 MOCK 再整屏替换（那一瞬显示的是假数） |
| 卡片 | `.bd-card`（+ `.bd-card--pad` 内边距 / `.bd-card--hover` 可点抬升）；带标题用 `.bd-card__h` + `.bd-card__h-sub` + `.bd-card__h-right`，正文 `.bd-card__b` | `<a-card :bordered="false" title>` + 页内 `border-radius: 10px` |
| 表格卡 | `.bd-tablecard` > `.bd-toolbar`（`.bd-toolbar__c` 计数 / `.bd-toolbar__spacer` / `.bd-searchbox` 搜索）> `table.bd-table`；表头已粘性；可加 `.bd-table--zebra`（长表无行内操作）/ `.bd-table--dense`（审计、会话） | 页内重写 th/td 的 padding、字号、行线 |
| 操作列 | `<span class="bd-acts"><button class="bd-link">编辑</button><button class="bd-link bd-link--danger">删除</button></span>`——真 `<button>`（可 Tab、可回车、有禁用态） | `<span class="bd-link" @click>` + `style="margin-left: 12px"` |
| 按钮 | `.bd-btn`（主）/ `--ghost` / `--danger` / `--sm`；禁用直接写 `:disabled`，三态与禁用态全局已给。**次要的危险操作**（审批页的「驳回」）写 `.bd-btn--ghost.bd-btn--danger`：白底红边红字，hover 浅红底，active 再深一档——叠加态在 app.css 里有专门一组规则，两个单类叠出来的不是它 | `:style="{ opacity: cond ? 1 : .5 }"` 手写禁用；`.bd-mbtn` 之类页内再造一套；为「驳回」再造一个红字幽灵按钮类 |
| 标签 | `.bd-tg .bd-tg--blue|green|red|gold|purple|grey`；状态点 `.bd-st .bd-st--ok|warn|bad|off` | `:style="tagStyle('#F53F3F')"` |
| 提示条 | `.bd-notice`（默认 info 蓝）/ `--plain` 中性口径说明 / `--warn` 注意但不阻断 / `--danger` 出错、拒绝、数据缺失 / `--success`；结构 `图标 + <span 或 .bd-notice__body>`，右侧动作 `.bd-notice__right` | 各页自造 `.bd-scopebar / .bd-sync / .bd-unk / .bd-wz__warn / .bd-catmgr__hint` |
| 抽屉表单 | 字段 `.bd-fld > label + 控件 + .bd-fld__d`（说明）/ `.bd-fld__err`；必填星号 `<i class="req">*</i>`（全局已抹平斜体）；两列 `.bd-fld-grid`；分节 `.bd-form-sec`；底栏 `.bd-drawer__foot`（`.bd-drawer__foot-spacer` 把主操作推到右边） | `.bd-wz__foot` + `<div style="flex:1">`；给 label 单写 margin |
| 弹窗 | `<a-modal>` 正文全局限高 `.arco-modal-body { max-height: calc(100vh - 220px) }`（Arco 头 48 + 原生脚 65 + 上下呼吸位），超出在正文里滚；`:footer="false"` 时把 `.bd-drawer__foot` 写在正文**末尾**，它在弹窗体内是 sticky 的——「取消 / 创建」在 1280×800 下始终可见 | 页内给 `.arco-modal-body` 另写高度；把底栏放进正文中间或包进别的滚动容器（sticky 只对最近的滚动祖先生效） |
| 页签 | `.bd-tabs[role=tablist]` > 真 `<button type="button" class="bd-tab" role="tab" :aria-selected="tab === 'x'">`；**选中态只认 `aria-selected="true"`**（不再写 `.on` / `.is-on`），条目计数放 `<em>`，待办计数放 `<span class="bd-badge">`；放进 PageHeader `#below` 时加 `.bd-tabs--flush`；焦点环走全局 `:focus-visible` | 页内 scoped 一份 `.bd-tabs/.bd-tab`（此前 11 页各一份，em 字号 / 间距 / 是否 inline-flex 各有出入）；`<span class="bd-tab" @click>`；`:class="{ on: … }"` 与 `aria-selected` 双写 |
| 区块标题 | `.bd-section-title`（可带 `.bd-section-title__sub`），全局已定义 | 页内 scoped 再定义一份（Auth / Gateway / System 各有一份，Overview 用了却没定义） |
| 左窄栏 + 右主体 | `.bd-two` > 左 `.bd-card` 定宽 + 右 `.bd-two__main` | `style="flex: 1; min-width: 0"` |
| 不可判定数 | `.bd-unknown`（灰、细）或直接用 StatCard | 让「—」长得像 0，或写 `?? 0` |

## 3. 逐页套用步骤（改前 / 改后对照清单模板）

复制下面这张表到你的报告里，每页一份，逐行填「改前 file:line → 改后」：

```
页面：views/Xxx.vue                                    视口截图：1440x900 ✔ / 1280x800 ✔
| 项 | 改前（file:line 或截图证据） | 改后 | 行为/文案是否改变 |
|---|---|---|---|
| 页头 | 手写 .bd-page__head + a-tag（L3-L12） | <PageHeader :live off-text="…"> | 否 |
| KPI | .bd-xxx__num 字号 26 + inline #F53F3F | <StatCard tone="danger"> | 否 |
| 空态 | <td class="bd-empty">暂无…</td>（L239） | <EmptyState size="md" title="…" desc="…"> | 否（文案沿用原句） |
| 首屏 | 无（表头下空白 ~0.5s） | <SkeletonBlock kind="table"> + loaded 标志 | 否 |
| 提示条 | .bd-sync / .bd-unk 自造（L30/L49） | .bd-notice / .bd-notice--warn | 否 |
| 页签 | scoped .bd-tabs/.bd-tab + :class="{ on }"（L397-405） | 删 scoped，模板只留 role="tab" :aria-selected（全局 .bd-tab 认它） | 否 |
| 抽屉表单 | .bd-fld 页内定义 + <div style="flex:1"> | 删页内定义（全局已有）+ .bd-drawer__foot | 否 |
| 间距/圆角/阴影/字号 | 12.5px ×N、9px 圆角、手写阴影 | 全部换 --bd-* | 否 |
| 删掉的 scoped 规则 | .bd-link--danger / .bd-two / button.bd-link / .bd-fld* （已全局） | — | 否 |
| 守卫 | npm run check-ui ✔  npm run type-check ✔ | | |
```

操作顺序：① 先跑一遍 `npm run check-ui && npm run type-check` 拿基线；② 换页头 → KPI → 空态 → 骨架 → 提示条 → 表单 → 最后清 scoped 样式里已全局化的类与裸像素；
③ 每一步用浏览器在 1440 与 1280 各看一眼；④ 收工双绿 + `git diff --stat` 只出现自己那页。

**禁止事项**：新增写死的状态文案；删弱「未实现」声明；`?? 0`；`catch {}` + 编造归因；页内再定义已全局的类（含 `.bd-tabs/.bd-tab`、StatCard 的 `.is-on`）；inline 十六进制色；
`overflow: hidden` 包表格（会让粘性表头失效，用 `overflow: clip`）；给 `body`/Arco 变量写值。

## 4. 两种视口的布局规则

- **1440×900**：内容区约 1180px。KPI 一行 4 张（`grid-template-columns: repeat(4, minmax(0,1fr))`）；三卡 `repeat(3,…)`；左窄栏 210~246px。
- **1280×800**：内容区约 1020px。`@media (max-width: 1320px)` 下：页面左右内边距自动收到 20px（app.css 已给）；KPI 收成 2×2；
  左窄栏收到 184px、搜索框 200px（见 Apps.vue 的媒体查询）；页头右侧动作 `flex-wrap`，不许溢出。
- 两种视口下都**不许出现横向滚动**；表格列多时给 `.bd-tablecard` 里的 table 一层 `overflow-x: auto` 容器，别让整页滚。
- 卡片间距恒为 `--bd-sp-4`（16），区块之间 `--bd-sp-6`（24）；页头到内容 `--bd-sp-5`（20）。
- 单页只有一个 `h1`（PageHeader 给），区块标题用 `.bd-section-title`，卡片标题用 `.bd-card__h`——三级不要混。

## 5. 组件 API 速查

```vue
<PageHeader title="应用管理" subtitle="…" :live="live" off-text="降级演示" off-color="orange">
  <button class="bd-btn">主动作</button>        <!-- 默认插槽 = 右侧动作 -->
  <template #subtitle>带链接的副标题</template>  <!-- 可选，替代 subtitle -->
  <template #below>页头下方整行（tabs 等）</template>
</PageHeader>

<StatCard label="在线会话" :value="unknown ? null : n" unit="/ 8" foot="当前活跃接入"
  unknown-text="无网关上报心跳，接入数不可判定" tone="danger" :trend="{ dir: 'up', text: '+3' }" clickable
  :active="filter === 'online'">   <!-- 兼作筛选入口时：当前生效的那张传 :active，主色描边由组件画，页面不再写 .is-on -->
  <template #badge>右上小标签</template><template #extra>进度条</template><template #foot>富文本脚注</template>
</StatCard>

<EmptyState size="md" tone="warn" title="尚无网关经 mTLS 注册" desc="以 -control 指向本控制面…">
  <template #icon><icon-xxx /></template><template #action><button class="bd-btn">去配置</button></template>
</EmptyState>

<SkeletonBlock kind="table" :rows="5" :cols="6" />   <!-- card / stat / text -->
```

## 6. 样板改前 / 改后（本次已做）

- `views/Apps.vue`：页头 → PageHeader；无空态（筛选到零条只剩表头）→ 三种处境各一条 EmptyState（搜索无命中 / 分类为空 / 未发布），读取失败 → `tone="danger"` 并转述后端原话；
  首屏 → SkeletonBlock；操作列 `<span @click>` + `margin-left:12px` → `.bd-acts` 真按钮；三处 `:style opacity` 手写禁用 → `:disabled`；
  五种自造提示条 → `.bd-notice`；`.bd-wz__foot` → `.bd-drawer__foot`；scoped 里 8 组已全局化的类删除；`--bd-line`（未定义）→ `--bd-border`。
- `views/Overview.vue`：4 张 `a-card.bd-kpi` → StatCard（在线会话的不可判定态由组件承接）；`.bd-section-title` 从"未定义"变为全局定义；
  `a-grid` → CSS grid（1280 下 KPI 自动 2×2）；`a-card title` → `.bd-card__h`；口径说明条 `background: var(--bd-fill2)`（未定义、静默透明）→ `.bd-notice--plain`；
  首屏先画 MOCK 再替换 → 骨架；风险分颜色 inline 十六进制 → `--bd-*` 语义类；攻击趋势柱色 `#F53F3F` → `--bd-danger`。
