<template>
  <div class="cn">
    <div class="cn__top">
      <div>
        <div class="cn__hi">你好，{{ session.user || '访问者' }}</div>
        <div class="cn__net">{{ stageLabel }} · {{ platformLabel() }}</div>
      </div>
      <span class="cn__pill" :class="stage">{{ stageDot }}</span>
    </div>

    <!-- 接入大环 -->
    <div class="cn__hero">
      <!-- ★大环在「未就绪」态下**必须仍可点**：那时隧道已经下发、系统状态栏的 VPN 钥匙亮着、
           数据面正以当前账号每 15s 保活，用户唯一想做的事就是把它关掉。禁用它等于让大环变成
           死键，人只能去杀进程。 -->
      <button class="cn__ring" :class="stage" :disabled="stage === 'connecting'" @click="toggle">
        <div class="cn__ring-in">
          <component :is="ringIcon" class="cn__ico" />
          <div class="cn__act">{{ ringAct }}</div>
          <div class="cn__hint">{{ ringHint }}</div>
        </div>
      </button>
    </div>

    <!-- 接入步骤（接入中显示） -->
    <div v-if="stage === 'connecting'" class="m-card cn__steps">
      <div v-for="(s, i) in STEPS" :key="s" class="cn__step" :class="{ done: i < step, doing: i === step }">
        <span class="cn__step-dot"><icon-check v-if="i < step" /><icon-loading v-else-if="i === step" /></span>
        {{ s }}
      </div>
      <!-- 接入中就把数据面**已经报出来**的失败原因显示出来。
           ★为什么需要它：桥的启动期轮询要等满 30s 才 resolve（敲门每 15s 重试一次，30s 正好覆盖
           两次，提前判死就把「第二次敲成功」的自愈路堵了——那 30s 不能缩）。但数据面在 t+1s 左右
           就已经把原因写进健康行了，2026-09-03 真机实测：用户要盯着转圈**33 秒**才看到
           「本机不信任控制中心的 HTTPS 证书」。这里只是提前**转述**，不改任何状态机：
           大环仍在「正在接入」，仍然等桥给终态，仍然允许自愈。 -->
      <div v-if="connectingWhy" class="cn__steps-why">
        数据面报告：{{ connectingWhy }}
        <span class="cn__steps-why-n">（敲门每 15 秒重试，仍可能自行恢复，故这里继续等）</span>
      </div>
    </div>

    <!-- 未就绪：引擎在跑、门没敲开。**常驻**而不是弹一条 Message——一闪而过的 toast
         在用户切回来时已经没了，而这条状态可能持续几分钟（敲门每 15s 重试）。
         原因原样转述数据面健康行，不改写：「x509: certificate signed by unknown authority」
         指得动管理员去装 CA，换成一句自编的「网络异常」只会把人支去重启手机。 -->
    <div v-if="stage === 'unready'" class="m-card cn__unready">
      <b>隧道已下发，但数据面未就绪</b>
      <div class="cn__unready-r">{{ session.notReady || '（原生侧未报告原因）' }}</div>
      <div class="cn__unready-n">
        引擎仍在运行，敲门每 15 秒自动重试——可能自行恢复，故这里<b>不会替你断开</b>；
        此刻隧道类应用访问不到。要停止请点上方大环。
      </div>
    </div>

    <!-- 上一次接入**没建立起来**的原因。常驻到下一次接入为止。
         ★为什么不能只靠 Message.error：本页 dropReason 那条注释里就写着「弹窗一闪而过不算看见」，
         而这里的方向此前恰好是反的——「未就绪」（可自愈的中间态）有常驻卡片，
         「接入被拒」（定性拒绝，不会自愈，用户必须去找管理员或修自己的机器）反而只有一闪而过的提示。
         2026-09-03 真机实测：li.fang 被终端合规闸拒（那台 Windows 验证机没开 BitLocker，
         而这道闸按**账号**判、不分设备），用户看到的是大环回到「未接入」、屏上什么都不剩。
         与 dropReason 分开：那条说「上一段接入不是你断的」（隧道曾经建起来过），
         这条说「这一次压根没建起来」，用户的下一步动作不同。 -->
    <div v-if="stage === 'idle' && lastFail" class="m-card cn__fail">
      <b>上一次接入没有建立</b>
      <div class="cn__unready-r">{{ lastFail }}</div>
      <div class="cn__unready-n">
        原因由控制中心或原生侧给出，此处原样转述、不做改写。
        「接入被拒」属于定性拒绝（强制下线 / 账号禁用 / 终端环境不合规），重试无用，请联系管理员。
      </div>
    </div>

    <!-- 隧道类当前失败（健康行 terr=）。**与就绪判定无关，故必须另立一格常驻**：
         wave10 把就绪判据收紧成敲门类的 knockErr 之后，一次持续性的隧道故障
         （指纹不匹配「疑似中间人」/ 网关装了隐身规则集却没带 -pf → 放行集合永远为空 /
         gm 开关与网关不一致）不再翻接入态——门确实敲开了，但这条隧道拉不起任何业务流。
         不显示它就又造出一种「界面写着已接入、而什么都访问不到」。
         措辞刻意不说"已断开"：它是可恢复的，隧道拨通一次就自行清掉。 -->
    <div v-if="session.tunnelNote" class="m-card cn__tnote">
      <b>隧道拨号失败（门已敲开，业务流量走不通）</b>
      <div class="cn__unready-r">{{ session.tunnelNote }}</div>
      <div class="cn__unready-n">
        这一格与「已接入」并不矛盾：敲门与拨隧道是两件事，前者过了后者仍可能失败。
        隧道每次访问应用时重试，拨通一次即自动消失。
      </div>
    </div>

    <!-- 接入信息（真实来自当前接入配置）。未就绪态同样要显示：那正是用户要拿去排障的一屏。 -->
    <div v-if="stage === 'connected' || stage === 'unready'" class="m-card cn__info">
      <div class="cn__info-row"><span>安全网关</span><b class="m-mono">{{ ti.gateway }}</b></div>
      <!-- 算法名后面必须跟上「有没有认证网关身份」：只写 SM2/SM4-GCM/SM3 读起来
           比钉扎那档还强，而移动端此前恰恰是零认证的那一档（Config 里连 pin 字段都没有）。 -->
      <div class="cn__info-row"><span>隧道加密</span><b :class="{ ok: ti.pinned }">{{ ti.cipher }}</b></div>
      <div class="cn__info-row"><span>可达资源</span><b>{{ ti.resources ? ti.resources + ' 项（经资源映射鉴权）' : '（无资源映射）' }}</b></div>
      <!-- 同桌面端：只说本机敲门状态，不替网关断言隐身效果（客户端拿不到那份回执，
           而参考部署默认不开 -pf，未敲门的 TCP 仍会被 nmap 判 open）。
           ★这一行改造前写死 `<b class="ok">已完成 · 已开放行窗口</b>`：2026-09-03 安卓真机上
           健康行是 `knock=false … x509: certificate signed by unknown authority`，它却仍然
           打着绿字说敲门已完成——**与健康行完全相反的一句断言**，判据改对了它照样撒谎，
           所以必须一起摘掉。现按数据面健康行**现算三态**（对照桌面端 Connect.vue 的做法）：
           读不到健康态时是「不可判定」，不是「已完成」。 -->
      <div class="cn__info-row"><span>SPA 敲门</span><b :class="knockView.cls">{{ knockView.text }}</b></div>
      <div class="cn__info-row"><span>受保护网段</span><b class="m-mono">{{ ti.route }} → 隧道</b></div>
      <div class="cn__info-row"><span>虚拟 IP</span><b class="m-mono">{{ ti.vip }}</b></div>
      <!-- 剖面拉不到时的降级必须当面说：这种接入多半是"隧道起来了却什么都访问不了"。 -->
      <div v-if="profileErr" class="cn__warn2">
        接入剖面未取到（{{ profileErr }}），本次使用「我的」页手填配置：
        网关落点 / 受保护网段 / 资源映射 / 证书指纹均非控制面下发，业务多半访问不到。
      </div>
    </div>

    <!-- 上一段接入不是用户断的（被抢占 / 被系统回收 / 引擎停机）：原因由 vpn.ts 的监视写进
         session.dropReason。此前这些原因只有原生侧的写端、没有 webview 侧的读端——用户看到的是
         纹丝不动的「已接入」。留在这里直到下一次接入，弹窗一闪而过不算「看见」。 -->
    <div v-if="stage === 'idle' && session.dropReason" class="m-card cn__drop">
      <b>上一次接入已中断</b>：{{ session.dropReason }}
    </div>

    <!-- 终端环境检测：移动端**尚未实现采集**，如实说明而不是画一张全绿的卡片。
         此处此前是四行硬编码 ok:true（磁盘已加密 / 未越狱 / 版本合规 / 客户端最新），
         对着一台从没被检测过的手机显示「终端安全检测 合规」——而合规判定权在控制面，
         它对这台设备根本没有任何数据。 -->
    <div v-if="stage === 'idle'" class="m-card cn__posture">
      <div class="cn__posture-h"><icon-safe /> 终端安全检测 <em class="na">未采集</em></div>
      <div class="cn__na">
        移动端暂未实现终端环境采集：原生 VPN 扩展只暴露了建立/断开隧道的接口，
        webview 侧读不到磁盘加密、越狱、系统版本等状态。
      </div>
      <div class="cn__na">
        因此控制面对本机按<b>缺报</b>处理——默认（observe）放行；
        若管理员开启了 <code>BAIDI_POSTURE_ENFORCE=strict</code>，本机将<b>无法接入</b>。
        桌面客户端已实现三平台真实采集。
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onUnmounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import {
  IconPoweroff, IconCheckCircleFill, IconCheck, IconLoading, IconExclamationCircleFill
} from '@arco-design/web-vue/es/icon';
import { session, validateConfig } from '@/lib/store';
import { startTunnel, stopTunnel, platformLabel, tunnelInfo, loadProfile, tunnelStatus } from '@/lib/vpn';
import type { TunnelStatus } from '@/lib/tunnelwatch';

// ★「终端环境检测上报」这一步已删除：移动端根本没有采集能力（见模板里的说明），
// 而它此前是一句 `await sleep(500)` 假装出来的——进度条走过一步，什么都没发生。
// 其余三步里只有「SPA 敲门」是本 UI 真发起的；后两步由原生扩展在自己进程里完成，
// webview 拿不到进度回报，故按固定节奏推进（见 connect() 里的说明）。
const STEPS = ['SPA 敲门（单包授权）', '建立国密 TLCP 隧道', '下发策略 / utun 引流'];
const ti = computed(() => tunnelInfo());
/**
 * 大环四态。★第四态 'unready' = **引擎在跑、门没敲开**（真机实测：stage=up 而
 * knock=false + x509 证书校验失败），改造前这种情况一路走到「已接入企业内网」。
 * 它与 idle 的区别是「隧道确实下发了、还在保活」，与 connected 的区别是「什么都访问不到」。
 */
const stage = ref<'idle' | 'connecting' | 'connected' | 'unready'>(
  session.connected ? 'connected' : session.notReady ? 'unready' : 'idle'
);
const step = ref(0);
const stageLabel = computed(() => (
  stage.value === 'connected' ? '已接入企业内网'
    : stage.value === 'connecting' ? '正在接入'
      : stage.value === 'unready' ? '已下发 · 未就绪' : '未接入'));
const stageDot = computed(() => (
  stage.value === 'connected' ? '● 在线'
    : stage.value === 'connecting' ? '◐ 连接中'
      : stage.value === 'unready' ? '◐ 未就绪' : '○ 离线'));
const ringIcon = computed(() => (
  stage.value === 'connected' ? IconCheckCircleFill
    : stage.value === 'unready' ? IconExclamationCircleFill : IconPoweroff));
const ringAct = computed(() => (
  stage.value === 'connected' ? '已接入'
    : stage.value === 'connecting' ? '接入中…'
      : stage.value === 'unready' ? '未就绪' : '点击接入'));
const ringHint = computed(() => (
  stage.value === 'connected' ? '点击断开'
    : stage.value === 'unready' ? '门未敲开 · 点击断开' : '企业内网 · 先认证后连接'));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * 原生健康快照的本页缓存。**刻意不再开第二个轮询器**：全局唯一的轮询在 vpn.ts 的监视里，
 * 它每轮把结论写进 session（connected / notReady / dropReason）；这里只在那三个信号变动时
 * 各重读一次快照即可——健康行的原文变了 notReady 也跟着变，所以不会漏刷。
 */
const snap = ref<TunnelStatus | null>(tunnelStatus());
function refreshSnap() { snap.value = tunnelStatus(); }

/**
 * 接入中「数据面已经报出来的原因」。空 = 还没有可说的。
 * 取值顺序与 notReadyReason 一致（knockErr 优先：挡住门的就是它那一格）。
 */
const connectingWhy = computed(() => {
  const s = snap.value;
  if (!s || s.healthObserved !== true) return '';
  return (s.healthKnockErr || s.healthErr || '').trim();
});

/**
 * 接入中的短轮询。**这是全页唯一的例外**，与上面「不再开第二个轮询器」并不冲突：
 * 它只在 connecting 这个最多 30 秒的窗口内活着（connect() 结束即 clear），只读不写任何 session 字段，
 * 存在的唯一理由是让已知原因早 30 秒上屏。接入之后的长期监视仍然只有 vpn.ts 那一个。
 */
let connTimer: ReturnType<typeof setInterval> | null = null;
function startConnectingPoll() {
  stopConnectingPoll();
  connTimer = setInterval(refreshSnap, 1000);
}
function stopConnectingPoll() {
  if (connTimer !== null) { clearInterval(connTimer); connTimer = null; }
}
onUnmounted(stopConnectingPoll);
watch([() => session.connected, () => session.notReady, () => session.dropReason,
       () => session.tunnelNote], refreshSnap);

/**
 * SPA 敲门的三态。★先判「有没有读到健康行」再判真假：健康态不可判定时（iOS / 鸿蒙壳 /
 * 旧安卓包不报这组键）healthKnock 恒缺席，直接看真假会把「探不到」画成「没敲开」，
 * 反过来写死成绿字则是替一份根本没读到的健康行背书——真机上正是后者在撒谎。
 */
const knockView = computed<{ cls: string; text: string }>(() => {
  const s = snap.value;
  if (!s || s.healthObserved !== true || typeof s.healthKnock !== 'boolean') {
    return { cls: 'na', text: '不可判定（本端未报告数据面健康状态）' };
  }
  if (s.healthKnock) return { cls: 'ok', text: '已完成 · 已开放行窗口' };
  const why = (s.healthKnockErr || s.healthErr || '').trim();
  return { cls: 'bad', text: why ? '未完成 · ' + why : '未完成（原生侧未报告原因）' };
});
/** 接入前拉剖面失败的原因。非空时接入信息卡上会当面写出来——退回手填配置的接入
 *  多半是半成功状态（无资源映射 → 发不出 CONNECT 前导 → 网关 fail-closed）。 */
const profileErr = ref('');

/** 上一次接入失败的原因（常驻到下一次接入）。**刻意是页内 ref 而不是 session 字段**：
 *  它只在「接入」页有意义，塞进全局 session 会多出一个要在登出、断开、认领三处各清一遍的字段。 */
const lastFail = ref('');

/**
 * 会话侧两个事实 → 大环状态的映射。写端只有一个（vpn.ts 的监视），这里是读端。
 *   · connected 翻真 —— 门敲开了（可能是接入那一刻，也可能是未就绪之后**自愈**）；
 *   · connected 假 + notReady 非空 —— 引擎在跑、门没敲开；
 *   · 两者皆假 —— 隧道没了（被抢占 / 被回收 / 引擎停机，原因在 dropReason）。
 * 「接入中」期间不插手：那段由 connect() 自己按步骤推进。
 */
watch([() => session.connected, () => session.notReady], ([conn, nr]) => {
  if (stage.value === 'connecting') return;
  if (conn) {
    // 未就绪自愈成功才是真正的「接入完成」，收尾提示留到这一刻发；
    // 正常路径里 connect() 已先把 stage 置成 connected，这里判等号即可避免重复弹。
    if (stage.value !== 'connected') { stage.value = 'connected'; Message.success('已接入企业内网'); }
    return;
  }
  if (nr) { stage.value = 'unready'; return; }
  if (stage.value === 'connected' || stage.value === 'unready') stage.value = 'idle';
});


function toggle() {
  // 未就绪也必须能断：那时 VPN 已下发、仍以当前账号保活，不给断开路径等于把大环变成死键。
  if (stage.value === 'connected' || stage.value === 'unready') return disconnect();
  if (stage.value === 'idle') return connect();
}

async function connect() {
  const bad = validateConfig();
  if (bad) { Message.warning(bad); return; }   // 接入前配置校验（端口/网段/虚拟IP/控制中心）
  stage.value = 'connecting'; step.value = 0; session.dropReason = ''; session.notReady = ''; lastFail.value = '';
  startConnectingPoll();
  // ★接入前拉一次接入剖面。移动端此前**全仓零处**拉它，接入配置全靠用户在「我的」页手填——
  //   于是网关落点、受保护网段、资源映射、证书指纹一概由终端自己猜，而只有控制面
  //   同时知道这四样。拉不到不阻断（退回手填配置），但要把原因说出来：那种接入多半是
  //   「隧道起来了却什么都访问不了」——无 resmap 就发不出 CONNECT 前导，而网关对
  //   无前导连接是 fail-closed 的。
  profileErr.value = await loadProfile();
  // ① SPA 敲门 —— 这一步是**真的**：携带 JWT 身份，原生壳里交给 VPN 扩展发包，
  //    dev 浏览器里经 knock-agent 发真实 SPA 单包。
  const r = await startTunnel(session.token);
  refreshSnap();
  if (!r.ok) {
    // ★失败有两种，处置完全不同：
    //   ① 引擎压根没起来（用户拒绝 VPN 授权 / 网段非法 / 超时）—— 回 idle，报错，收工；
    //   ② 引擎起来了、门没敲开 —— vpn.ts 已经把它认下来并开始监视（notReady 非空），
    //      这里要停在「未就绪」而**不弹「已接入企业内网」**：真机上改造前正是弹了那一句，
    //      而同一时刻健康行写着 knock=false。原因常驻在下面那张卡片上。
    stopConnectingPoll();
    if (session.notReady) { stage.value = 'unready'; return; }
    stage.value = 'idle';
    // 前缀刻意中性：startTunnel 的失败不只有敲门——原生侧点名的「用户拒绝了 VPN 授权」
    // 「受保护网段配置无效」都从这里出来，冠以「SPA 敲门失败」会把用户支去查网关。
    lastFail.value = r.detail || '网关不可达';
    Message.error('接入失败：' + lastFail.value);
    return;
  }
  // ②③ 建隧道与引流由原生扩展在自己的进程里完成，webview **收不到分步进度**：
  //    桥的 tunnelStatus 只有 idle/starting/up/failed 四态（安卓 startTunnel 的 Promise 就是
  //    轮询它到 up 才 resolve 的），没有「隧道已建、引流未起」这种中间态。这里按固定节奏
  //    推进进度条，是展示性的——不代表这两步各自何时真正完成。接入之后的存活由
  //    vpn.ts 的监视每 2s 读同一个 tunnelStatus 来守（见 startTunnelWatch）。
  stopConnectingPoll();
  step.value = 1; await sleep(450);
  step.value = 2; await sleep(350);
  step.value = STEPS.length; stage.value = 'connected'; session.connected = true;
  Message.success('已接入企业内网');
}

async function disconnect() {
  await stopTunnel();   // 它同时停监视并清 notReady：主动断开既不是中断、也不再是「未就绪」
  stage.value = 'idle'; session.connected = false;
  refreshSnap();
  Message.info('已断开');
}
</script>

<style scoped>
.cn { padding: 14px 16px; }
.cn__top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
.cn__hi { font-size: 18px; font-weight: 700; color: var(--bd-t1); }
.cn__net { font-size: 12px; color: var(--bd-t3); margin-top: 2px; }
.cn__pill { font-size: 12px; padding: 3px 10px; border-radius: 20px; background: var(--bd-fill-2); color: var(--bd-t3); }
.cn__pill.connected { background: var(--bd-success); color: #fff; }
.cn__pill.connecting { background: var(--bd-primary-1); color: var(--bd-primary); }
/* 未就绪既不是在线也不是离线：用告警橙，别用绿（会被读成已接入）也别用红（那是已断开）。 */
.cn__pill.unready { background: var(--bd-tag-gold-bg, #FFF7E8); color: var(--bd-warning); }

.cn__hero { display: flex; justify-content: center; padding: 22px 0 26px; }
.cn__ring { width: 216px; height: 216px; border-radius: 50%; border: none; cursor: pointer; padding: 0;
  background: radial-gradient(circle at 50% 40%, #fff, var(--bd-fill-2)); position: relative;
  box-shadow: 0 0 0 10px rgba(134, 144, 156, 0.08), 0 12px 30px rgba(0, 0, 0, 0.08); transition: box-shadow 0.3s; }
.cn__ring.idle { box-shadow: 0 0 0 10px rgba(134, 144, 156, 0.10), 0 12px 30px rgba(0, 0, 0, 0.08); }
.cn__ring.connecting { box-shadow: 0 0 0 0 rgba(22, 93, 255, 0.45); animation: pulse 1.4s infinite; }
.cn__ring.connected { background: radial-gradient(circle at 50% 40%, #EAFBE7, #D6F5D6);
  box-shadow: 0 0 0 10px rgba(0, 180, 42, 0.16), 0 12px 30px rgba(0, 180, 42, 0.20); }
.cn__ring.unready { background: radial-gradient(circle at 50% 40%, #FFFBF0, #FFF0D6);
  box-shadow: 0 0 0 10px rgba(255, 125, 0, 0.16), 0 12px 30px rgba(255, 125, 0, 0.18); }
.cn__ring.unready .cn__ico { color: var(--bd-warning); }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(22,93,255,0.40); } 70% { box-shadow: 0 0 0 22px rgba(22,93,255,0); } 100% { box-shadow: 0 0 0 0 rgba(22,93,255,0); } }
.cn__ring-in { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 4px; }
.cn__ico { font-size: 46px; color: var(--bd-t3); }
.cn__ring.connecting .cn__ico { color: var(--bd-primary); }
.cn__ring.connected .cn__ico { color: var(--bd-success); }
.cn__act { font-size: 18px; font-weight: 700; color: var(--bd-t1); margin-top: 4px; }
.cn__hint { font-size: 11px; color: var(--bd-t3); }

.cn__steps { display: flex; flex-direction: column; gap: 12px; }
.cn__steps-why { margin-top: 2px; padding-top: 10px; border-top: 1px solid var(--bd-border-1, #E5E6EB);
  font-size: 12.5px; line-height: 1.6; color: var(--bd-warning); word-break: break-all; }
.cn__steps-why-n { color: var(--bd-t3); }
.cn__step { display: flex; align-items: center; gap: 10px; font-size: 14px; color: var(--bd-t3); }
.cn__step.done { color: var(--bd-t2); }
.cn__step.doing { color: var(--bd-primary); font-weight: 600; }
.cn__step-dot { width: 22px; height: 22px; border-radius: 50%; background: var(--bd-fill-2); display: inline-flex; align-items: center; justify-content: center; font-size: 13px; }
.cn__step.done .cn__step-dot { background: var(--bd-success); color: #fff; }
.cn__step.doing .cn__step-dot { background: var(--bd-primary-1); color: var(--bd-primary); }

.cn__info-row, .cn__p { display: flex; align-items: center; }
.cn__info-row { justify-content: space-between; padding: 9px 0; border-bottom: 1px solid var(--bd-fill-2); font-size: 14px; color: var(--bd-t3); }
.cn__info-row:last-child { border-bottom: none; }
.cn__info-row b { color: var(--bd-t1); font-weight: 600; }
.cn__info-row b.ok { color: var(--bd-success); }
.cn__info-row b.bad { color: var(--bd-danger); }
/* 「不可判定」用中性灰：既不是通过也不是失败，别用颜色替一份没读到的健康行表态
   （与终端环境检测卡片里 em.na 同一条约定）。 */
.cn__info-row b.na { color: var(--bd-t3); font-weight: 500; }
.cn__unready { border-left: 3px solid var(--bd-warning); }
/* 隧道类失败用同一套排版、但换一色：它与「未就绪」是两件事（门开着 vs 门没开），
   同色会让用户以为是同一条告警换了句措辞。 */
.cn__fail { border-left: 3px solid var(--bd-danger); }
.cn__fail > b { color: var(--bd-danger); font-size: 14px; }
.cn__tnote { border-left: 3px solid var(--bd-danger); }
.cn__tnote > b { color: var(--bd-danger); font-size: 14px; }
.cn__unready > b { color: var(--bd-warning); font-size: 14px; }
.cn__unready-r { margin-top: 6px; font-size: 12.5px; line-height: 1.6; color: var(--bd-t1);
  word-break: break-all; font-family: var(--bd-mono, ui-monospace, monospace); }
.cn__unready-n { margin-top: 8px; font-size: 12px; line-height: 1.7; color: var(--bd-t3); }
.cn__unready-n b { color: var(--bd-t2); font-weight: 600; }

.cn__posture-h { display: flex; align-items: center; gap: 6px; font-weight: 600; color: var(--bd-t1); margin-bottom: 10px; }
.cn__posture-h em { font-style: normal; font-size: 12px; padding: 1px 8px; border-radius: 4px; background: var(--bd-tag-red-bg, #FFECE8); color: var(--bd-danger); margin-left: auto; }
/* 「未采集」是不可判定，既不是合规也不是风险——用中性灰，别用绿或红替它表态。 */
.cn__posture-h em.na { background: var(--bd-fill-2); color: var(--bd-t3); }
.cn__na { font-size: 12.5px; line-height: 1.7; color: var(--bd-t3); margin-top: 8px; }
.cn__na b { color: var(--bd-t2); font-weight: 600; }
.cn__na code { font-family: var(--bd-mono, ui-monospace, monospace); font-size: 11.5px; background: var(--bd-fill-2); padding: 1px 5px; border-radius: 3px; }
.cn__p { gap: 8px; padding: 7px 0; font-size: 14px; color: var(--bd-t2); }
.cn__p-ic { font-size: 17px; }
.cn__p-ic.ok { color: var(--bd-success); }
.cn__p-ic.bad { color: var(--bd-danger); }
.cn__drop { font-size: 12.5px; line-height: 1.7; color: var(--bd-danger); background: var(--bd-tag-red-bg, #FFECE8); }
.cn__drop b { font-weight: 600; }
.cn__warn2 { margin-top: 10px; padding: 9px 11px; font-size: 12px; line-height: 1.65;
  color: var(--bd-warning); background: var(--bd-tag-gold-bg, #FFF7E8); border-radius: 8px; }
</style>