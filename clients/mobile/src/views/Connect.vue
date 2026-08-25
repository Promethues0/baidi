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
      <button class="cn__ring" :class="stage" :disabled="stage === 'connecting'" @click="toggle">
        <div class="cn__ring-in">
          <component :is="stage === 'connected' ? IconCheckCircleFill : IconPoweroff" class="cn__ico" />
          <div class="cn__act">{{ stage === 'connected' ? '已接入' : stage === 'connecting' ? '接入中…' : '点击接入' }}</div>
          <div class="cn__hint">{{ stage === 'connected' ? '点击断开' : '企业内网 · 先认证后连接' }}</div>
        </div>
      </button>
    </div>

    <!-- 接入步骤（接入中显示） -->
    <div v-if="stage === 'connecting'" class="m-card cn__steps">
      <div v-for="(s, i) in STEPS" :key="s" class="cn__step" :class="{ done: i < step, doing: i === step }">
        <span class="cn__step-dot"><icon-check v-if="i < step" /><icon-loading v-else-if="i === step" /></span>
        {{ s }}
      </div>
    </div>

    <!-- 已接入信息（真实来自当前接入配置） -->
    <div v-else-if="stage === 'connected'" class="m-card cn__info">
      <div class="cn__info-row"><span>安全网关</span><b class="m-mono">{{ ti.gateway }}</b></div>
      <!-- 算法名后面必须跟上「有没有认证网关身份」：只写 SM2/SM4-GCM/SM3 读起来
           比钉扎那档还强，而移动端此前恰恰是零认证的那一档（Config 里连 pin 字段都没有）。 -->
      <div class="cn__info-row"><span>隧道加密</span><b :class="{ ok: ti.pinned }">{{ ti.cipher }}</b></div>
      <div class="cn__info-row"><span>可达资源</span><b>{{ ti.resources ? ti.resources + ' 项（经资源映射鉴权）' : '（无资源映射）' }}</b></div>
      <!-- 同桌面端：只说本机敲门状态，不替网关断言隐身效果（客户端拿不到那份回执，
           而参考部署默认不开 -pf，未敲门的 TCP 仍会被 nmap 判 open）。 -->
      <div class="cn__info-row"><span>SPA 敲门</span><b class="ok">已完成 · 已开放行窗口</b></div>
      <div class="cn__info-row"><span>受保护网段</span><b class="m-mono">{{ ti.route }} → 隧道</b></div>
      <div class="cn__info-row"><span>虚拟 IP</span><b class="m-mono">{{ ti.vip }}</b></div>
      <!-- 剖面拉不到时的降级必须当面说：这种接入多半是"隧道起来了却什么都访问不了"。 -->
      <div v-if="profileErr" class="cn__warn2">
        接入剖面未取到（{{ profileErr }}），本次使用「我的」页手填配置：
        网关落点 / 受保护网段 / 资源映射 / 证书指纹均非控制面下发，业务多半访问不到。
      </div>
    </div>

    <!-- 终端环境检测：移动端**尚未实现采集**，如实说明而不是画一张全绿的卡片。
         此处此前是四行硬编码 ok:true（磁盘已加密 / 未越狱 / 版本合规 / 客户端最新），
         对着一台从没被检测过的手机显示「终端安全检测 合规」——而合规判定权在控制面，
         它对这台设备根本没有任何数据。 -->
    <div v-else class="m-card cn__posture">
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
import { ref, computed } from 'vue';
import { Message } from '@arco-design/web-vue';
import {
  IconPoweroff, IconCheckCircleFill, IconCheck, IconLoading
} from '@arco-design/web-vue/es/icon';
import { session, validateConfig } from '@/lib/store';
import { startTunnel, stopTunnel, platformLabel, tunnelInfo, loadProfile } from '@/lib/vpn';

// ★「终端环境检测上报」这一步已删除：移动端根本没有采集能力（见模板里的说明），
// 而它此前是一句 `await sleep(500)` 假装出来的——进度条走过一步，什么都没发生。
// 其余三步里只有「SPA 敲门」是本 UI 真发起的；后两步由原生扩展在自己进程里完成，
// webview 拿不到进度回报，故按固定节奏推进（见 connect() 里的说明）。
const STEPS = ['SPA 敲门（单包授权）', '建立国密 TLCP 隧道', '下发策略 / utun 引流'];
const ti = computed(() => tunnelInfo());
const stage = ref<'idle' | 'connecting' | 'connected'>(session.connected ? 'connected' : 'idle');
const step = ref(0);
const stageLabel = computed(() => (stage.value === 'connected' ? '已接入企业内网' : stage.value === 'connecting' ? '正在接入' : '未接入'));
const stageDot = computed(() => (stage.value === 'connected' ? '● 在线' : stage.value === 'connecting' ? '◐ 连接中' : '○ 离线'));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** 接入前拉剖面失败的原因。非空时接入信息卡上会当面写出来——退回手填配置的接入
 *  多半是半成功状态（无资源映射 → 发不出 CONNECT 前导 → 网关 fail-closed）。 */
const profileErr = ref('');


function toggle() {
  if (stage.value === 'connected') return disconnect();
  if (stage.value === 'idle') return connect();
}

async function connect() {
  const bad = validateConfig();
  if (bad) { Message.warning(bad); return; }   // 接入前配置校验（端口/网段/虚拟IP/控制中心）
  stage.value = 'connecting'; step.value = 0;
  // ★接入前拉一次接入剖面。移动端此前**全仓零处**拉它，接入配置全靠用户在「我的」页手填——
  //   于是网关落点、受保护网段、资源映射、证书指纹一概由终端自己猜，而只有控制面
  //   同时知道这四样。拉不到不阻断（退回手填配置），但要把原因说出来：那种接入多半是
  //   「隧道起来了却什么都访问不了」——无 resmap 就发不出 CONNECT 前导，而网关对
  //   无前导连接是 fail-closed 的。
  profileErr.value = await loadProfile();
  // ① SPA 敲门 —— 这一步是**真的**：携带 JWT 身份，原生壳里交给 VPN 扩展发包，
  //    dev 浏览器里经 knock-agent 发真实 SPA 单包。
  const r = await startTunnel(session.token);
  if (!r.ok) {
    stage.value = 'idle';
    Message.error('SPA 敲门失败：' + (r.detail || '网关不可达'));
    return;
  }
  // ②③ 建隧道与引流由原生扩展在自己的进程里完成，webview **收不到进度回报**
  //    （NativeBridge 只有 startTunnel/stopTunnel 两个方法）。这里按固定节奏推进
  //    进度条，是展示性的——不代表这两步各自何时真正完成。要把它变成真进度，
  //    得先给原生桥加一个状态查询接口，三端各实现一遍。
  step.value = 1; await sleep(450);
  step.value = 2; await sleep(350);
  step.value = STEPS.length; stage.value = 'connected'; session.connected = true;
  Message.success('已接入企业内网');
}

async function disconnect() {
  await stopTunnel();
  stage.value = 'idle'; session.connected = false;
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

.cn__hero { display: flex; justify-content: center; padding: 22px 0 26px; }
.cn__ring { width: 216px; height: 216px; border-radius: 50%; border: none; cursor: pointer; padding: 0;
  background: radial-gradient(circle at 50% 40%, #fff, var(--bd-fill-2)); position: relative;
  box-shadow: 0 0 0 10px rgba(134, 144, 156, 0.08), 0 12px 30px rgba(0, 0, 0, 0.08); transition: box-shadow 0.3s; }
.cn__ring.idle { box-shadow: 0 0 0 10px rgba(134, 144, 156, 0.10), 0 12px 30px rgba(0, 0, 0, 0.08); }
.cn__ring.connecting { box-shadow: 0 0 0 0 rgba(22, 93, 255, 0.45); animation: pulse 1.4s infinite; }
.cn__ring.connected { background: radial-gradient(circle at 50% 40%, #EAFBE7, #D6F5D6);
  box-shadow: 0 0 0 10px rgba(0, 180, 42, 0.16), 0 12px 30px rgba(0, 180, 42, 0.20); }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(22,93,255,0.40); } 70% { box-shadow: 0 0 0 22px rgba(22,93,255,0); } 100% { box-shadow: 0 0 0 0 rgba(22,93,255,0); } }
.cn__ring-in { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 4px; }
.cn__ico { font-size: 46px; color: var(--bd-t3); }
.cn__ring.connecting .cn__ico { color: var(--bd-primary); }
.cn__ring.connected .cn__ico { color: var(--bd-success); }
.cn__act { font-size: 18px; font-weight: 700; color: var(--bd-t1); margin-top: 4px; }
.cn__hint { font-size: 11px; color: var(--bd-t3); }

.cn__steps { display: flex; flex-direction: column; gap: 12px; }
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
.cn__warn2 { margin-top: 10px; padding: 9px 11px; font-size: 12px; line-height: 1.65;
  color: var(--bd-warning); background: var(--bd-tag-gold-bg, #FFF7E8); border-radius: 8px; }
</style>