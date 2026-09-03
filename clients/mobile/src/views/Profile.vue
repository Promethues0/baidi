<template>
  <div class="m-page">
    <div class="pf__card">
      <span class="pf__av">{{ initial }}</span>
      <div>
        <div class="pf__name">{{ session.user || '未登录' }}</div>
        <div class="pf__role">企业终端用户</div>
      </div>
    </div>

    <div class="m-card pf__list">
      <!-- 三态：已接入 / 已下发但未就绪 / 未接入。中间那态改造前显示成「已接入」——
           而那正是真机上门没敲开、什么都访问不到的那一刻。 -->
      <div class="pf__row"><span>接入状态</span>
        <b :class="session.connected ? 'ok' : session.notReady ? 'warn' : ''">
          {{ session.connected ? '已接入' : session.notReady ? '已下发 · 未就绪' : '未接入' }}
        </b>
      </div>
      <div class="pf__row"><span>控制中心</span><b :class="ctlOk === null ? '' : ctlOk ? 'ok' : 'bad'">{{ ctlOk === null ? '检测中…' : ctlOk ? '连通' : '不可达' }}</b></div>
      <div class="pf__row"><span>数据面</span><b>{{ platformLabel() }}</b></div>
      <!-- ★版本号来自构建期注入（package.json），不再手写。手写的字符串必然与真实
           打包版本分家，而它正是更新检查与终端合规判定的输入。 -->
      <div class="pf__row"><span>客户端版本</span><b>v{{ appVersion }}</b></div>
    </div>

    <!-- ★客户端更新检查（FR-UPG-19 最后一跳）。后端按 platform 分桶早已支持
         android/ios/harmony，改造前只是移动端从没调过这一跳——于是灰度对移动端
         **完全不可见**：管理员配了、服务端算了、终端一无所知。
         判定完全在服务端，这里只渲染结论；查询失败静默（不打扰用户，也不假装"已是最新"）。 -->
    <div v-if="upd?.update" class="m-card pf__upd">
      <div class="pf__upd-h"><icon-notification /> 有新版本可用</div>
      <div class="pf__upd-b">
        当前 v{{ upd.current }} → <b>v{{ upd.latest }}</b>
        <span class="pf__upd-r">{{ upd.reason }}</span>
      </div>
      <div class="pf__upd-n">
        白帝<b>不自动下载、不自动安装</b>：请到门户「下载中心」取安装包。
        灰度只决定「告诉谁有新版」，你实际装的版本由这一步决定。
      </div>
    </div>

    <div class="m-card pf__cfg">
      <div class="pf__cfg-h"><icon-settings /> 接入配置</div>
      <div class="pf__f"><label>控制中心</label><a-input v-model="config.control" size="small" placeholder="留空=按原生下发" @change="onCfg" /></div>
      <div class="pf__f"><label>安全网关</label><a-input v-model="config.gateway" size="small" placeholder="如 gw.baidi.local" @change="onCfg" /></div>
      <div class="pf__f"><label>受保护网段</label><a-input v-model="config.route" size="small" placeholder="10.99.0.0/24" @change="onCfg" /></div>
      <div class="pf__f"><label>虚拟 IP</label><a-input v-model="config.ip" size="small" placeholder="10.99.0.2" @change="onCfg" /></div>
      <div class="pf__f pf__f--sw"><label>国密隧道（TLCP）</label><a-switch v-model="config.gm" size="small" @change="onCfg" /></div>
      <div class="pf__cfg-note">网段 / 虚拟 IP / 国密 由本端配置并经原生 VPN 扩展生效；控制中心 / 网关留空则用原生壳下发。</div>
    </div>

    <div class="m-card pf__diag">
      <div class="pf__diag-h"><icon-pulse /> 链路诊断</div>
      <!-- ★三态而不是二值：探不到（本端壳不报数据面健康态）既不是通过也不是失败。
           二值渲染只能在两种错法里挑一种——画成红叉会让用户去排查一个不存在的问题，
           画成绿勾则是替一份根本没读到的健康行背书（本波要消灭的正是后者）。 -->
      <div v-for="d in results" :key="d.k" class="pf__d">
        <component
          :is="d.state === 'na' ? IconQuestionCircleFill : d.state === 'ok' ? IconCheckCircleFill : IconCloseCircleFill"
          :class="['pf__d-ic', d.state]"
        />
        <span>{{ d.k }}</span><em>{{ d.v }}</em>
      </div>
      <button class="m-btn m-btn--ghost" :disabled="diaging" @click="diag">{{ diaging ? '检测中…' : '一键诊断' }}</button>
    </div>

    <button class="m-btn m-btn--danger" @click="doLogout">退出登录</button>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { IconCheckCircleFill, IconCloseCircleFill, IconQuestionCircleFill } from '@arco-design/web-vue/es/icon';
import { ping, checkClientUpdate, appVersion, PING_PATH, type ClientUpdateResp } from '@/lib/api';
import { session, config, saveConfig, validateConfig, logout } from '@/lib/store';
import { platformLabel, stopTunnel, tunnelStatus } from '@/lib/vpn';

function onCfg() { saveConfig(); const e = validateConfig(); if (e) Message.warning(e); }

const router = useRouter();
const initial = computed(() => (session.user || '?').slice(0, 1).toUpperCase());
const ctlOk = ref<boolean | null>(null);

/** 服务端算出的更新结论；null = 没查过或查失败（**不等于**已是最新，故不渲染任何东西）。 */
const upd = ref<ClientUpdateResp | null>(null);
/** 本端平台：原生壳注入 __BAIDI_NATIVE__.platform，dev 浏览器按 UA 粗判。
 *  ★取不到就不查——空平台会让服务端拿一个它不认识的桶去算，结论没有意义。 */
function mobilePlatform(): string {
  const nb = (window as unknown as { __BAIDI_NATIVE__?: { platform?: string } }).__BAIDI_NATIVE__;
  const p = (nb?.platform || '').toLowerCase();
  if (p) return p;
  const ua = navigator.userAgent;
  if (/android/i.test(ua)) return 'android';
  if (/iphone|ipad|ipod/i.test(ua)) return 'ios';
  if (/harmony/i.test(ua)) return 'harmony';
  return '';
}
async function checkUpdate() {
  upd.value = null; // 先清：换账号时不该挂着上一个人的结论
  const plat = mobilePlatform();
  if (!plat || !appVersion) return;
  try { upd.value = await checkClientUpdate(plat, appVersion); } catch { /* 静默：见 upd 的注释 */ }
}

/** 自检项。state 三态：ok / bad / **na=不可判定**（不是"失败"，也不是"通过"）。 */
type DiagState = 'ok' | 'bad' | 'na';
const results = reactive<{ k: string; v: string; state: DiagState }[]>([]);
const diaging = ref(false);

async function checkCtl() { ctlOk.value = await ping(); }

async function diag() {
  diaging.value = true; results.length = 0;
  const ok = await ping();
  results.push({ k: '控制中心 ' + PING_PATH, v: ok ? '连通（回 JSON）' : '不可达', state: ok ? 'ok' : 'bad' });
  results.push({ k: '身份令牌', v: session.token ? '有效' : '缺失', state: session.token ? 'ok' : 'bad' });

  // ★数据面的三行**必须现算**，不能读 session.connected：那是 UI 的结论，
  //   而这一栏存在的意义正是"UI 的结论对不对"。真机上二者曾经相反（UI 说已接入、
  //   健康行说 knock=false），只读 UI 结论的自检把那次错判整段掩盖掉了。
  const s = tunnelStatus();
  if (!s) {
    results.push({ k: '数据面运行态', v: '不可判定（本端壳未提供运行态接口）', state: 'na' });
  } else {
    const running = s.stage === 'up' || s.stage === 'starting';
    results.push({
      k: '数据面运行态',
      v: `stage=${s.stage}` + (s.reason?.trim() ? ` · ${s.reason.trim()}` : ''),
      state: running ? 'ok' : 'bad'
    });
    const three = (v: unknown, okText: string, badText: string): { v: string; state: DiagState } =>
      (s.healthObserved !== true || typeof v !== 'boolean')
        ? { v: '不可判定（本端未报告数据面健康状态）', state: 'na' }
        : v ? { v: okText, state: 'ok' } : { v: badText, state: 'bad' };
    results.push({ k: 'SPA 敲门', ...three(s.healthKnock, '成功 · 放行窗口已开', '失败') });
    // tunnel 是**粘性位**：用户打开第一个应用之前它恒 false，那是健康的空闲态而不是故障，
    // 所以文案不能写「隧道不通」（桌面端在这上面踩过，见 ARCHITECTURE 第七节边界①）。
    results.push({ k: '业务隧道', ...three(s.healthTunnel, '已拨通过业务连接', '尚无业务连接拨通（未必是故障：首次访问应用前恒为此值）') });
    const err = (s.healthErr || '').trim();
    const kerr = (s.healthKnockErr || '').trim();
    const terr = (s.healthTunnelErr || '').trim();
    if (s.healthObserved !== true) {
      results.push({ k: '健康行错误', v: '不可判定（尚未读到健康回报）', state: 'na' });
    } else {
      const detail = [kerr && '敲门：' + kerr, terr && '隧道：' + terr, !kerr && !terr && err].filter(Boolean).join(' / ');
      results.push({ k: '健康行错误', v: detail || '无', state: detail ? 'bad' : 'ok' });
    }
  }
  diaging.value = false;
}

/* 退出登录必须带走数据面。
   ★移动端的隧道是**系统级 VpnService**：只清 localStorage 的话，它继续以上一个账号的
   会话令牌保活续窗（-reknock 15s），网关按那个账号鉴权并写审计，而系统状态栏上
   那把 VPN 钥匙还亮着——下一个人登录后用的仍是前一个人的授权。
   断不开就**不登出**：否则回到"UI 说没登录、数据面还以他的身份在跑"。 */

/**
 * 「数据面此刻还在不在跑」——登出守卫的唯一判据。
 *
 * ★改造前守卫是 `if (session.connected)`，而 wave10 之后 connected 表达的是**门敲开没有**：
 *   未就绪态下它是 false，于是登出会跳过 stopTunnel，把一条仍以上一个账号每 15s 保活续窗的
 *   VpnService 留在系统里——正是上面那段注释要防的事，只是换成了"判据自己变了"这种发生法。
 *
 * ★读不到原生运行态时回落到 session.connected，并且两者取**或**：多断一次没有代价
 *   （stopTunnel 幂等，原生侧本就没在跑时是空动作），少断一次的代价见上。
 */
function dataplaneRunning(): boolean {
  const s = tunnelStatus();
  return (!!s && (s.stage === 'starting' || s.stage === 'up')) || session.connected;
}

async function doLogout() {
  if (dataplaneRunning()) {
    try {
      await stopTunnel();
    } catch (e) {
      Message.error('断开接入失败，未退出登录：' + String((e as Error)?.message ?? e)
        + '（数据面仍以当前账号运行，请在「接入」页手动断开后重试）');
      return;
    }
    session.connected = false;
  }
  logout();
  router.replace('/login');
}

onMounted(() => { void checkCtl(); void checkUpdate(); });
</script>

<style scoped>
.pf__upd { border-left: 3px solid var(--bd-warning); }
.pf__upd-h { display: flex; align-items: center; gap: 6px; font-size: 14px; font-weight: 600; color: var(--bd-warning); }
.pf__upd-b { margin-top: 8px; font-size: 13px; color: var(--bd-t1); }
.pf__upd-r { display: block; margin-top: 4px; font-size: 12px; color: var(--bd-t3); }
.pf__upd-n { margin-top: 8px; font-size: 12px; line-height: 1.7; color: var(--bd-t3); }
.pf__card { display: flex; align-items: center; gap: 14px; padding: 6px 2px 18px; }
.pf__av { width: 54px; height: 54px; border-radius: 16px; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-purple)); color: #fff; font-size: 24px; font-weight: 700; }
.pf__name { font-size: 18px; font-weight: 700; color: var(--bd-t1); }
.pf__role { font-size: 12px; color: var(--bd-t3); margin-top: 3px; }
.pf__list { margin-bottom: 14px; }
.pf__row { display: flex; justify-content: space-between; align-items: center; padding: 11px 0; border-bottom: 1px solid var(--bd-fill-2); font-size: 14px; color: var(--bd-t3); }
.pf__row:last-child { border-bottom: none; }
.pf__row b { color: var(--bd-t1); font-weight: 600; }
.pf__row b.ok { color: var(--bd-success); }
.pf__row b.bad { color: var(--bd-danger); }
.pf__row b.warn { color: var(--bd-warning); }
.pf__cfg { margin-bottom: 14px; }
.pf__cfg-h { display: flex; align-items: center; gap: 6px; font-weight: 600; color: var(--bd-t1); margin-bottom: 12px; }
.pf__f { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.pf__f label { width: 92px; flex: none; font-size: 13px; color: var(--bd-t2); }
.pf__f--sw { justify-content: space-between; }
.pf__f--sw label { width: auto; }
.pf__cfg-note { font-size: 11px; color: var(--bd-t3); line-height: 1.6; margin-top: 2px; }
.pf__diag { margin-bottom: 16px; }
.pf__diag-h { display: flex; align-items: center; gap: 6px; font-weight: 600; color: var(--bd-t1); margin-bottom: 10px; }
.pf__d { display: flex; align-items: flex-start; gap: 8px; padding: 7px 0; font-size: 13px; color: var(--bd-t2); line-height: 1.5; }
.pf__d > span { flex: none; }
.pf__d em { font-style: normal; margin-left: auto; color: var(--bd-t3); text-align: right; word-break: break-all; }
.pf__d-ic { font-size: 16px; flex: none; margin-top: 1px; }
.pf__d-ic.ok { color: var(--bd-success); }
.pf__d-ic.bad { color: var(--bd-danger); }
/* 不可判定用中性灰：颜色也是一种断言，探不到时不该表态（与 Connect 页 b.na 同一条约定）。 */
.pf__d-ic.na { color: var(--bd-t3); }
</style>
