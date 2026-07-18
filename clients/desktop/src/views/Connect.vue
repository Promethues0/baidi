<template>
  <div class="ck">
    <!-- 未登录：登录 -->
    <div v-if="!authedNow" class="ck-login">
      <div class="dk-card ck-login__card">
        <div class="ck-login__logo">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
            <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </div>
        <div class="ck-login__t">登录白帝安全接入</div>
        <div class="ck-login__s">{{ needMfa ? '终端未授信，请完成短信二次认证' : '使用企业账号登录终端客户端' }}</div>

        <template v-if="!needMfa">
          <a-input v-model="form.username" size="large" placeholder="企业账号" class="ck-inp"><template #prefix><icon-user /></template></a-input>
          <a-input-password v-model="form.password" size="large" placeholder="登录口令" class="ck-inp" @keyup.enter="doLogin(false)"><template #prefix><icon-lock /></template></a-input-password>
        </template>
        <template v-else>
          <div class="ck-mfa-tip"><icon-exclamation-circle-fill /> {{ mfaReason }}</div>
          <a-input v-model="form.mfaCode" size="large" placeholder="短信验证码" class="ck-inp" @keyup.enter="doLogin(true)"><template #prefix><icon-safe /></template></a-input>
        </template>

        <div v-if="err" class="ck-err"><icon-close-circle-fill /> {{ err }}</div>
        <button class="dk-btn ck-login__btn" :disabled="loading" @click="doLogin(needMfa)">{{ loading ? '验证中…' : needMfa ? '验证并登录' : '登 录' }}</button>
        <div class="ck-login__hint">演示 <code>li.fang / baidi@123</code> · 外包账号 <code>ext.zhou</code> 触发验证码 <code>123456</code></div>
      </div>
    </div>

    <!-- 已登录：接入 hub -->
    <div v-else class="ck-hub">
      <!-- 左：接入状态环 -->
      <div class="dk-card ck-main">
        <div class="ck-ring" :class="stage">
          <div class="ck-ring__inner">
            <component :is="stage === 'connected' ? 'IconCheck' : 'IconLock'" class="ck-ring__ic" />
            <div class="ck-ring__txt">{{ stageLabel }}</div>
          </div>
          <span v-if="stage === 'connecting'" class="ck-ring__pulse" />
        </div>

        <div class="ck-hello">你好，<b>{{ session.user }}</b></div>

        <div v-if="stage === 'connecting'" class="ck-steps">
          <div v-for="(s, i) in STEPS" :key="s" class="ck-step" :class="{ done: i < step, cur: i === step }">
            <span class="ck-step__d"><icon-check v-if="i < step" /></span>{{ s }}
          </div>
        </div>

        <div v-if="denied" class="ck-denied">
          <icon-stop class="ck-denied__ic" />
          <div class="ck-denied__b">
            <div class="ck-denied__t">接入已被控制面拒绝</div>
            <div class="ck-denied__r">{{ deniedReason }}</div>
            <div class="ck-denied__h">隧道已断开。请联系管理员解除后重试——重复接入不会成功。</div>
          </div>
        </div>

        <button v-if="stage === 'idle'" class="dk-btn ck-cta" @click="connect"><icon-link />接入企业内网</button>
        <button v-else-if="stage === 'connected'" class="dk-btn dk-btn--ghost ck-cta" @click="disconnect"><icon-poweroff />断开连接</button>
        <button v-else-if="connectTimedOut" class="dk-btn dk-btn--ghost ck-cta" @click="disconnect"><icon-poweroff />停止接入</button>
        <div v-else class="ck-connecting">接入中…</div>

        <div v-if="err2" class="ck-err2"><icon-exclamation-circle-fill /> {{ err2 }}</div>
        <div v-if="!isTauri" class="ck-devnote">浏览器联调模式 · 真 utun 接管流量需打包客户端运行（需管理员授权）</div>
      </div>

      <!-- 右：环境检测 + 接入信息 -->
      <div class="ck-side">
        <div class="dk-card ck-posture">
          <div class="ck-card__h">终端环境检测
            <span class="ck-trust" :class="{ bad: postureVerdict?.verdict === 'block' || !allOk }">
              {{ postureVerdict ? (postureVerdict.verdict === 'block' ? '接入受限' : postureVerdict.verdict === 'allow' && allOk ? '终端可信' : '存在风险') : '采集中…' }}
            </span>
          </div>
          <div v-for="p in posture" :key="p.key" class="ck-pi">
            <component :is="p.ok ? 'IconCheckCircleFill' : 'IconExclamationCircleFill'" :style="{ color: p.ok ? '#00B42A' : '#FF7D00' }" />
            <span class="ck-pi__l">{{ p.label }}</span>
            <span class="ck-pi__v" :class="{ warn: !p.ok }">{{ p.ok ? '通过' : '关注' }}</span>
          </div>
          <div v-if="posture.length === 0" class="ck-pi" style="color: var(--bd-t3)">正在采集终端环境…</div>
          <div class="ck-report">
            {{ postureVerdict ? `已上报控制中心 · 判定 ${VERDICT_ZH[postureVerdict.verdict]} · 评分 ${postureVerdict.score}` : '每 60s 周期上报控制中心 · 风险驱动动态收缩权限' }}
          </div>
        </div>

        <div class="dk-card ck-conn" :class="{ off: stage !== 'connected' }">
          <div class="ck-card__h">接入信息<span v-if="stage === 'connected'" class="ck-live">● 隧道活动</span></div>
          <template v-if="stage === 'connected'">
            <div class="ck-kv"><span>安全代理网关</span><b class="dk-mono">{{ tun.gateway }}</b></div>
            <div class="ck-kv"><span>加密隧道</span><b class="ok">已建立 · {{ tun.cipher }}</b></div>
            <div class="ck-kv"><span>SPA 服务隐身</span><b class="ok">{{ tun.keepalive ? '敲门保活中 · 业务对外不可见' : '已敲门 · 业务对外不可见' }}</b></div>
            <div class="ck-kv"><span>虚拟网卡 / IP</span><b class="dk-mono">{{ tun.dev || 'utun' }} · {{ tun.vip }}</b></div>
            <div class="ck-kv"><span>引流网段</span><b class="dk-mono">{{ tun.route }} → 隧道</b></div>
            <div v-if="isTauri" class="ck-logwrap">
              <div class="ck-log__h" @click="showLog = !showLog"><icon-code /> 数据面日志 <icon-down :class="{ flip: showLog }" /></div>
              <pre v-if="showLog" class="ck-log">{{ tun.lines.join('\n') || '（暂无日志）' }}</pre>
            </div>
          </template>
          <div v-else class="ck-conn__off">接入后展示网关 / 隧道 / 隐身 / 虚拟 IP / 引流网段</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type PortalLoginResp } from '@/lib/api';
import { session, login, authed, validateConfig } from '@/lib/store';
import { knock } from '@/lib/knock';
import { tauriRuntime, tunnelStart, tunnelStop, tunnelStatus, type TunView } from '@/lib/tunnel';
import { postureState } from '@/lib/posture';

const authedNow = computed(() => authed());
const isTauri = tauriRuntime();

/* 登录 */
const form = reactive({ username: 'li.fang', password: '', mfaCode: '' });
const needMfa = ref(false);
const mfaReason = ref('');
const err = ref('');
const loading = ref(false);
async function doLogin(withMfa: boolean) {
  loading.value = true; err.value = '';
  try {
    const r = await api<PortalLoginResp>('/portal/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: form.username, password: form.password, mfaCode: withMfa ? form.mfaCode : '' })
    });
    if (r.ok && r.token) { login(r.token, r.displayName || form.username); }
    else if (r.needMfa) { needMfa.value = true; mfaReason.value = r.reason || ''; err.value = ''; }
    else { err.value = r.reason || '登录失败'; }
  } catch { err.value = '无法连接控制中心（检查「设置」里的控制中心地址）'; } finally { loading.value = false; }
}

/* 接入状态机 —— 真 utun 数据面 */
const STEPS = ['请求管理员授权', '创建 utun 虚拟网卡', 'SPA 敲门 · 建立加密隧道', '受保护网段引流接管'];
const stage = ref<'idle' | 'connecting' | 'connected'>('idle');
const step = ref(0);
const err2 = ref('');
const showLog = ref(false);
const tun = ref<TunView>({ running: false, ready: false, dev: '', vip: '', route: '', gateway: '', cipher: '', keepalive: false, error: '', denied: false, deniedReason: '', lines: [] });
const stageLabel = computed(() => (stage.value === 'connected' ? '已接入' : stage.value === 'connecting' ? '接入中' : '待接入'));

let pollTimer = 0;
let pollGen = 0;         // 轮询代次：断开/重连后自增，令过期的在途轮询失效
let connectTO = 0;      // 接入超时计时器
const connectTimedOut = ref(false);
const denied = ref(false);            // 被控制面强制下线 / 账号禁用（不可自愈）
const deniedReason = ref('');
const EMPTY_TUN: TunView = { running: false, ready: false, dev: '', vip: '', route: '', gateway: '', cipher: '', keepalive: false, error: '', denied: false, deniedReason: '', lines: [] };
function stepFromTun(v: TunView): number {
  if (v.ready) return STEPS.length;
  if (v.keepalive) return 3;
  if (v.dev) return 2;
  return 1;
}

async function connect() {
  err2.value = ''; connectTimedOut.value = false; denied.value = false; deniedReason.value = '';
  if (!isTauri) { await connectDev(); return; }   // 浏览器联调：真敲门探测，不接管流量
  const bad = validateConfig();
  if (bad) { err2.value = bad; return; }          // 接入前配置校验（端口/网段/URL）
  stage.value = 'connecting'; step.value = 0;
  try {
    await tunnelStart();                            // 触发管理员授权 + 后台拉起 baidi-tun（root）
  } catch (e) {
    stage.value = 'idle';
    err2.value = String((e as Error)?.message ?? e);
    return;
  }
  step.value = 1;
  startPolling();
  clearTimeout(connectTO);
  connectTO = window.setTimeout(() => {
    if (stage.value === 'connecting') {
      connectTimedOut.value = true;
      err2.value = '接入超时：数据面已启动但未就绪，请确认网关已运行、且「国密隧道」开关与网关一致';
    }
  }, 25000);
}

function startPolling() {
  clearInterval(pollTimer);
  const gen = ++pollGen;
  pollTimer = window.setInterval(async () => {
    if (gen !== pollGen) return;                 // 代次守卫：忽略过期轮询
    let v: TunView;
    try { v = await tunnelStatus(); } catch { return; }
    if (gen !== pollGen) return;                 // await 期间可能已断开
    tun.value = v;
    if (!v.running) {
      clearInterval(pollTimer);
      session.connected = false;
      if (stage.value !== 'idle') {
        stage.value = 'idle';
        clearTimeout(connectTO); connectTimedOut.value = false;
        if (v.denied) { err2.value = ''; }               // 定性拒绝走专属提示条，不占通用错误位
        else if (v.error) { err2.value = '数据面退出：' + v.error; }
      }
      denied.value = v.denied;
      deniedReason.value = v.deniedReason;
      return;
    }
    step.value = stepFromTun(v);
    if (v.ready) {
      stage.value = 'connected'; session.connected = true;
      connectTimedOut.value = false; err2.value = ''; clearTimeout(connectTO);
    }
  }, 1500);
}

async function disconnect() {
  try { await tunnelStop(); } catch (e) { err2.value = String((e as Error)?.message ?? e); return; }
  pollGen++; clearInterval(pollTimer); clearTimeout(connectTO);
  stage.value = 'idle'; session.connected = false; connectTimedOut.value = false; err2.value = '';
  denied.value = false; deniedReason.value = '';
  tun.value = { ...EMPTY_TUN };
}

/* 浏览器联调：经 knock-agent 真实敲门，UI 走通（不接管系统流量） */
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function connectDev() {
  stage.value = 'connecting'; step.value = 1;
  await sleep(400); step.value = 2; await sleep(300);
  const r = await knock(session.token);
  if (!r.ok) { stage.value = 'idle'; err2.value = 'SPA 敲门失败：' + (r.detail || '网关不可达'); return; }
  step.value = 3; await sleep(300); step.value = STEPS.length;
  tun.value = { running: true, ready: true, dev: 'utun(dev)', vip: '10.99.0.2', route: '10.99.0.0/24', gateway: '127.0.0.1:18443', cipher: '通用 TLS 1.3', keepalive: false, error: '', denied: false, deniedReason: '', lines: [(r.detail || 'SPA 敲门成功')] };
  stage.value = 'connected'; session.connected = true;
  Message.success('（联调）已敲门 · 真 utun 接管需打包运行');
}

/* 环境检测：读 App 级共享状态（上报循环脱离视图，切 Tab 不中断） */
const postureVerdict = computed(() => postureState.verdict);
const posture = computed(() => postureState.info?.checks ?? []);
const allOk = computed(() => posture.value.length > 0 && posture.value.every((p) => p.ok));
const VERDICT_ZH: Record<string, string> = { allow: '合规', degrade: '降权', gray: '灰度', block: '阻断' };

/* 重开 app 时若隧道仍在跑，恢复已接入态 */
onMounted(async () => {
  if (!isTauri || !authedNow.value) return;
  try {
    const v = await tunnelStatus();
    if (v.running) { tun.value = v; stage.value = v.ready ? 'connected' : 'connecting'; session.connected = v.ready; if (!v.ready) startPolling(); else startPolling(); }
  } catch { /* ignore */ }
});
onBeforeUnmount(() => { pollGen++; clearInterval(pollTimer); clearTimeout(connectTO); });
</script>

<style scoped>
.ck { height: 100%; padding: 24px; }

/* 登录 */
.ck-login { height: 100%; display: flex; align-items: center; justify-content: center; }
.ck-login__card { width: 340px; padding: 32px 28px 24px; text-align: center; }
.ck-login__logo { width: 48px; height: 48px; border-radius: 13px; margin: 0 auto; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d)); box-shadow: 0 4px 12px rgba(22, 93, 255, .32); }
.ck-login__t { font-size: 17px; font-weight: 700; margin-top: 14px; }
.ck-login__s { font-size: 12px; color: var(--bd-t3); margin: 5px 0 20px; }
.ck-inp { margin-bottom: 13px; }
.ck-mfa-tip { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--bd-warning); background: var(--bd-tag-gold-bg); border-radius: 7px; padding: 8px 10px; margin-bottom: 12px; }
.ck-err { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--bd-danger); margin: -4px 0 10px; }
.ck-login__btn { width: 100%; height: 40px; justify-content: center; font-size: 14px; letter-spacing: 2px; margin-top: 2px; }
.ck-login__hint { font-size: 11.5px; color: var(--bd-t3); margin-top: 14px; line-height: 1.7; }
.ck-login__hint code { color: var(--bd-primary); background: var(--bd-primary-1); padding: 1px 5px; border-radius: 4px; font-family: ui-monospace, monospace; }

/* 接入 hub */
.ck-hub { display: flex; gap: 18px; height: 100%; }
.ck-main { flex: 1; min-width: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 24px; }
.ck-ring { width: 152px; height: 152px; border-radius: 50%; position: relative; display: flex; align-items: center; justify-content: center; background: var(--bd-fill-2); border: 3px solid var(--bd-t4); transition: all .3s; }
.ck-ring.connecting { border-color: var(--bd-primary); background: var(--bd-primary-1); }
.ck-ring.connected { border-color: var(--bd-success); background: #E8FFEA; }
.ck-ring__inner { text-align: center; }
.ck-ring__ic { font-size: 40px; color: var(--bd-t3); }
.ck-ring.connecting .ck-ring__ic { color: var(--bd-primary); }
.ck-ring.connected .ck-ring__ic { color: var(--bd-success); }
.ck-ring__txt { font-size: 15px; font-weight: 700; margin-top: 6px; color: var(--bd-t1); }
.ck-ring__pulse { position: absolute; inset: -3px; border-radius: 50%; border: 3px solid var(--bd-primary); animation: ckpulse 1.4s ease-out infinite; }
@keyframes ckpulse { 0% { transform: scale(1); opacity: .6; } 100% { transform: scale(1.25); opacity: 0; } }
.ck-hello { font-size: 14px; color: var(--bd-t2); margin: 18px 0 6px; }
.ck-hello b { color: var(--bd-t1); }
.ck-steps { margin: 8px 0 14px; width: 240px; }
.ck-step { display: flex; align-items: center; gap: 8px; font-size: 12.5px; color: var(--bd-t3); padding: 4px 0; }
.ck-step.cur { color: var(--bd-primary); font-weight: 600; }
.ck-step.done { color: var(--bd-t2); }
.ck-step__d { width: 16px; height: 16px; border-radius: 50%; border: 1.5px solid currentColor; display: inline-flex; align-items: center; justify-content: center; font-size: 10px; }
.ck-cta { height: 42px; padding: 0 28px; font-size: 14px; margin-top: 10px; }
.ck-connecting { font-size: 13px; color: var(--bd-primary); margin-top: 12px; }
.ck-err2 { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--bd-danger); margin-top: 12px; max-width: 280px; text-align: left; }
.ck-denied { display: flex; gap: 10px; align-items: flex-start; margin-top: 16px; max-width: 300px; text-align: left; padding: 12px 14px; border-radius: 10px; background: rgba(245, 63, 63, .08); border: 1px solid rgba(245, 63, 63, .28); }
.ck-denied__ic { font-size: 20px; color: var(--bd-danger); flex: none; margin-top: 1px; }
.ck-denied__t { font-size: 13px; font-weight: 600; color: var(--bd-danger); }
.ck-denied__r { font-size: 12px; color: var(--bd-t1); margin-top: 4px; line-height: 1.5; }
.ck-denied__h { font-size: 11px; color: var(--bd-t3); margin-top: 6px; line-height: 1.6; }
.ck-devnote { font-size: 11px; color: var(--bd-t3); margin-top: 14px; max-width: 260px; text-align: center; line-height: 1.6; }

.ck-side { width: 320px; flex: none; display: flex; flex-direction: column; gap: 16px; }
.ck-card__h { font-size: 14px; font-weight: 600; padding: 14px 16px; border-bottom: 1px solid var(--bd-fill-2); display: flex; align-items: center; justify-content: space-between; }
.ck-trust { font-size: 11px; font-weight: 500; color: var(--bd-success); background: #E8FFEA; padding: 2px 8px; border-radius: 10px; }
.ck-trust.bad { color: var(--bd-warning); background: var(--bd-tag-gold-bg); }
.ck-live { font-size: 11px; font-weight: 500; color: var(--bd-success); }
.ck-posture { padding-bottom: 6px; }
.ck-pi { display: flex; align-items: center; gap: 9px; padding: 9px 16px; font-size: 13px; }
.ck-pi__l { flex: 1; color: var(--bd-t1); }
.ck-pi__v { font-size: 12px; color: var(--bd-success); }
.ck-pi__v.warn { color: var(--bd-warning); }
.ck-report { font-size: 11px; color: var(--bd-t3); padding: 8px 16px 12px; border-top: 1px solid var(--bd-fill-2); margin-top: 4px; }
.ck-conn { padding-bottom: 8px; }
.ck-conn.off { opacity: .8; }
.ck-kv { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 16px; font-size: 13px; border-bottom: 1px solid var(--bd-fill-1); }
.ck-kv:last-child { border-bottom: none; }
.ck-kv span { color: var(--bd-t3); flex: none; }
.ck-kv b { font-weight: 500; color: var(--bd-t1); text-align: right; }
.ck-kv b.ok { color: var(--bd-success); }
.ck-conn__off { padding: 18px 16px; font-size: 12.5px; color: var(--bd-t3); }
.ck-logwrap { padding: 4px 16px 10px; }
.ck-log__h { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--bd-t3); cursor: pointer; padding: 6px 0; }
.ck-log__h .flip { transform: rotate(180deg); }
.ck-log { margin: 4px 0 0; padding: 10px; background: #0e1f33; color: #9fd0ff; border-radius: 7px; font-size: 11px; line-height: 1.5; max-height: 150px; overflow: auto; white-space: pre-wrap; word-break: break-all; font-family: ui-monospace, monospace; }
</style>
