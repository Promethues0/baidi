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
        <div class="ck-login__hint">演示 <code>li.ming / baidi@123</code> · 外包账号 <code>ext.zhou</code> 触发验证码 <code>123456</code></div>
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

        <button v-if="stage === 'idle'" class="dk-btn ck-cta" @click="connect"><icon-link />接入企业内网</button>
        <button v-else-if="stage === 'connected'" class="dk-btn dk-btn--ghost ck-cta" @click="disconnect"><icon-poweroff />断开连接</button>
        <div v-else class="ck-connecting">接入中…</div>
      </div>

      <!-- 右：环境检测 + 接入信息 -->
      <div class="ck-side">
        <div class="dk-card ck-posture">
          <div class="ck-card__h">终端环境检测<span class="ck-trust" :class="{ bad: !allOk }">{{ allOk ? '终端可信' : '存在风险' }}</span></div>
          <div v-for="p in posture" :key="p.label" class="ck-pi">
            <component :is="p.ok ? 'IconCheckCircleFill' : 'IconExclamationCircleFill'" :style="{ color: p.ok ? '#00B42A' : '#FF7D00' }" />
            <span class="ck-pi__l">{{ p.label }}</span>
            <span class="ck-pi__v" :class="{ warn: !p.ok }">{{ p.ok ? '通过' : '关注' }}</span>
          </div>
          <div class="ck-report">每 60s 周期上报控制中心 · 风险驱动动态收缩权限</div>
        </div>

        <div class="dk-card ck-conn" :class="{ off: stage !== 'connected' }">
          <div class="ck-card__h">接入信息</div>
          <template v-if="stage === 'connected'">
            <div class="ck-kv"><span>安全代理网关</span><b>华东出口 · gw-east-01</b></div>
            <div class="ck-kv"><span>SSL 访问隧道</span><b class="ok">已建立（TLCP/国密）</b></div>
            <div class="ck-kv"><span>SPA 服务隐身</span><b class="ok">已敲门 · 业务对外不可见</b></div>
            <div class="ck-kv"><span>虚拟 IP</span><b class="dk-mono">100.64.0.17</b></div>
          </template>
          <div v-else class="ck-conn__off">接入后展示网关 / 隧道 / 隐身 / 虚拟 IP</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type PortalLoginResp } from '@/lib/api';
import { session, login, authed } from '@/lib/store';
import { knock } from '@/lib/knock';

const authedNow = computed(() => authed());

/* 登录 */
const form = reactive({ username: 'li.ming', password: '', mfaCode: '' });
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
  } catch { err.value = '无法连接控制中心（baidi-control）'; } finally { loading.value = false; }
}

/* 接入状态机 */
const STEPS = ['终端环境检测上报', 'SPA 敲门（单包授权）', '建立 SSL 访问隧道', '下发访问策略 / 引流打标'];
const stage = ref<'idle' | 'connecting' | 'connected'>(session.connected ? 'connected' : 'idle');
const step = ref(0);
const stageLabel = computed(() => (stage.value === 'connected' ? '已接入' : stage.value === 'connecting' ? '接入中' : '待接入'));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function connect() {
  stage.value = 'connecting'; step.value = 0;
  await sleep(500);                       // ① 终端环境检测上报
  step.value = 1;                         // ② SPA 敲门 —— 真实链路（携带 JWT 身份）
  const r = await knock(session.token);
  if (!r.ok) {
    stage.value = 'idle';
    Message.error('SPA 敲门失败：' + (r.detail || '网关不可达'));
    return;
  }
  step.value = 2; await sleep(450);       // ③ 建立 SSL 访问隧道
  step.value = 3; await sleep(350);       // ④ 下发访问策略 / 引流打标
  step.value = STEPS.length; stage.value = 'connected'; session.connected = true;
  Message.success('已接入企业内网 · ' + (r.detail || ''));
}
function disconnect() { stage.value = 'idle'; session.connected = false; }

/* 环境检测（终端本地研判，演示） */
const posture = reactive([
  { label: '磁盘已加密', ok: true },
  { label: '系统未越狱 / 未 root', ok: true },
  { label: '系统版本合规', ok: true },
  { label: 'EDR 终端防护在线', ok: true },
  { label: '客户端为最新版本 v0.1.0', ok: true }
]);
const allOk = computed(() => posture.every((p) => p.ok));
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
.ck-steps { margin: 8px 0 14px; width: 230px; }
.ck-step { display: flex; align-items: center; gap: 8px; font-size: 12.5px; color: var(--bd-t3); padding: 4px 0; }
.ck-step.cur { color: var(--bd-primary); font-weight: 600; }
.ck-step.done { color: var(--bd-t2); }
.ck-step__d { width: 16px; height: 16px; border-radius: 50%; border: 1.5px solid currentColor; display: inline-flex; align-items: center; justify-content: center; font-size: 10px; }
.ck-cta { height: 42px; padding: 0 28px; font-size: 14px; margin-top: 10px; }
.ck-connecting { font-size: 13px; color: var(--bd-primary); margin-top: 12px; }

.ck-side { width: 320px; flex: none; display: flex; flex-direction: column; gap: 16px; }
.ck-card__h { font-size: 14px; font-weight: 600; padding: 14px 16px; border-bottom: 1px solid var(--bd-fill-2); display: flex; align-items: center; justify-content: space-between; }
.ck-trust { font-size: 11px; font-weight: 500; color: var(--bd-success); background: #E8FFEA; padding: 2px 8px; border-radius: 10px; }
.ck-trust.bad { color: var(--bd-warning); background: var(--bd-tag-gold-bg); }
.ck-posture { padding-bottom: 6px; }
.ck-pi { display: flex; align-items: center; gap: 9px; padding: 9px 16px; font-size: 13px; }
.ck-pi__l { flex: 1; color: var(--bd-t1); }
.ck-pi__v { font-size: 12px; color: var(--bd-success); }
.ck-pi__v.warn { color: var(--bd-warning); }
.ck-report { font-size: 11px; color: var(--bd-t3); padding: 8px 16px 12px; border-top: 1px solid var(--bd-fill-2); margin-top: 4px; }
.ck-conn { padding-bottom: 8px; }
.ck-conn.off { opacity: .8; }
.ck-kv { display: flex; align-items: center; justify-content: space-between; padding: 10px 16px; font-size: 13px; border-bottom: 1px solid var(--bd-fill-1); }
.ck-kv:last-child { border-bottom: none; }
.ck-kv span { color: var(--bd-t3); }
.ck-kv b { font-weight: 500; color: var(--bd-t1); }
.ck-kv b.ok { color: var(--bd-success); }
.ck-conn__off { padding: 18px 16px; font-size: 12.5px; color: var(--bd-t3); }
</style>
