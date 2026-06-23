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

    <!-- 已接入信息 -->
    <div v-else-if="stage === 'connected'" class="m-card cn__info">
      <div class="cn__info-row"><span>安全网关</span><b class="m-mono">{{ session.serverAddr }}</b></div>
      <div class="cn__info-row"><span>隧道加密</span><b>国密 TLCP · SM4</b></div>
      <div class="cn__info-row"><span>SPA 隐身</span><b class="ok">端口对未授权者不可见</b></div>
      <div class="cn__info-row"><span>虚拟 IP</span><b class="m-mono">10.99.0.2</b></div>
    </div>

    <!-- 终端环境检测 -->
    <div v-else class="m-card cn__posture">
      <div class="cn__posture-h"><icon-safe /> 终端安全检测 <em :class="{ ok: allOk }">{{ allOk ? '合规' : '有风险' }}</em></div>
      <div v-for="p in posture" :key="p.label" class="cn__p">
        <component :is="p.ok ? IconCheckCircleFill : IconCloseCircleFill" :class="['cn__p-ic', p.ok ? 'ok' : 'bad']" />
        {{ p.label }}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed } from 'vue';
import { Message } from '@arco-design/web-vue';
import {
  IconPoweroff, IconCheckCircleFill, IconCloseCircleFill, IconCheck, IconLoading
} from '@arco-design/web-vue/es/icon';
import { session } from '@/lib/store';
import { startTunnel, stopTunnel, platformLabel } from '@/lib/vpn';

const STEPS = ['终端环境检测上报', 'SPA 敲门（单包授权）', '建立国密 TLCP 隧道', '下发策略 / utun 引流'];
const stage = ref<'idle' | 'connecting' | 'connected'>(session.connected ? 'connected' : 'idle');
const step = ref(0);
const stageLabel = computed(() => (stage.value === 'connected' ? '已接入企业内网' : stage.value === 'connecting' ? '正在接入' : '未接入'));
const stageDot = computed(() => (stage.value === 'connected' ? '● 在线' : stage.value === 'connecting' ? '◐ 连接中' : '○ 离线'));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const posture = reactive([
  { label: '磁盘已加密', ok: true },
  { label: '系统未越狱 / 未 root', ok: true },
  { label: '系统版本合规', ok: true },
  { label: '客户端为最新版本 v0.1.0', ok: true }
]);
const allOk = computed(() => posture.every((p) => p.ok));

function toggle() {
  if (stage.value === 'connected') return disconnect();
  if (stage.value === 'idle') return connect();
}

async function connect() {
  stage.value = 'connecting'; step.value = 0;
  await sleep(500);                     // ① 终端环境检测上报
  step.value = 1;                       // ② SPA 敲门 —— 真实链路（携带 JWT 身份）
  const r = await startTunnel(session.token);
  if (!r.ok) {
    stage.value = 'idle';
    Message.error('SPA 敲门失败：' + (r.detail || '网关不可达'));
    return;
  }
  step.value = 2; await sleep(450);     // ③ 建立国密 TLCP 隧道
  step.value = 3; await sleep(350);     // ④ 下发策略 / 引流
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
.cn__posture-h em.ok { background: var(--bd-tag-green-bg, #E8FFEA); color: var(--bd-success); }
.cn__p { gap: 8px; padding: 7px 0; font-size: 14px; color: var(--bd-t2); }
.cn__p-ic { font-size: 17px; }
.cn__p-ic.ok { color: var(--bd-success); }
.cn__p-ic.bad { color: var(--bd-danger); }
</style>
