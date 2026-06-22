<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">时间与 NTP<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">系统时间直接影响证书校验、令牌有效期、审计时序与 HMAC 哈希链——时间不同步会导致大面积接入失败</div>
      </div>
      <a-button type="primary" size="small" @click="save"><template #icon><icon-save /></template>保存配置</a-button>
    </div>

    <div class="zl-grid" style="grid-template-columns: 360px 1fr;">
      <!-- 同步状态 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title" style="margin-bottom:14px">同步状态</div>
        <div class="clock data">{{ nowStr }}</div>
        <div class="clock-tz">{{ c.timezone }}</div>
        <div class="sync-box" :class="synced ? 'ok' : 'bad'">
          <span class="sync-dot" />
          {{ synced ? 'NTP 已同步' : '未同步 / 漂移过大' }}
        </div>
        <div class="cert-detail">
          <div class="cd-row"><span>时间源</span><b class="data">{{ c.source || '—' }}</b></div>
          <div class="cd-row"><span>上次同步</span><b class="data">{{ c.lastSync || '—' }}</b></div>
          <div class="cd-row"><span>时钟偏移</span><b class="data" :class="{warn: Math.abs(c.offsetMs)>100}">{{ c.offsetMs > 0 ? '+' : '' }}{{ c.offsetMs }} ms</b></div>
        </div>
        <a-button size="small" long style="margin-top:14px" :loading="syncing" @click="syncNow">立即同步</a-button>
      </div>

      <!-- 配置 -->
      <div class="zl-card zl-card__pad">
        <div class="card-head"><div class="zl-card__title">NTP 客户端</div><a-switch v-model="c.ntpEnabled" /></div>
        <div class="cfg" :class="{dim: !c.ntpEnabled}">
          <div class="cfg-row" style="align-items:flex-start"><label style="padding-top:4px">NTP 服务器</label>
            <div style="flex:1;max-width:420px">
              <div v-for="(s, i) in c.ntpServers" :key="i" class="ntp-row">
                <a-input v-model="c.ntpServers[i]" size="small" placeholder="ntp.example.com" />
                <a-button size="mini" status="danger" @click="c.ntpServers.splice(i,1)"><icon-delete /></a-button>
              </div>
              <a-button size="mini" style="margin-top:6px" @click="c.ntpServers.push('')"><template #icon><icon-plus /></template>添加服务器</a-button>
              <div class="cfg-hint">按顺序故障转移；建议至少配置 2 个不同来源（内网 + 公网池）。</div>
            </div>
          </div>
          <div class="cfg-row"><label>同步间隔</label>
            <a-select v-model="c.syncInterval" size="small" style="width:200px">
              <a-option :value="600">10 分钟</a-option><a-option :value="3600">1 小时</a-option><a-option :value="21600">6 小时</a-option><a-option :value="86400">1 天</a-option>
            </a-select>
          </div>
        </div>
        <div class="cfg" style="margin-top:8px;border-top:1px solid var(--line);padding-top:14px">
          <div class="cfg-row"><label>时区</label>
            <a-select v-model="c.timezone" size="small" style="width:240px" show-search>
              <a-option v-for="tz in zones" :key="tz" :value="tz">{{ tz }}</a-option>
            </a-select>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue';
import { Message } from '@arco-design/web-vue';

const live = ref(false);
const syncing = ref(false);
const zones = ['Asia/Shanghai', 'Asia/Urumqi', 'Asia/Hong_Kong', 'UTC', 'America/New_York', 'Europe/London'];
const c = reactive<any>({
  timezone: 'Asia/Shanghai', ntpEnabled: true, ntpServers: ['ntp.aliyun.com', 'cn.pool.ntp.org'],
  syncInterval: 3600, lastSync: '2026-06-13 09:32:11', offsetMs: -3, source: 'ntp.aliyun.com'
});

const synced = computed(() => c.ntpEnabled && Math.abs(c.offsetMs) < 100);
const nowTick = ref(Date.now());
let tick: any = null;
const nowStr = computed(() => {
  const d = new Date(nowTick.value);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
});

async function load() {
  try {
    const r = await fetch('/ctl/api/coll?kind=syscfg');
    if (!r.ok) throw new Error();
    const docs = await r.json();
    const d = docs.find((x: any) => x.key === 'time');
    if (d) Object.assign(c, d);
    live.value = true;
  } catch { live.value = false; }
}
onMounted(() => { load(); tick = setInterval(() => (nowTick.value = Date.now()), 1000); });
onUnmounted(() => tick && clearInterval(tick));

async function save() {
  if (live.value) {
    try {
      const r = await fetch('/ctl/api/coll?kind=syscfg', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ key: 'time', doc: { key: 'time', ...c } })
      });
      if (!r.ok) throw new Error();
    } catch { return Message.error('保存失败：控制面不可达'); }
  }
  Message.success('时间与 NTP 配置已保存' + (live.value ? ' · 已持久化' : '（mock）'));
}
async function syncNow() {
  syncing.value = true;
  await new Promise((r) => setTimeout(r, 700));
  c.offsetMs = -2; c.source = c.ntpServers[0];
  syncing.value = false;
  Message.success('已向 ' + c.ntpServers[0] + ' 同步时间 · 偏移 -2ms');
}
</script>

<style scoped>
.clock { font-size: 26px; font-weight: 700; color: var(--ink); letter-spacing: .5px; }
.clock-tz { font-size: 12px; color: var(--ink-3); margin-top: 2px; margin-bottom: 14px; }
.sync-box { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600; padding: 9px 12px; border-radius: var(--r-md); margin-bottom: 14px; }
.sync-box.ok { background: color-mix(in oklch, var(--ok) 10%, transparent); color: var(--ok); }
.sync-box.bad { background: color-mix(in oklch, var(--danger) 10%, transparent); color: var(--danger); }
.sync-dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
.cert-detail { display: flex; flex-direction: column; }
.cd-row { display: flex; justify-content: space-between; gap: 12px; padding: 7px 0; border-bottom: 1px solid var(--line); font-size: 12.5px; }
.cd-row:last-child { border-bottom: 0; }
.cd-row span { color: var(--ink-3); }
.cd-row b { color: var(--ink); font-weight: 600; } .cd-row b.warn { color: var(--warn); }

.card-head { display: flex; align-items: center; justify-content: space-between; padding-bottom: 12px; margin-bottom: 12px; border-bottom: 1px solid var(--line); }
.cfg { display: flex; flex-direction: column; gap: 12px; transition: opacity .2s; }
.cfg.dim { opacity: .4; pointer-events: none; }
.cfg-row { display: flex; align-items: center; gap: 16px; }
.cfg-row label { font-size: 12.5px; font-weight: 600; color: var(--ink-2); width: 90px; flex: none; }
.cfg-hint { font-size: 11px; color: var(--ink-3); line-height: 1.5; margin-top: 6px; }
.ntp-row { display: flex; gap: 6px; margin-bottom: 6px; }
.ntp-row .arco-input-wrapper { flex: 1; }
</style>
