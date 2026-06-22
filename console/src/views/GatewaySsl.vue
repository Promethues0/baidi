<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">SSL 接入点<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">自有 TLS/TLCP 隧道 · 流量形态与正常 HTTPS 不可区分（ZL-NFR-004 / PDP-10）· SPA 先敲门后可见</div>
      </div>
      <a-select v-model="gw" size="small" style="width:180px">
        <a-option value="zl-gw-hq-01">zl-gw-hq-01（总部）</a-option>
        <a-option value="zl-gw-dmz-02">zl-gw-dmz-02（DMZ）</a-option>
      </a-select>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1fr 1.5fr;">
      <div style="display:flex;flex-direction:column;gap:16px;min-width:0">
        <!-- 监听与降级链 -->
        <div class="zl-card zl-card__pad">
          <div class="zl-card__title" style="margin-bottom:12px">监听与承载（DTLS→TLS→443 降级链）</div>
          <div class="ssl-chain">
            <div v-for="(s, i) in chain" :key="s.k" class="ssl-hop" :class="{ off: !s.on }">
              <div class="ssl-hop__head">
                <span class="ssl-hop__n data">{{ i + 1 }}</span>
                <b>{{ s.name }}</b>
                <a-switch v-model="s.on" size="small" :disabled="s.locked" />
              </div>
              <div class="ssl-hop__d">{{ s.desc }}</div>
            </div>
          </div>
          <div class="ssl-note"><icon-info-circle /> 443 兜底不可关闭——运营商抗识别是产品核心承诺（M1 出口门禁：UDP 封锁网络实测可用）。</div>
        </div>

        <!-- 套件 -->
        <div class="zl-card zl-card__pad">
          <div class="zl-card__title" style="margin-bottom:12px">密码套件（Tongsuo 单一底座）</div>
          <div class="ssl-rows">
            <div class="ssl-row"><div><b>TLS 1.3</b><span>默认 · X25519 / AES-GCM</span></div><span class="zl-badge zl-badge--ok">启用</span></div>
            <div class="ssl-row"><div><b>国密 TLCP</b><span>SM2 双证 + SM4-GCM · 策略下发门控（PDP-07）</span></div><a-switch v-model="tlcp" size="small" /></div>
            <div class="ssl-row"><div><b>抗量子 PQC</b><span>混合密钥交换（X25519 + ML-KEM）· Standard 档（PDP-12）</span></div><a-switch v-model="pqc" size="small" /></div>
            <div class="ssl-row"><div><b>SPA 单包授权</b><span>未授权探测 0 响应（服务隐身）</span></div><span class="zl-badge zl-badge--ok">强制</span></div>
          </div>
        </div>
      </div>

      <!-- 在线会话 -->
      <div class="zl-card">
        <div class="ssl-sess__head">
          <div class="zl-card__title" style="margin:0">在线会话 · {{ gw }}</div>
          <span class="zl-page__sub">{{ sessions.length }} 条 · 吊销传播 ≤10s（ZL-FR-105）</span>
        </div>
        <a-table :data="sessions" :pagination="false" :bordered="false" row-key="id"
                 :row-class="()=>'row-click'" @row-click="openDetail">
          <template #columns>
            <a-table-column title="用户 / 设备">
              <template #cell="{ record }">
                <div style="display:flex;flex-direction:column;gap:1px">
                  <span style="font-weight:600;color:var(--ink);font-size:12.5px">{{ record.user }}</span>
                  <span class="data" style="font-size:11px;color:var(--ink-3)">{{ record.device }} · {{ record.ip }}</span>
                </div>
              </template>
            </a-table-column>
            <a-table-column title="承载" align="center" :width="92">
              <template #cell="{ record }">
                <span class="zl-badge" :class="record.carrier==='DTLS'?'zl-badge--ok':record.carrier==='TLS'?'zl-badge--accent':'zl-badge--warn'">{{ record.carrier }}</span>
              </template>
            </a-table-column>
            <a-table-column title="套件" :width="120">
              <template #cell="{ record }"><span class="data" style="font-size:11.5px;color:var(--ink-2)">{{ record.suite }}</span></template>
            </a-table-column>
            <a-table-column title="时长" align="right" :width="80">
              <template #cell="{ record }"><span class="data">{{ record.dur }}</span></template>
            </a-table-column>
            <a-table-column title="" align="center" :width="80">
              <template #cell="{ record }">
                <a-button size="mini" status="danger" type="text" @click.stop="revoke(record)">吊销</a-button>
              </template>
            </a-table-column>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 会话详情 -->
    <a-drawer v-model:visible="drawer" :width="440" :footer="false">
      <template #title>会话详情 · {{ cur?.user }}</template>
      <div v-if="cur" class="sd">
        <div class="sd-banner">
          <span class="sd-banner__g">{{ cur.carrier==='DTLS' ? '⚡' : cur.carrier==='TLS' ? '🔒' : '🥷' }}</span>
          <div>
            <div class="sd-banner__t">{{ cur.user }} · 在线</div>
            <div class="sd-banner__d">{{ cur.device }} · {{ cur.ip }} · 经 {{ gw }}</div>
          </div>
        </div>

        <div class="sd-sec">承载与密码</div>
        <div class="sd-kv"><span>承载</span><b>{{ carrierFull(cur.carrier) }}</b></div>
        <div class="sd-kv"><span>密码套件</span><b class="data">{{ cur.suite }}</b></div>
        <div class="sd-kv"><span>SPA 敲门</span><b style="color:var(--ok)">已验签放行（Ed25519）</b></div>
        <div class="sd-kv"><span>会话时长</span><b class="data">{{ cur.dur }}</b></div>
        <div class="sd-kv"><span>建立时间</span><b class="data">{{ estAt(cur) }}</b></div>

        <div class="sd-sec">设备态势（posture）</div>
        <div class="sd-posture">
          <span v-for="p in posture(cur)" :key="p.k" class="sd-pchip" :class="p.ok?'ok':'bad'">{{ p.ok?'✓':'✕' }} {{ p.label }}</span>
        </div>

        <div class="sd-sec">可达资源（此会话 netmap 投影）</div>
        <div class="sd-res">
          <div v-for="r in reach(cur)" :key="r.name" class="sd-res__row">
            <span class="zl-mode-pill" :class="`zl-mode--${r.mode}`">{{ r.mode }}</span>
            <span class="sd-res__n">{{ r.name }}</span>
            <span class="data" style="font-size:11px;color:var(--accent-2)">{{ r.policy }}</span>
          </div>
        </div>

        <div class="sd-sec">流量</div>
        <div class="fed-grid">
          <div class="fed-kv"><span>接收</span><b class="data">{{ rxtx(cur).rx }}</b></div>
          <div class="fed-kv"><span>发送</span><b class="data">{{ rxtx(cur).tx }}</b></div>
        </div>

        <div class="sd-foot">
          <a-button size="small" status="warning" @click="forceReauth">强制重认证（step-up）</a-button>
          <a-button size="small" status="danger" type="primary" @click="revoke(cur); drawer=false">吊销会话</a-button>
        </div>
      </div>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref, watch } from 'vue';
import { Message } from '@arco-design/web-vue';

const gw = ref('zl-gw-hq-01');
const chain = reactive([
  { k: 'dtls', name: 'DTLS（UDP 443）', on: true, locked: false, desc: '首选承载：低时延，UDP 通畅网络直接使用' },
  { k: 'tls', name: 'TLS（TCP 443）', on: true, locked: false, desc: 'UDP 受限自动降级；与 HTTPS 同握手外观' },
  { k: 'h443', name: '443 伪装兜底', on: true, locked: true, desc: '深度受限网络（酒店/咖啡厅/运营商 DPI）最后兜底，流量形态不可区分' }
]);
const tlcp = ref(true);
const pqc = ref(false);

/* 在线会话来自控制面 /ctl/api/ssl/sessions?gw=X（数据面会话目录），切换网关重拉、
   吊销走后端（真实环境通知 gateway 断链）；控制面不可达时降级 mock。 */
const mockSessions = [
  { id: 's1', user: 'zhang.wei', device: 'MBP-7F2A', ip: '10.8.3.142', carrier: 'DTLS', suite: 'TLS1.3 X25519', dur: '02:14:08' },
  { id: 's2', user: 'li.na', device: 'iPhone-92', ip: '10.8.7.21', carrier: 'TLS', suite: 'TLCP SM2/SM4', dur: '00:48:33' },
  { id: 's3', user: 'chen.jing', device: 'Pad-1180', ip: '10.8.9.77', carrier: '443伪装', suite: 'TLS1.3 X25519', dur: '00:12:51' },
  { id: 's4', user: 'svc.ci', device: 'ci-runner-01', ip: '10.8.0.55', carrier: 'DTLS', suite: 'TLS1.3 X25519', dur: '6天12h' }
];
const sessions = ref<any[]>([...mockSessions]);
const live = ref(false);
async function loadSessions() {
  try {
    const r = await fetch(`/ctl/api/ssl/sessions?gw=${gw.value}`);
    if (!r.ok) return;
    sessions.value = await r.json();
    live.value = true;
  } catch { live.value = false; }
}
onMounted(loadSessions);
watch(gw, loadSessions); // 切换网关重新拉会话

async function revoke(r: any) {
  if (live.value) {
    try {
      const res = await fetch(`/ctl/api/ssl/sessions?id=${r.id}`, { method: 'DELETE' });
      if (!res.ok) return Message.error('吊销失败');
      await loadSessions();
    } catch { return Message.error('控制面不可达'); }
  } else {
    sessions.value = sessions.value.filter((s) => s.id !== r.id);
  }
  Message.success(`已吊销 ${r.user}@${r.device} 的会话 · 三执行点 ≤10s 生效，审计链已记录`);
}

/* —— 会话详情抽屉 —— */
const drawer = ref(false);
const cur = ref<any>(null);
function openDetail(r: any) { cur.value = r; drawer.value = true; }
function forceReauth() {
  Message.success(`已向 ${cur.value.user}@${cur.value.device} 下发强制重认证 · 客户端 ≤10s 触发 MFA step-up，未通过则会话降级`);
}
const carrierFull = (c: string) => ({ DTLS: 'DTLS（UDP 443，首选低时延）', TLS: 'TLS 1.3（TCP 443，UDP 受限降级）', '443伪装': '443 伪装兜底（与 HTTPS 不可区分）' } as Record<string, string>)[c] || c;
function estAt(r: any) {
  // 由时长粗推建立时刻（演示）
  const m = String(r.dur).match(/(\d+):(\d+):(\d+)/);
  return m ? `今日 ${String(15 - Number(m[1])).padStart(2, '0')}:${m[2]}` : '—';
}
function posture(r: any) {
  const byod = /Pad|BYOD/i.test(r.device);
  return [
    { k: 'disk', label: '磁盘加密', ok: true },
    { k: 'jb', label: '未越狱 / Root', ok: !byod },
    { k: 'os', label: '系统版本合规', ok: true },
    { k: 'edr', label: 'EDR 在线', ok: !byod }
  ];
}
function reach(r: any) {
  const fin = /li\.na|finance/i.test(r.user);
  const base = [
    { name: 'OA 办公系统', mode: 'ssl', policy: 'pol-oa-all' },
    { name: 'GitLab', mode: 'mesh', policy: 'pol-rd-database' }
  ];
  if (fin) base.push({ name: '财务系统', mode: 'ssl', policy: 'pol-finance-fin' });
  return base;
}
function rxtx(r: any) {
  const h = String(r.dur).includes('天') ? 9000 : (Number(String(r.dur).slice(0, 2)) || 1) * 80;
  return { rx: `${(h * 1.7).toFixed(0)} MB`, tx: `${(h * 0.6).toFixed(0)} MB` };
}
</script>

<style scoped>
.ssl-chain { display: flex; flex-direction: column; gap: 10px; }
.ssl-hop { border: 1px solid var(--line); border-radius: var(--r-md); padding: 10px 13px; }
.ssl-hop.off { opacity: .5; }
.ssl-hop__head { display: flex; align-items: center; gap: 9px; margin-bottom: 4px; }
.ssl-hop__head b { flex: 1; font-size: 13px; color: var(--ink); }
.ssl-hop__n { width: 19px; height: 19px; border-radius: 50%; display: grid; place-items: center; font-size: 10.5px; font-weight: 700; background: var(--accent-soft); color: var(--accent-2); }
.ssl-hop__d { font-size: 11.5px; color: var(--ink-3); line-height: 1.55; padding-left: 28px; }
.ssl-note { display: flex; gap: 7px; font-size: 11.5px; color: var(--ink-3); margin-top: 12px; line-height: 1.6; }
.ssl-rows { display: flex; flex-direction: column; }
.ssl-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 0; }
.ssl-row + .ssl-row { border-top: 1px solid var(--line); }
.ssl-row b { display: block; font-size: 13px; color: var(--ink); font-weight: 650; }
.ssl-row span { display: block; font-size: 11.5px; color: var(--ink-3); margin-top: 2px; }
.ssl-sess__head { display: flex; align-items: baseline; justify-content: space-between; padding: 16px 20px 8px; }
:deep(.row-click) { cursor: pointer; }
.sd-banner { display: flex; align-items: center; gap: 12px; padding: 12px 14px; border: 1px solid var(--ok); border-radius: var(--r-md); margin-bottom: 16px; }
.sd-banner__g { width: 34px; height: 34px; border-radius: 50%; display: grid; place-items: center; font-size: 16px; background: var(--ok-soft); }
.sd-banner__t { font-size: 14px; font-weight: 700; color: var(--ink); }
.sd-banner__d { font-size: 11.5px; color: var(--ink-3); margin-top: 2px; }
.sd-sec { font-size: 11.5px; font-weight: 700; color: var(--ink-3); margin: 18px 0 8px; }
.sd-kv { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--line); font-size: 12.5px; }
.sd-kv span { color: var(--ink-3); flex: none; }
.sd-kv b { color: var(--ink); font-weight: 600; text-align: right; }
.sd-posture { display: flex; flex-wrap: wrap; gap: 8px; }
.sd-pchip { font-size: 11.5px; font-weight: 600; padding: 4px 10px; border-radius: var(--r-pill); }
.sd-pchip.ok { background: var(--ok-soft); color: var(--ok); }
.sd-pchip.bad { background: var(--danger-soft); color: var(--danger); }
.sd-res { display: flex; flex-direction: column; gap: 6px; }
.sd-res__row { display: flex; align-items: center; gap: 9px; }
.sd-res__n { flex: 1; font-size: 12.5px; color: var(--ink); }
.fed-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1px; background: var(--line); border: 1px solid var(--line); border-radius: var(--r-md); overflow: hidden; }
.fed-kv { background: var(--surface); padding: 10px 12px; display: flex; flex-direction: column; gap: 4px; }
.fed-kv span { font-size: 11px; color: var(--ink-3); }
.fed-kv b { font-size: 12.5px; color: var(--ink); font-weight: 600; }
.sd-foot { display: flex; justify-content: space-between; gap: 12px; margin-top: 20px; }
</style>
