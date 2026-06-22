<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">Mesh 中继 / 连接器</h1>
        <div class="zl-page__sub">P2P 直连优先，NAT 难穿透时经 derp 中继兜底 · 子网路由暴露内网（DP-01 路径B / 差异化支柱）</div>
      </div>
      <div class="mesh-kpi">
        <div class="mesh-kpi__c"><b class="data">{{ meshStats.directRatio }}%</b><span>P2P 直连率</span></div>
        <div class="mesh-kpi__c"><b class="data">{{ meshStats.nodes }}</b><span>在网节点</span></div>
        <div class="mesh-kpi__c"><b class="data">{{ meshStats.relayFallback }}</b><span>中继回退</span></div>
        <div class="mesh-kpi__c"><b class="data" :style="allowedSvc < 3 ? 'color:var(--danger)' : ''">{{ allowedSvc }}/3</b><span>可达服务·张伟</span></div>
      </div>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1.6fr 1fr;">
      <!-- 拓扑图 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title" style="margin-bottom:6px">Mesh 网络拓扑</div>
        <div class="zl-page__sub" style="margin-bottom:8px">点节点查看其对等连接 · 星型网关产品画不出这张图</div>
        <svg viewBox="0 0 800 470" class="mesh-svg">
          <!-- 边 -->
          <g>
            <line v-for="(e, i) in edges" :key="i"
                  :x1="nodeMap[e.a].x" :y1="nodeMap[e.a].y" :x2="nodeMap[e.b].x" :y2="nodeMap[e.b].y"
                  :class="['mesh-edge', `mesh-edge--${e.type}`, edgeActive(e) ? 'on' : (sel ? 'dim' : '')]" />
            <template v-for="(e, i) in edges" :key="'t'+i">
              <text v-if="e.rtt !== '—' && (edgeActive(e) || !sel)"
                    :x="(nodeMap[e.a].x + nodeMap[e.b].x)/2" :y="(nodeMap[e.a].y + nodeMap[e.b].y)/2 - 4"
                    class="mesh-edge-label data">{{ e.rtt }}</text>
            </template>
          </g>
          <!-- 节点 -->
          <g v-for="n in nodes" :key="n.id" :class="['mesh-node', `mesh-node--${n.kind}`, sel && sel.id !== n.id && !peers.includes(n.id) ? 'faded' : '', sel?.id === n.id ? 'sel' : '']"
             @click="sel = sel?.id === n.id ? null : n">
            <circle :cx="n.x" :cy="n.y" :r="n.kind === 'gateway' ? 26 : n.kind === 'subnet' ? 20 : 19" />
            <text :x="n.x" :y="n.y + 1" class="mesh-node-glyph">{{ glyph(n) }}</text>
            <text :x="n.x" :y="n.y + (n.kind === 'gateway' ? 42 : 34)" class="mesh-node-label">{{ n.label }}</text>
            <text v-if="n.nat" :x="n.x" :y="n.y + (n.kind === 'gateway' ? 56 : 48)" class="mesh-node-nat data">{{ n.nat }}</text>
            <text v-if="n.kind === 'service'" :x="n.x" :y="n.y + 48" class="mesh-node-nat" :style="n.allowed ? 'fill:var(--ok)' : 'fill:var(--danger)'">{{ n.allowed ? '策略放行' : '策略阻断' }}</text>
          </g>
        </svg>
        <div class="mesh-legend">
          <span><i class="lg lg-direct" />P2P 直连（WireGuard）</span>
          <span><i class="lg lg-relay" />中继回退（derp）</span>
          <span><i class="lg lg-route" />子网路由</span>
          <span><i class="lg lg-blocked" />策略阻断（实时求值）</span>
        </div>
      </div>

      <!-- 右侧：节点详情 or 中继/连接器 -->
      <div style="display:flex;flex-direction:column;gap:16px;min-width:0">
        <div class="zl-card zl-card__pad" v-if="sel">
          <div class="zl-card__title">{{ sel.label }}</div>
          <div class="mesh-kv"><span>类型</span><b>{{ kindText(sel.kind) }}{{ sel.relay ? ' · derp 中继' : '' }}{{ sel.connector ? ' · 连接器' : '' }}</b></div>
          <div class="mesh-kv" v-if="sel.os"><span>系统</span><b>{{ sel.os }}</b></div>
          <div class="mesh-kv" v-if="sel.nat"><span>NAT 类型</span><b>{{ sel.nat }}</b></div>
          <template v-if="sel.kind === 'service'">
            <div class="mesh-kv"><span>判定</span>
              <span class="zl-badge" :class="sel.allowed ? 'zl-badge--ok' : 'zl-badge--danger'">{{ sel.allowed ? 'ALLOW' : 'DENY' }}</span>
            </div>
            <div class="mesh-kv"><span>策略</span><b class="data">{{ sel.policy || '—（默认拒绝）' }}</b></div>
            <div class="mesh-kv"><span>原因</span><b style="font-weight:500;font-size:12px">{{ sel.reason }}</b></div>
            <router-link to="/policy/simulator" style="font-size:12px;color:var(--accent-2)">→ 去仿真器复核该判定</router-link>
          </template>
          <div class="mesh-sec">对等连接（{{ peerEdges.length }}）</div>
          <div v-for="(e, i) in peerEdges" :key="i" class="mesh-peer">
            <span class="mesh-peer__dot" :class="`mesh-edge--${e.type}`" />
            <span class="mesh-peer__n">{{ nodeMap[e.a].id === sel.id ? nodeMap[e.b].label : nodeMap[e.a].label }}</span>
            <span class="mesh-peer__t data">{{ e.type === 'direct' ? '直连' : e.type === 'relay' ? '中继' : e.type === 'blocked' ? '策略阻断' : '路由' }} {{ e.rtt }}</span>
          </div>

          <template v-if="sel.kind==='device' || sel.kind==='gateway'">
            <div class="mesh-sec">节点操作</div>
            <a-space wrap size="small">
              <a-button size="mini" @click="nodeAct('repunch', sel)">重置打洞</a-button>
              <a-button size="mini" status="warning" @click="nodeAct('relay', sel)">强制走中继</a-button>
              <a-button size="mini" status="danger" type="outline" @click="nodeAct('offline', sel)">下线节点</a-button>
            </a-space>
          </template>
        </div>

        <div class="zl-card" v-else>
          <div class="mesh-tab"><span class="zl-card__title" style="margin:0;padding:14px 18px 0">derp 中继</span></div>
          <a-table :data="derpRelays" :pagination="false" :bordered="false" row-key="region" size="small">
            <template #columns>
              <a-table-column title="区域" data-index="region" />
              <a-table-column title="中继会话" align="right" :width="80"><template #cell="{ record }"><span class="data">{{ record.sessions }}</span></template></a-table-column>
              <a-table-column title="状态" align="center" :width="64"><template #cell><span class="zl-badge zl-badge--ok">up</span></template></a-table-column>
            </template>
          </a-table>
        </div>

        <!-- 真实在网节点（控制面 /ctl/mesh/peers）-->
        <div class="zl-card" v-if="!sel">
          <div class="mesh-tab" style="display:flex;align-items:center;gap:8px;padding:14px 18px 0">
            <span class="zl-card__title" style="margin:0;padding:0">控制面在网节点</span>
            <span v-if="meshLive" class="zl-badge zl-badge--ok" style="font-size:10px">● /ctl/mesh/peers</span>
            <span v-else class="zl-badge zl-badge--idle" style="font-size:10px">未连控制面</span>
          </div>
          <a-table v-if="realPeers.length" :data="realPeers" :pagination="false" :bordered="false" row-key="id" size="small">
            <template #columns>
              <a-table-column title="节点"><template #cell="{ record }"><span class="data" style="color:var(--ink);font-weight:600">{{ record.id }}</span></template></a-table-column>
              <a-table-column title="公网候选"><template #cell="{ record }"><span class="data" style="font-size:11px">{{ pubCand(record) }}</span></template></a-table-column>
              <a-table-column title="子网路由"><template #cell="{ record }"><span class="data" style="font-size:11px;color:var(--ink-2)">{{ (record.routes || []).join('、') || '—' }}</span></template></a-table-column>
            </template>
          </a-table>
          <div v-else class="idp-note"><icon-info-circle /> 控制面暂无在网节点（起 zhulong-control + mesh 节点注册到 /ctl/mesh/peers 后，实时显示真实组网：节点公网候选与子网路由）。</div>
        </div>

        <div class="zl-card" v-if="!sel">
          <div class="mesh-tab"><span class="zl-card__title" style="margin:0;padding:14px 18px 0">连接器 · 子网路由</span></div>
          <a-table :data="connectors" :pagination="false" :bordered="false" row-key="name" size="small">
            <template #columns>
              <a-table-column title="连接器" data-index="name"><template #cell="{ record }"><span class="data" style="color:var(--ink);font-weight:600">{{ record.name }}</span></template></a-table-column>
              <a-table-column title="发布路由"><template #cell="{ record }"><span class="data" style="font-size:11.5px;color:var(--ink-2)">{{ record.routes.join('、') }}</span></template></a-table-column>
              <a-table-column title="状态" align="center" :width="64"><template #cell="{ record }"><span class="zl-badge" :class="record.status==='online'?'zl-badge--ok':'zl-badge--idle'">{{ record.status==='online'?'在线':'离线' }}</span></template></a-table-column>
            </template>
          </a-table>
          <div class="idp-note"><icon-info-circle /> 子网路由让 Mesh 节点直达内网网段，无需在每台内网主机装客户端（连接器 advertise，控制台审批生效）。</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { Message } from '@arco-design/web-vue';
import { meshNodes, meshEdges, meshStats, derpRelays, connectors, type MeshNode } from '@/mock';
import { evaluate, simSubjects, simResources, policyStore } from '@/policy-store';

function nodeAct(act: string, n: any) {
  const msg: Record<string, string> = {
    repunch: `已对「${n.label}」触发重新打洞 · STUN 反射 + 候选并发探测，确认制 Ping 重测直连`,
    relay: `已将「${n.label}」强制切到 derp 中继 · 直连不可用时的兜底路径（端到端仍 SM4-GCM 加密，中继不解密）`,
    offline: `已将「${n.label}」下线 · 撤销其 node key，netmap 移除该节点路由，≤60s 全网生效`
  };
  Message.success(msg[act]);
}

/* 真实在网节点：控制面 /ctl/mesh/peers（注册的 Mesh 节点目录），控制面不可达时降级 */
const realPeers = ref<any[]>([]);
const meshLive = ref(false);
function pubCand(p: any): string {
  const c = (p.candidates || []).find((x: string) => !x.startsWith('[::]') && !x.startsWith('127.'));
  return c || p.endpoint || '—';
}
async function loadPeers() {
  try {
    const r = await fetch('/ctl/mesh/peers?self=');
    if (!r.ok) { meshLive.value = false; return; }
    realPeers.value = await r.json();
    meshLive.value = true;
  } catch { meshLive.value = false; }
}
onMounted(loadPeers);

/* 张伟视角：mesh 模式可达的服务挂进拓扑，边的通断由策略 store 实时求值（联动核心） */
const ZW = simSubjects[0];
const DEMO_CTX = { mfa: true, posture: true, workhours: true };
const SVC_POS: Record<string, { x: number; y: number; rtt: string }> = {
  'app:gitlab': { x: 85, y: 145, rtt: '11ms' },
  'service:db.corp:5432': { x: 85, y: 255, rtt: '7ms' },
  'service:bastion.corp:22': { x: 85, y: 365, rtt: '14ms' }
};
const svcNodes = computed(() => {
  void policyStore.map((p) => p.enabled); // 显式依赖：策略增删/启停触发重算
  return Object.entries(SVC_POS).map(([key, pos]) => {
    const r = simResources.find((x) => x.key === key)!;
    const v = evaluate(ZW, r, DEMO_CTX);
    return { id: 'svc-' + key, label: r.name, kind: 'service' as const, x: pos.x, y: pos.y,
             allowed: v.decision === 'allow', policy: v.matched, reason: v.reason, rtt: pos.rtt };
  });
});
const svcEdges = computed(() => svcNodes.value.map((s) => ({
  a: 'mbp', b: s.id, type: s.allowed ? ('direct' as const) : ('blocked' as const), rtt: s.allowed ? (s as any).rtt : '✕'
})));
const allowedSvc = computed(() => svcNodes.value.filter((s) => s.allowed).length);

const nodes = computed<any[]>(() => [...meshNodes, ...svcNodes.value]);
const edges = computed(() => [...meshEdges, ...svcEdges.value]);
const nodeMap = computed(() => Object.fromEntries(nodes.value.map((n: any) => [n.id, n])));
const sel = ref<any>(null);

const peerEdges = computed(() => (sel.value ? edges.value.filter((e) => e.a === sel.value!.id || e.b === sel.value!.id) : []));
const peers = computed(() => peerEdges.value.flatMap((e) => [e.a, e.b]));
const edgeActive = (e: any) => sel.value && (e.a === sel.value.id || e.b === sel.value.id);

const glyph = (n: any) =>
  n.kind === 'gateway' ? '🛡' : n.kind === 'subnet' ? '🖧' : n.kind === 'service' ? (n.allowed ? '⚙' : '🚫')
    : n.os === 'HarmonyOS' || n.os === 'iOS' ? '📱'
    : n.os === 'Ubuntu' || n.os === 'Kylin' ? '🖥' : '💻';
const kindText = (k: string) => ({ gateway: '网关', device: '设备节点', subnet: '子网', service: '服务（张伟视角判定）' }[k]);
</script>

<style scoped>
.mesh-kpi { display: flex; gap: 22px; }
.mesh-kpi__c { text-align: right; }
.mesh-kpi__c b { font-size: 20px; font-weight: 750; color: var(--accent-2); display: block; }
.mesh-kpi__c span { font-size: 11px; color: var(--ink-3); }
.mesh-svg { width: 100%; height: auto; display: block; }

.mesh-edge { stroke-width: 2; opacity: .9; transition: opacity .2s; }
.mesh-edge--direct { stroke: var(--ok); }
.mesh-edge--relay { stroke: var(--warn); stroke-dasharray: 6 4; }
.mesh-edge--route { stroke: var(--accent); stroke-dasharray: 2 4; }
.mesh-edge--blocked { stroke: var(--danger); stroke-dasharray: 4 4; opacity: .8; }
.mesh-edge.dim { opacity: .12; }
.mesh-edge.on { opacity: 1; stroke-width: 3; }
.mesh-edge-label { font-size: 10px; fill: var(--ink-3); text-anchor: middle; }

.mesh-node { cursor: pointer; transition: opacity .2s; }
.mesh-node.faded { opacity: .3; }
.mesh-node circle { fill: var(--surface); stroke: var(--line-2); stroke-width: 2; transition: all .15s; }
.mesh-node--gateway circle { fill: var(--accent-soft); stroke: var(--accent); }
.mesh-node--subnet circle { fill: var(--surface-2); stroke: var(--accent-line); stroke-dasharray: 3 3; }
.mesh-node--device circle { fill: var(--surface); stroke: var(--ok); }
.mesh-node--service circle { fill: var(--surface-2); stroke: var(--ink-3); }
.mesh-node.sel circle { stroke-width: 3.5; filter: drop-shadow(0 2px 8px var(--accent-soft)); }
.mesh-node:hover circle { stroke-width: 3; }
.mesh-node-glyph { font-size: 15px; text-anchor: middle; dominant-baseline: middle; }
.mesh-node-label { font-size: 11px; fill: var(--ink); text-anchor: middle; font-weight: 600; }
.mesh-node-nat { font-size: 9.5px; fill: var(--ink-3); text-anchor: middle; }

.mesh-legend { display: flex; gap: 18px; margin-top: 8px; font-size: 11.5px; color: var(--ink-3); }
.mesh-legend span { display: flex; align-items: center; gap: 6px; }
.lg { width: 16px; height: 2.5px; border-radius: 2px; display: inline-block; }
.lg-direct { background: var(--ok); }
.lg-relay { background: var(--warn); }
.lg-route { background: var(--accent); }
.lg-blocked { background: var(--danger); }

.mesh-kv { display: flex; gap: 12px; padding: 7px 0; font-size: 12.5px; }
.mesh-kv > span { color: var(--ink-3); min-width: 64px; }
.mesh-kv b { color: var(--ink); font-weight: 600; }
.mesh-sec { font-size: 11.5px; font-weight: 700; color: var(--ink-3); margin: 14px 0 8px; }
.mesh-peer { display: flex; align-items: center; gap: 9px; padding: 6px 0; border-bottom: 1px solid var(--line); }
.mesh-peer__dot { width: 9px; height: 9px; border-radius: 50%; flex: none; }
.mesh-peer__dot.mesh-edge--direct { background: var(--ok); }
.mesh-peer__dot.mesh-edge--relay { background: var(--warn); }
.mesh-peer__dot.mesh-edge--route { background: var(--accent); }
.mesh-peer__dot.mesh-edge--blocked { background: var(--danger); }
.mesh-peer__n { flex: 1; font-size: 12.5px; color: var(--ink); }
.mesh-peer__t { font-size: 11px; color: var(--ink-3); }
.idp-note { display: flex; gap: 8px; align-items: flex-start; padding: 12px 16px; font-size: 11.5px; color: var(--ink-3); border-top: 1px solid var(--line); line-height: 1.6; }
</style>
