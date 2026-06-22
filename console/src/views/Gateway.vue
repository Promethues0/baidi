<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">网关与隐身</div>
        <div class="bd-page__sub">代理网关区域 / 节点 · SPA 服务隐身：先认证后连接、攻击面收敛至零</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'topo' }" @click="tab = 'topo'">拓扑总览</span>
      <span class="bd-tab" :class="{ on: tab === 'spa' }" @click="tab = 'spa'">SPA 服务隐身</span>
      <span class="bd-tab" :class="{ on: tab === 'zone' }" @click="tab = 'zone'">区域与节点</span>
    </div>

    <!-- ============ 拓扑总览（P8 SVG）============ -->
    <div v-show="tab === 'topo'">
      <div class="bd-card bd-topo">
        <svg viewBox="0 0 960 460" width="100%" preserveAspectRatio="xMidYMid meet" font-family="-apple-system, 'PingFang SC', 'Segoe UI', sans-serif">
          <!-- 控制中心（策略大脑） -->
          <g>
            <rect x="360" y="14" width="240" height="52" rx="10" fill="#F2F7FF" stroke="#BEDAFF" />
            <circle cx="392" cy="40" r="9" fill="#165DFF" />
            <text x="412" y="36" font-size="14" font-weight="600" fill="#1D2129">控制中心 · 策略大脑</text>
            <text x="412" y="53" font-size="12" fill="#86909C">认证决策 / 策略下发 / 服务隐身编排</text>
          </g>

          <!-- 客户端云 -->
          <g>
            <rect x="24" y="184" width="156" height="92" rx="12" fill="#F7F8FA" stroke="#E5E6EB" />
            <text x="102" y="214" font-size="14" font-weight="600" fill="#1D2129" text-anchor="middle">访问者 / 客户端</text>
            <text x="102" y="240" font-size="22" font-weight="700" fill="#165DFF" text-anchor="middle">{{ totalClients }}</text>
            <text x="102" y="261" font-size="12" fill="#86909C" text-anchor="middle">在线终端（SPA 敲门）</text>
          </g>

          <!-- 受保护业务 -->
          <g>
            <rect x="800" y="160" width="136" height="140" rx="12" fill="#F7F8FA" stroke="#E5E6EB" />
            <text x="868" y="190" font-size="14" font-weight="600" fill="#1D2129" text-anchor="middle">受保护业务</text>
            <text x="868" y="226" font-size="26" font-weight="700" fill="#1D2129" text-anchor="middle">{{ totalApps }}</text>
            <text x="868" y="247" font-size="12" fill="#86909C" text-anchor="middle">个已发布应用</text>
            <rect x="824" y="262" width="88" height="24" rx="12" fill="#E8FFEA" />
            <text x="868" y="278" font-size="11" font-weight="600" fill="#0B8235" text-anchor="middle">攻击面 = 0</text>
          </g>

          <!-- 安全代理网关：区域块 -->
          <g v-for="(z, i) in zones" :key="z.key">
            <!-- 数据面：客户端 → 区域（实线） -->
            <path
              :d="`M180 230 C 280 230, 280 ${zoneY(i) + zoneH / 2}, 340 ${zoneY(i) + zoneH / 2}`"
              fill="none" :stroke="strokeColor(z.status)" stroke-width="2"
            />
            <!-- 控制面：控制中心 → 区域（虚线） -->
            <path
              :d="`M480 66 C 480 110, ${zoneCx} ${zoneY(i) - 14}, ${zoneCx} ${zoneY(i)}`"
              fill="none" stroke="#BEDAFF" stroke-width="1.5" stroke-dasharray="4 4"
            />
            <!-- 数据面：区域 → 业务（实线） -->
            <path
              :d="`M620 ${zoneY(i) + zoneH / 2} C 720 ${zoneY(i) + zoneH / 2}, 720 230, 800 230`"
              fill="none" :stroke="strokeColor(z.status)" stroke-width="2"
            />

            <!-- 区域矩形 -->
            <rect x="340" :y="zoneY(i)" width="280" :height="zoneH" rx="10" fill="#FFFFFF" :stroke="strokeColor(z.status)" stroke-width="1.5" />
            <!-- 区域标题 -->
            <circle cx="358" :cy="zoneY(i) + 22" r="5" :fill="strokeColor(z.status)" />
            <text x="372" :y="zoneY(i) + 26" font-size="14" font-weight="600" fill="#1D2129">{{ z.name }}</text>
            <text x="608" :y="zoneY(i) + 26" font-size="11" :fill="strokeColor(z.status)" text-anchor="end" font-weight="600">{{ statusText(z.status) }}</text>

            <!-- 节点行 -->
            <g v-for="(n, j) in z.nodes" :key="n.name">
              <circle cx="358" :cy="nodeY(i, j) + 4" r="4" :fill="strokeColor(n.status)" />
              <text x="372" :y="nodeY(i, j) + 8" font-size="12" fill="#1D2129">{{ n.name }}</text>
              <text x="372" :y="nodeY(i, j) + 24" font-size="11" fill="#86909C" font-family="ui-monospace, monospace">{{ n.ip }}</text>
              <text x="470" :y="nodeY(i, j) + 8" font-size="11" :fill="n.role === 'primary' ? '#165DFF' : '#86909C'">{{ n.role === 'primary' ? '主' : '备' }}</text>
              <!-- load mini bar -->
              <rect x="492" :y="nodeY(i, j) - 1" width="92" height="6" rx="3" fill="#F2F3F5" />
              <rect x="492" :y="nodeY(i, j) - 1" :width="92 * n.loadPct / 100" height="6" rx="3" :fill="loadColor(n.loadPct)" />
              <text x="608" :y="nodeY(i, j) + 22" font-size="11" fill="#86909C" text-anchor="end">{{ n.loadPct }}%</text>
            </g>
          </g>

          <!-- 控制面标注 -->
          <text x="500" y="100" font-size="11" fill="#86909C">策略下发（控制面）</text>

          <!-- 图例 -->
          <g transform="translate(24, 416)">
            <text x="0" y="12" font-size="12" font-weight="600" fill="#4E5969">图例</text>
            <line x1="56" y1="8" x2="84" y2="8" stroke="#86909C" stroke-width="2" />
            <text x="92" y="12" font-size="12" fill="#86909C">数据面（实线）</text>
            <line x1="220" y1="8" x2="248" y2="8" stroke="#BEDAFF" stroke-width="1.5" stroke-dasharray="4 4" />
            <text x="256" y="12" font-size="12" fill="#86909C">控制面（虚线）</text>
            <circle cx="392" cy="8" r="5" fill="#00B42A" /><text x="404" y="12" font-size="12" fill="#86909C">健康</text>
            <circle cx="462" cy="8" r="5" fill="#FF7D00" /><text x="474" y="12" font-size="12" fill="#86909C">降级</text>
            <circle cx="532" cy="8" r="5" fill="#F53F3F" /><text x="544" y="12" font-size="12" fill="#86909C">故障</text>
          </g>
        </svg>
      </div>
    </div>

    <!-- ============ SPA 服务隐身 ============ -->
    <div v-show="tab === 'spa'">
      <div class="bd-spa">
        <!-- 状态总览卡 -->
        <div class="bd-card bd-spacard">
          <div class="bd-section-title">服务隐身状态</div>
          <div class="bd-spa__top">
            <div class="bd-gen">
              <span class="bd-gen__badge">{{ spa.generation }}</span>
              <span class="bd-gen__cap">单包授权代次</span>
            </div>
            <div class="bd-spa__meta">
              <div class="bd-kv"><span>认证模式</span><b>{{ spa.authMode }}</b></div>
              <div class="bd-kv"><span>服务隐身</span>
                <b>
                  <span class="bd-st"><span class="d" :style="{ background: spa.hidden ? 'var(--bd-success)' : 'var(--bd-danger)' }" />{{ spa.hidden ? '已隐身（端口默认丢弃）' : '未隐身' }}</span>
                </b>
              </div>
              <div class="bd-kv"><span>SPA 敲门校验</span>
                <b>
                  <span class="bd-tg" :style="tagStyle(spa.knockOk ? '#00B42A' : '#F53F3F')">
                    {{ spa.knockOk ? '正常' : '异常' }}
                  </span>
                </b>
              </div>
            </div>
          </div>

          <div class="bd-spa__ports">
            <div class="bd-spa__portshead">受保护端口（默认对外不可见，仅 SPA 敲门后短暂放行）</div>
            <div class="bd-spa__portslist">
              <span v-for="p in spa.protectedPorts" :key="p" class="bd-tg bd-port">{{ p }}</span>
            </div>
          </div>
        </div>

        <!-- 隐身效果对比 -->
        <div class="bd-section-title" style="margin-top: 22px">隐身效果 · 未装专属客户端 vs 已装客户端</div>
        <div class="bd-cmp">
          <div class="bd-card bd-cmp__c bd-cmp__c--bad">
            <div class="bd-cmp__h">
              <icon-close-circle-fill class="bd-cmp__ic bad" />未装专属客户端
            </div>
            <ul class="bd-cmp__list">
              <li><icon-info-circle />端口扫描全程超时，<b>无任何端口可探测</b></li>
              <li><icon-info-circle />未通过 SPA 敲门，网关<b>静默丢弃</b>所有报文</li>
              <li><icon-info-circle />无法建立 TCP 连接，<b>无法接入</b>任何业务</li>
              <li><icon-info-circle />在攻击者视角下，网关与业务<b>等同于不存在</b></li>
            </ul>
            <div class="bd-cmp__foot bad">攻击面 = 0 · 先认证后连接</div>
          </div>

          <div class="bd-card bd-cmp__c bd-cmp__c--good">
            <div class="bd-cmp__h">
              <icon-check-circle-fill class="bd-cmp__ic good" />已装专属客户端
            </div>
            <ul class="bd-cmp__list">
              <li><icon-check-circle-fill class="li-ok" />客户端发送 <b>{{ spa.generation }} 单包授权</b>完成身份敲门</li>
              <li><icon-check-circle-fill class="li-ok" />网关校验通过后<b>按需短暂放行</b>受保护端口</li>
              <li><icon-check-circle-fill class="li-ok" />仅放行<b>本人已授权应用</b>，其余仍不可见</li>
              <li><icon-check-circle-fill class="li-ok" />会话结束端口<b>立即重新隐身</b></li>
            </ul>
            <div class="bd-cmp__foot good">认证通过 · 最小化按需暴露</div>
          </div>
        </div>
      </div>
    </div>

    <!-- ============ 区域与节点 ============ -->
    <div v-show="tab === 'zone'" class="bd-zones">
      <div v-for="z in zones" :key="z.key" class="bd-card bd-zcard">
        <div class="bd-zcard__h">
          <span class="bd-st"><span class="d" :style="{ background: strokeColor(z.status) }" /></span>
          <span class="bd-zcard__name">{{ z.name }}</span>
          <a-tag :color="zoneTagColor(z.status)" bordered size="small">{{ statusText(z.status) }}</a-tag>
          <div class="bd-zcard__counts">
            <span><b>{{ z.apps }}</b> 应用</span>
            <span><b>{{ z.clients }}</b> 客户端</span>
            <span><b>{{ z.nodes.length }}</b> 节点</span>
          </div>
        </div>
        <table class="bd-table">
          <thead>
            <tr><th>节点</th><th>IP</th><th>角色</th><th>状态</th><th>负载</th></tr>
          </thead>
          <tbody>
            <tr v-for="n in z.nodes" :key="n.name">
              <td><b style="color: var(--bd-t1); font-weight: 500">{{ n.name }}</b></td>
              <td><span class="bd-mono">{{ n.ip }}</span></td>
              <td>
                <span class="bd-tg" :style="tagStyle(n.role === 'primary' ? '#165DFF' : '#86909C')">{{ n.role === 'primary' ? '主' : '备' }}</span>
              </td>
              <td>
                <span class="bd-st"><span class="d" :style="{ background: strokeColor(n.status) }" />{{ statusText(n.status) }}</span>
              </td>
              <td style="width: 180px">
                <a-progress :percent="n.loadPct / 100" :color="loadColor(n.loadPct)" :show-text="true" :stroke-width="6" />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { api, type GatewayBundle, type GwZone, type SpaStatus } from '@/lib/api';

const tab = ref<'topo' | 'spa' | 'zone'>('topo');
const live = ref(false);

/* ── 内置 mock（结构同后端 GatewayBundle）── */
const MOCK_ZONES: GwZone[] = [
  {
    key: 'dmz', name: 'DMZ 接入区', status: 'healthy', apps: 18, clients: 642,
    nodes: [
      { name: 'gw-dmz-01', ip: '10.10.0.11', role: 'primary', status: 'healthy', loadPct: 47 },
      { name: 'gw-dmz-02', ip: '10.10.0.12', role: 'backup', status: 'healthy', loadPct: 23 }
    ]
  },
  {
    key: 'core', name: '核心业务区', status: 'degraded', apps: 12, clients: 388,
    nodes: [
      { name: 'gw-core-01', ip: '10.20.0.11', role: 'primary', status: 'healthy', loadPct: 81 },
      { name: 'gw-core-02', ip: '10.20.0.12', role: 'backup', status: 'degraded', loadPct: 64 }
    ]
  },
  {
    key: 'edge', name: '分支边缘区', status: 'down', apps: 6, clients: 73,
    nodes: [
      { name: 'gw-edge-01', ip: '10.30.0.11', role: 'primary', status: 'down', loadPct: 0 },
      { name: 'gw-edge-02', ip: '10.30.0.12', role: 'backup', status: 'healthy', loadPct: 35 }
    ]
  }
];
const MOCK_SPA: SpaStatus = {
  generation: 'G3',
  authMode: 'SPA 单包授权 + mTLS 双向证书',
  protectedPorts: ['443/HTTPS', '8443/HTTPS', '22/SSH', '3389/RDP', '5432/PG', '6379/Redis'],
  hidden: true,
  knockOk: true
};

const zones = ref<GwZone[]>(MOCK_ZONES);
const spa = ref<SpaStatus>(MOCK_SPA);

const totalClients = computed(() => zones.value.reduce((s, z) => s + z.clients, 0));
const totalApps = computed(() => zones.value.reduce((s, z) => s + z.apps, 0));

/* ── SVG 布局辅助 ── */
const zoneH = 108;
const zoneGap = 22;
const zoneTop = 96;
const zoneCx = 480;
function zoneY(i: number) { return zoneTop + i * (zoneH + zoneGap); }
function nodeY(i: number, j: number) { return zoneY(i) + 46 + j * 30; }

/* ── 颜色 / 文案 ── */
function strokeColor(status: string) {
  return status === 'healthy' ? '#00B42A' : status === 'degraded' ? '#FF7D00' : status === 'down' ? '#F53F3F' : '#86909C';
}
function loadColor(pct: number) {
  return pct >= 80 ? '#F53F3F' : pct >= 60 ? '#FF7D00' : '#00B42A';
}
function statusText(status: string) {
  return status === 'healthy' ? '健康' : status === 'degraded' ? '降级' : status === 'down' ? '故障' : status;
}
function zoneTagColor(status: string) {
  return status === 'healthy' ? 'green' : status === 'degraded' ? 'orange' : 'red';
}
function tagStyle(color: string) { return { color, background: color + '14' }; }

onMounted(async () => {
  try {
    const b = await api<GatewayBundle>('/gateway');
    zones.value = b.zones; spa.value = b.spa; live.value = true;
  } catch { live.value = false; }
});
</script>

<style scoped>
/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

/* 拓扑卡 */
.bd-topo { padding: 16px 18px; }
.bd-topo svg { display: block; }

/* SPA */
.bd-spa { max-width: 1080px; }
.bd-spacard { padding: 18px 20px 20px; }
.bd-section-title { font-size: 15px; font-weight: 600; color: var(--bd-t1); margin-bottom: 14px; }
.bd-spa__top { display: flex; gap: 28px; align-items: stretch; }
.bd-gen { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; width: 168px; flex: none; background: var(--bd-primary-1); border: 1px solid var(--bd-primary-b); border-radius: var(--bd-radius); padding: 18px 0; }
.bd-gen__badge { font-size: 40px; font-weight: 800; color: var(--bd-primary); line-height: 1; letter-spacing: 1px; }
.bd-gen__cap { font-size: 12px; color: var(--bd-t3); }
.bd-spa__meta { flex: 1; min-width: 0; display: flex; flex-direction: column; justify-content: center; }
.bd-kv { display: flex; align-items: center; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid var(--bd-fill-1); font-size: 13px; }
.bd-kv:last-child { border-bottom: none; }
.bd-kv span { color: var(--bd-t3); }
.bd-kv b { font-weight: 500; color: var(--bd-t1); }

.bd-spa__ports { margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--bd-fill-2); }
.bd-spa__portshead { font-size: 12.5px; color: var(--bd-t3); margin-bottom: 12px; }
.bd-spa__portslist { display: flex; flex-wrap: wrap; gap: 10px; }
.bd-port { font-size: 12.5px; padding: 5px 12px; border-radius: 14px; background: var(--bd-fill-2); color: var(--bd-t2); font-family: ui-monospace, monospace; }

/* 对比卡 */
.bd-cmp { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.bd-cmp__c { padding: 18px 20px; }
.bd-cmp__c--bad { border-color: var(--bd-tag-red-bg); background: linear-gradient(180deg, #FFF8F7 0%, #fff 60%); }
.bd-cmp__c--good { border-color: var(--bd-tag-green-bg); background: linear-gradient(180deg, #F6FFF8 0%, #fff 60%); }
.bd-cmp__h { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--bd-t1); margin-bottom: 14px; }
.bd-cmp__ic { font-size: 18px; }
.bd-cmp__ic.bad { color: var(--bd-danger); }
.bd-cmp__ic.good { color: var(--bd-success); }
.bd-cmp__list { list-style: none; margin: 0; padding: 0; }
.bd-cmp__list li { display: flex; align-items: flex-start; gap: 8px; font-size: 13px; color: var(--bd-t2); line-height: 1.7; padding: 5px 0; }
.bd-cmp__list li :deep(svg) { flex: none; margin-top: 4px; color: var(--bd-t4); font-size: 13px; }
.bd-cmp__list li :deep(svg.li-ok) { color: var(--bd-success); }
.bd-cmp__list b { color: var(--bd-t1); font-weight: 600; }
.bd-cmp__foot { margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--bd-fill-2); font-size: 12.5px; font-weight: 600; }
.bd-cmp__foot.bad { color: var(--bd-danger); }
.bd-cmp__foot.good { color: #0B8235; }

/* 区域与节点 */
.bd-zones { display: flex; flex-direction: column; gap: 16px; }
.bd-zcard { overflow: hidden; }
.bd-zcard__h { display: flex; align-items: center; gap: 10px; padding: 16px 18px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-zcard__name { font-size: 15px; font-weight: 600; color: var(--bd-t1); }
.bd-zcard__counts { margin-left: auto; display: flex; gap: 20px; font-size: 12.5px; color: var(--bd-t3); }
.bd-zcard__counts b { font-size: 15px; font-weight: 700; color: var(--bd-t1); margin-right: 3px; }
</style>
