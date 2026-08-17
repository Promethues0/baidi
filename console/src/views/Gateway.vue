<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">网关与隐身</div>
        <div class="bd-page__sub">已注册数据面网关 · SPA 服务隐身：先认证后连接、攻击面收敛至零</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '后端未连接' }}</a-tag>
        <a-button @click="load"><template #icon><icon-refresh /></template>刷新</a-button>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'topo' }" @click="tab = 'topo'">拓扑总览</span>
      <span class="bd-tab" :class="{ on: tab === 'spa' }" @click="tab = 'spa'">SPA 服务隐身</span>
      <span class="bd-tab" :class="{ on: tab === 'node' }" @click="tab = 'node'">网关节点</span>
    </div>

    <!-- 空态：一台网关都没注册。整页不画任何拓扑——
         此前这里会渲染「华东/华南出口」四台编造节点，运维对着不存在的拓扑排查不了任何问题。 -->
    <div v-if="!nodes.length" class="bd-card bd-empty">
      <icon-exclamation-circle-fill class="bd-empty__ic" />
      <div class="bd-empty__t">尚无数据面网关经 mTLS 注册</div>
      <div class="bd-empty__d">
        本页只展示注册心跳上报的真实网关。以 <code>-control</code> 指向本控制面、并带上
        <code>-mtls-cert/-mtls-key/-mtls-ca</code> 启动 <code>baidi-gateway</code>，注册后此处才有事实可报。
      </div>
      <div class="bd-empty__d">
        控制面自身可独立运行；没有网关不代表控制面异常，但也意味着<b>此刻没有任何隧道接入能力</b>。
      </div>
    </div>

    <template v-else>
      <!-- ============ 拓扑总览 ============ -->
      <div v-show="tab === 'topo'">
        <div class="bd-card bd-topo">
          <svg :viewBox="`0 0 960 ${svgH}`" width="100%" preserveAspectRatio="xMidYMid meet"
               font-family="-apple-system, 'PingFang SC', 'Segoe UI', sans-serif">
            <!-- 控制中心 -->
            <g>
              <rect x="360" y="14" width="240" height="52" rx="10" fill="#F2F7FF" stroke="#BEDAFF" />
              <circle cx="392" cy="40" r="9" fill="#165DFF" />
              <text x="412" y="36" font-size="14" font-weight="600" fill="#1D2129">控制中心 · 策略大脑</text>
              <text x="412" y="53" font-size="12" fill="#86909C">认证决策 / 策略下发 / 敲门令牌签发</text>
            </g>

            <!-- 访问者 -->
            <g>
              <rect x="24" y="184" width="156" height="92" rx="12" fill="#F7F8FA" stroke="#E5E6EB" />
              <text x="102" y="214" font-size="14" font-weight="600" fill="#1D2129" text-anchor="middle">访问者 / 客户端</text>
              <text x="102" y="240" font-size="22" font-weight="700" fill="#165DFF" text-anchor="middle">{{ bundle.sessions }}</text>
              <text x="102" y="261" font-size="12" fill="#86909C" text-anchor="middle">在线网关上报的会话</text>
            </g>

            <!-- 受保护业务 -->
            <g>
              <rect x="800" y="176" width="136" height="108" rx="12" fill="#F7F8FA" stroke="#E5E6EB" />
              <text x="868" y="206" font-size="14" font-weight="600" fill="#1D2129" text-anchor="middle">受保护业务</text>
              <text x="868" y="238" font-size="24" font-weight="700" fill="#1D2129" text-anchor="middle">{{ bundle.total ? totalTunnels : 0 }}</text>
              <text x="868" y="258" font-size="12" fill="#86909C" text-anchor="middle">活跃隧道连接</text>
            </g>

            <!-- 网关节点 -->
            <g v-for="(n, i) in nodes" :key="n.id">
              <path :d="`M180 230 C 280 230, 280 ${nodeY(i) + nodeH / 2}, 340 ${nodeY(i) + nodeH / 2}`"
                    fill="none" :stroke="statusColor(n.online)" stroke-width="2" />
              <path :d="`M480 66 C 480 110, 480 ${nodeY(i) - 14}, 480 ${nodeY(i)}`"
                    fill="none" stroke="#BEDAFF" stroke-width="1.5" stroke-dasharray="4 4" />
              <path :d="`M620 ${nodeY(i) + nodeH / 2} C 720 ${nodeY(i) + nodeH / 2}, 720 230, 800 230`"
                    fill="none" :stroke="statusColor(n.online)" stroke-width="2" />

              <rect x="340" :y="nodeY(i)" width="280" :height="nodeH" rx="10" fill="#FFFFFF"
                    :stroke="statusColor(n.online)" stroke-width="1.5" />
              <circle cx="358" :cy="nodeY(i) + 22" r="5" :fill="statusColor(n.online)" />
              <text x="372" :y="nodeY(i) + 26" font-size="14" font-weight="600" fill="#1D2129">{{ n.id }}</text>
              <text x="608" :y="nodeY(i) + 26" font-size="11" :fill="statusColor(n.online)" text-anchor="end"
                    font-weight="600">{{ n.online ? '在线' : '心跳超时' }}</text>
              <text x="372" :y="nodeY(i) + 48" font-size="11" fill="#86909C" font-family="ui-monospace, monospace">
                敲门口 {{ n.spa || '—' }} · 隧道口 {{ n.proxy || '—' }}
              </text>
              <text x="372" :y="nodeY(i) + 66" font-size="11" fill="#86909C">
                会话 {{ n.sessions }} · 隧道 {{ n.tunnels }} · 放行源 {{ n.clients }}
              </text>
              <text x="608" :y="nodeY(i) + 66" font-size="11" fill="#86909C" text-anchor="end">{{ n.version || '版本未上报' }}</text>
            </g>

            <text x="500" y="100" font-size="11" fill="#86909C">策略下发（控制面）</text>

            <g :transform="`translate(24, ${svgH - 30})`">
              <text x="0" y="12" font-size="12" font-weight="600" fill="#4E5969">图例</text>
              <line x1="56" y1="8" x2="84" y2="8" stroke="#86909C" stroke-width="2" />
              <text x="92" y="12" font-size="12" fill="#86909C">数据面（实线）</text>
              <line x1="220" y1="8" x2="248" y2="8" stroke="#BEDAFF" stroke-width="1.5" stroke-dasharray="4 4" />
              <text x="256" y="12" font-size="12" fill="#86909C">控制面（虚线）</text>
              <circle cx="392" cy="8" r="5" fill="#00B42A" /><text x="404" y="12" font-size="12" fill="#86909C">在线</text>
              <circle cx="462" cy="8" r="5" fill="#F53F3F" /><text x="474" y="12" font-size="12" fill="#86909C">心跳超时</text>
            </g>
          </svg>
        </div>
      </div>

      <!-- ============ SPA 服务隐身 ============ -->
      <div v-show="tab === 'spa'">
        <div class="bd-spa">
          <div class="bd-card bd-spacard">
            <div class="bd-section-title">服务隐身状态</div>
            <div class="bd-spa__meta">
              <div class="bd-kv"><span>认证模式</span><b>先认证后连接：SPA 敲门 + mTLS 机器身份 + 证书指纹钉扎</b></div>
              <div class="bd-kv"><span>敲门令牌</span>
                <b>控制面签发的一次性短时效令牌 · 有效期 {{ bundle.knockTokenTtlSec }} 秒</b>
              </div>
              <div class="bd-kv"><span>在线网关</span>
                <b>{{ bundle.online }} / {{ bundle.total }} 台（判据：{{ bundle.onlineWindowSec }} 秒内有心跳）</b>
              </div>
            </div>

            <div class="bd-spa__ports">
              <div class="bd-spa__portshead">
                各网关上报的监听口（未通过敲门时由内核态规则默认丢弃）
              </div>
              <div class="bd-spa__portslist">
                <span v-for="n in nodes" :key="n.id" class="bd-tg bd-port">
                  {{ n.id }} · 敲门 {{ n.spa || '—' }} · 隧道 {{ n.proxy || '—' }}
                </span>
              </div>
              <!-- ★这段注记不是免责声明，是口径说明：控制面只转述网关上报的事实，
                   "端口在公网上到底可不可见"要从外部实测，白帝没有做这件事。
                   原实现里那个恒为 true 的「已隐身」开关就是在替一台可能压根没配
                   防火墙规则的网关打包票。 -->
              <div class="bd-spa__note">
                控制面不从外部实测端口可见性：以上为网关自报的监听地址。隐身是否真的生效，
                请从外网侧扫描验证（未敲门时应表现为超时而非拒绝）。
              </div>
            </div>
          </div>

          <div class="bd-section-title" style="margin-top: 22px">隐身效果 · 未装专属客户端 vs 已装客户端</div>
          <div class="bd-cmp">
            <div class="bd-card bd-cmp__c bd-cmp__c--bad">
              <div class="bd-cmp__h"><icon-close-circle-fill class="bd-cmp__ic bad" />未装专属客户端</div>
              <ul class="bd-cmp__list">
                <li><icon-info-circle />端口扫描全程超时，<b>无任何端口可探测</b></li>
                <li><icon-info-circle />未通过 SPA 敲门，网关<b>静默丢弃</b>所有报文</li>
                <li><icon-info-circle />无法建立 TCP 连接，<b>无法接入</b>任何业务</li>
                <li><icon-info-circle />在攻击者视角下，网关与业务<b>等同于不存在</b></li>
              </ul>
              <div class="bd-cmp__foot bad">攻击面 = 0 · 先认证后连接</div>
            </div>

            <div class="bd-card bd-cmp__c bd-cmp__c--good">
              <div class="bd-cmp__h"><icon-check-circle-fill class="bd-cmp__ic good" />已装专属客户端</div>
              <ul class="bd-cmp__list">
                <li><icon-check-circle-fill class="li-ok" />客户端先向控制面换取<b>一次性敲门令牌</b>（受账号状态/终端合规闸约束）</li>
                <li><icon-check-circle-fill class="li-ok" />网关校验通过后<b>按需短暂放行</b>该源地址</li>
                <li><icon-check-circle-fill class="li-ok" />仅放行<b>本人已授权资源</b>，其余仍不可见</li>
                <li><icon-check-circle-fill class="li-ok" />放行窗口到期<b>立即重新隐身</b></li>
              </ul>
              <div class="bd-cmp__foot good">认证通过 · 最小化按需暴露</div>
            </div>
          </div>
        </div>
      </div>

      <!-- ============ 网关节点 ============ -->
      <div v-show="tab === 'node'">
        <div class="bd-card">
          <table class="bd-table">
            <thead>
              <tr>
                <!-- ★「对外接入地址」与「敲门口/隧道口」是两回事：后者是网关自报的**监听**地址
                     （默认 ':18201' 不带 host），前者才是客户端真正会去拨的地址。
                     没登记时剖面只能拿全局兜底去猜，症状是「显示在线却连不上」。 -->
                <th>网关</th><th>对外接入地址</th><th>敲门口</th><th>隧道口</th><th>状态</th>
                <th>会话</th><th>隧道</th><th>放行源</th><th>版本</th><th>时钟偏差</th><th>运行时长</th><th>最后心跳</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="n in nodes" :key="n.id">
                <td><b style="color: var(--bd-t1); font-weight: 500">{{ n.id }}</b></td>
                <td>
                  <template v-if="n.accessConfigured">
                    <div v-if="n.lanHost" class="bd-mono bd-acc"><i>内网</i>{{ n.lanHost }}</div>
                    <div v-if="n.wanHost" class="bd-mono bd-acc"><i>互联网</i>{{ n.wanHost }}</div>
                  </template>
                  <span v-else class="bd-acc__none" title="未登记时客户端拿到的是全局兜底地址（多为 127.0.0.1），会拨号超时——而这一页仍显示在线">
                    <icon-exclamation-circle-fill />未登记
                  </span>
                  <button type="button" class="bd-link bd-acc__edit" @click="openAccess(n)">编辑</button>
                </td>
                <td><span class="bd-mono">{{ n.spa || '—' }}</span></td>
                <td><span class="bd-mono">{{ n.proxy || '—' }}</span></td>
                <td>
                  <span class="bd-st">
                    <span class="d" :style="{ background: statusColor(n.online) }" />{{ n.online ? '在线' : '心跳超时' }}
                  </span>
                </td>
                <td>{{ n.sessions }}</td>
                <td>{{ n.tunnels }}</td>
                <td>{{ n.clients }}</td>
                <!-- 旧网关不上报版本：显示 — 而不是猜一个 -->
                <td><span class="bd-mono">{{ n.version || '—' }}</span></td>
                <!-- 时钟偏差三态：null=未上报（不可判定，绝不显示 0）；超 10s 标黄提醒。
                     敲门令牌是控制面签、网关验的，这一列漂过令牌有效期时敲门全灭且无报错。 -->
                <td>
                  <span v-if="n.skewSec === null || n.skewSec === undefined" style="color: var(--bd-t3)">未上报</span>
                  <span v-else :style="{ color: Math.abs(n.skewSec) > 10 ? 'var(--bd-warning, #FF7D00)' : 'var(--bd-t2)' }" class="bd-mono">
                    {{ n.skewSec > 0 ? '+' : '' }}{{ n.skewSec }}s
                  </span>
                </td>
                <td>{{ humanUptime(n.uptime) }}</td>
                <td>{{ sinceText(n.lastSeen) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
    <!-- 对外接入地址（PRD FR-SCEN-08/17）。★两栏都可留空，都空即撤销登记。
         端口刻意不收：它的权威来源是网关自报的监听地址，收第二份就会有两个真相，
         而不一致时症状是「敲门发到 A 口、隧道拨到 B 口」，两边日志都正常。 -->
    <a-modal v-model:visible="acc.open" :title="`网关「${acc.id}」的对外接入地址`" :width="520"
      :ok-loading="acc.busy" ok-text="保存" cancel-text="取消" @ok="saveAccess">
      <div class="bd-accnote">
        客户端会照这两个地址拨号。它与网关自报的<b>监听地址</b>是两回事——网关默认监听
        <code>:18201</code>，无从知道自己在 NAT / 负载均衡后面对外是什么地址。
        两栏都填时，客户端按<b>内网优先</b>的顺序依次尝试（拨不通自动切下一个）。
      </div>
      <div class="bd-accfld">
        <label>局域网访问地址</label>
        <a-input v-model="acc.lan" placeholder="如 10.0.0.9 或 gw-lan.corp.internal" allow-clear />
        <span class="bd-accfld__d">内网终端用的地址。只填主机名或 IP，不要带端口和协议。</span>
      </div>
      <div class="bd-accfld">
        <label>互联网访问地址</label>
        <a-input v-model="acc.wan" placeholder="如 gw.example.com 或 203.0.113.9" allow-clear />
        <span class="bd-accfld__d">公网终端用的地址。内外网想用同一个域名（分区 DNS）时，两栏填一样即可。</span>
      </div>
      <div v-if="acc.err" class="bd-accerr"><icon-close-circle-fill />{{ acc.err }}</div>
    </a-modal>
</template>

<script setup lang="ts">
/**
 * 网关与隐身页。
 *
 * ★整页数据来自 GET /api/v1/gateway，而该端点读的是 mTLS 注册心跳的在线登记
 * （与 GET /api/v1/gateways、诊断页的「数据面网关在线 / SPA 服务隐身」同一份）。
 *
 * 此前这里有一份 MOCK_ZONES：三个区域、六台带主备角色与负载百分比的节点，
 * 全是编的，而且后端种子也是编的——两边都假，看起来严丝合缝。现在页面**没有
 * 任何内置演示数据**：拉不到就说拉不到，没网关就是空态。
 *
 * 去掉的维度与理由：
 *  - 区域：白帝没有区域概念（apps.node 里那列区域名没有任何消费方），
 *    做成网关自报字段既不可验证也不参与任何判定，那是又一个 config-only；
 *  - 主/备角色：没有选主机制；
 *  - 负载百分比：不采集网关负载（宿主机指标另有「设备状态」页，走 metrics 时序）。
 */
import { ref, reactive, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type GatewayBundle, type GwNode } from '@/lib/api';

const tab = ref<'topo' | 'spa' | 'node'>('topo');
const live = ref(false);

const EMPTY: GatewayBundle = {
  nodes: [], total: 0, online: 0, sessions: 0, onlineWindowSec: 0, knockTokenTtlSec: 0
};
const bundle = ref<GatewayBundle>(EMPTY);
const nodes = computed<GwNode[]>(() => bundle.value.nodes ?? []);
const totalTunnels = computed(() => nodes.value.filter((n) => n.online).reduce((s, n) => s + n.tunnels, 0));

/* ── SVG 布局 ── */
const nodeH = 86;
const nodeGap = 20;
const nodeTop = 96;
function nodeY(i: number) { return nodeTop + i * (nodeH + nodeGap); }
const svgH = computed(() => Math.max(460, nodeTop + nodes.value.length * (nodeH + nodeGap) + 60));

function statusColor(online: boolean) { return online ? '#00B42A' : '#F53F3F'; }

function humanUptime(sec: number): string {
  if (!sec) return '—';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d) return `${d} 天 ${h} 小时`;
  if (h) return `${h} 小时 ${m} 分`;
  return `${m} 分`;
}

function sinceText(ts: number): string {
  if (!ts) return '—';
  const sec = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (sec < 60) return `${sec} 秒前`;
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟前`;
  return `${Math.floor(sec / 3600)} 小时前`;
}

async function load(): Promise<void> {
  try {
    bundle.value = await api<GatewayBundle>('/gateway');
    live.value = true;
  } catch {
    // 拉不到就是拉不到：清空而不是回落到演示拓扑。
    bundle.value = EMPTY;
    live.value = false;
  }
}

/* ── 对外接入地址（wave8 行动 4）── */
const acc = reactive({ open: false, busy: false, id: '', lan: '', wan: '', err: '' });
function openAccess(n: GwNode) {
  Object.assign(acc, { open: true, busy: false, id: n.id, lan: n.lanHost ?? '', wan: n.wanHost ?? '', err: '' });
}
async function saveAccess() {
  acc.busy = true; acc.err = '';
  try {
    await api(`/gateway/${encodeURIComponent(acc.id)}/access`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lanHost: acc.lan.trim(), wanHost: acc.wan.trim() })
    });
    acc.open = false;
    Message.success('接入地址已保存，客户端下次拉取剖面即生效');
    await load();
  } catch (e) {
    // 后端的校验文案要原样透出：它说清了为什么这个地址必然连不通（回环 / 带端口 / 带协议）
    acc.err = (e as Error).message || '保存失败';
  } finally { acc.busy = false; }
}

onMounted(load);
</script>

<style scoped>
/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

/* 空态 */
.bd-empty { padding: 40px 24px; text-align: center; }
.bd-empty__ic { font-size: 30px; color: var(--bd-warning); }
.bd-empty__t { margin-top: 12px; font-size: 15px; font-weight: 600; color: var(--bd-t1); }
.bd-empty__d { margin-top: 8px; font-size: 13px; color: var(--bd-t3); line-height: 1.8; }
.bd-empty__d code { font-family: ui-monospace, monospace; background: var(--bd-fill-2); padding: 1px 6px; border-radius: 4px; }

/* 拓扑卡 */
.bd-topo { padding: 16px 18px; }
.bd-topo svg { display: block; }

/* SPA */
.bd-spa { max-width: 1080px; }
.bd-spacard { padding: 18px 20px 20px; }
.bd-section-title { font-size: 15px; font-weight: 600; color: var(--bd-t1); margin-bottom: 14px; }
.bd-spa__meta { display: flex; flex-direction: column; }
.bd-kv { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding: 10px 0; border-bottom: 1px solid var(--bd-fill-1); font-size: 13px; }
.bd-kv:last-child { border-bottom: none; }
.bd-kv span { color: var(--bd-t3); flex: none; }
.bd-kv b { font-weight: 500; color: var(--bd-t1); text-align: right; }

.bd-spa__ports { margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--bd-fill-2); }
.bd-spa__portshead { font-size: 12.5px; color: var(--bd-t3); margin-bottom: 12px; }
.bd-spa__portslist { display: flex; flex-wrap: wrap; gap: 10px; }
.bd-port { font-size: 12.5px; padding: 5px 12px; border-radius: 14px; background: var(--bd-fill-2); color: var(--bd-t2); font-family: ui-monospace, monospace; }
.bd-spa__note { margin-top: 12px; font-size: 12.5px; color: var(--bd-t3); line-height: 1.7; }

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
/* 对外接入地址列 */
.bd-acc { font-size: 12px; line-height: 1.7; white-space: nowrap; }
.bd-acc i { display: inline-block; min-width: 42px; margin-right: 6px; font-style: normal; color: var(--bd-t3); font-size: 11px; }
.bd-acc__none { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; color: var(--bd-warning, #FF7D00); }
.bd-acc__edit { margin-left: 10px; font-size: 12px; }
.bd-accnote { font-size: 12.5px; line-height: 1.8; color: var(--bd-t2); background: var(--bd-fill-1);
  padding: 10px 12px; border-radius: 8px; margin-bottom: 14px; }
.bd-accnote code { font-family: var(--bd-mono, monospace); background: var(--bd-fill-2, #f2f3f5); padding: 0 4px; border-radius: 3px; }
.bd-accfld { margin-bottom: 14px; }
.bd-accfld label { display: block; font-size: 13px; font-weight: 500; color: var(--bd-t1); margin-bottom: 6px; }
.bd-accfld__d { display: block; margin-top: 5px; font-size: 12px; color: var(--bd-t3); line-height: 1.6; }
.bd-accerr { display: flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--bd-danger);
  background: var(--bd-tag-red-bg, #FFECE8); padding: 8px 12px; border-radius: 6px; }
</style>
