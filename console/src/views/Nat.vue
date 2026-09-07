<template>
  <div class="bd-page">
    <PageHeader title="地址转换" :live="live" off-text="数据未读取" off-color="red"
      subtitle="把网关复用为出口 / 发布路由设备 · SNAT 代理上网与 DNAT 资源发布 · 规则由控制面编译后灌入网关内核">
      <!-- ★这一页最要紧的两列（网关回执、命中计数）是**运行态**：网关每个心跳周期上报一次。
           此前没有任何刷新入口，也不显示数据时间——页面上那份回执定格在打开那一刻，
           管理员改完规则盯着看，会以为网关一直没装上。 -->
      <span v-if="fetchedAt" class="bd-natts">数据时间 {{ fetchedAt }}</span>
      <button class="bd-btn bd-btn--ghost" :disabled="busy" @click="load()"><icon-refresh />刷新</button>
      <button class="bd-btn" :disabled="!ifaceReady" @click="openWizard()">
        <icon-plus />新增策略
      </button>
    </PageHeader>

    <!-- 风险提示（FR-NAT-12/11/16）：文案由后端下发，前端不自行编写——
         这几条是安全结论，写在前端就会与后端的实际行为脱节。 -->
    <div v-for="(w, i) in warnings" :key="i" class="bd-notice bd-notice--warn">
      <icon-exclamation-circle-fill /><span>{{ w }}</span>
    </div>

    <div v-if="err" class="bd-notice bd-notice--danger"><icon-close-circle-fill /><span>{{ err }}</span></div>

    <div class="bd-two">
      <!-- 网卡台账 -->
      <div class="bd-card bd-ifaces">
        <div class="bd-card__h">
          网关网卡
          <span class="bd-card__h-sub">实测上报</span>
        </div>
        <div class="bd-card__b">
          <SkeletonBlock v-if="!loaded" kind="text" :rows="4" />
          <!-- ★读取失败必须排在「还没有网关上报网卡」之前：/nat 拉不到时 ifaces 被清空，与「一张网卡都没报」
               完全同形；落进下面那个 warn 空态，管理员会照着它去升级网关、查心跳——而读不出来的是控制面这一侧，
               网关有没有报网卡此刻根本不可判定。tone=danger + 转述后端原话（与 Gateway 页同款）。 -->
          <EmptyState v-else-if="loadErr" size="sm" tone="danger" title="网卡清单未读取"
            :desc="`${loadErr}——网卡与策略来自同一次 GET /api/v1/nat，这里显示的不是「没有网关上报网卡」。`" />
          <EmptyState v-else-if="!ifaces.length" size="sm" tone="warn" title="还没有网关上报网卡。"
            desc="网卡清单随网关 mTLS 心跳上报，需网关运行 v0.4 及以上版本。" />
          <div v-for="g in ifaceGroups" :key="g.gatewayId" class="bd-ifgrp">
            <div class="bd-ifgrp__h"><icon-storage />{{ g.gatewayId }}</div>
            <div v-for="f in g.list" :key="f.name" class="bd-ifrow">
              <div class="bd-ifrow__l">
                <b class="bd-mono">{{ f.name }}</b>
                <span v-if="!f.up" class="bd-tg bd-tg--grey">未启用</span>
                <i class="bd-mono">{{ f.addrs.join(' · ') || '无 IPv4 地址' }}</i>
              </div>
              <!-- 用包裹层定宽而不是给 a-select 加 class：Arco 的 .arco-select 自带
                   width:100% 且选择器特异性更高，直接写 .bd-iftype{width:116px} 会被顶掉，
                   后果是下拉框撑满整行、把左边的网卡名与 IP 压成 0 宽（本页第一版就是这样）。 -->
              <div class="bd-iftype">
                <a-select :model-value="f.type" size="mini" :disabled="busy"
                  @update:model-value="(v: unknown) => setType(f, String(v))">
                  <a-option value="">未定性</a-option>
                  <a-option value="lan">LAN 口（对内）</a-option>
                  <a-option value="wan">WAN 口（对外）</a-option>
                </a-select>
              </div>
            </div>
          </div>
          <div class="bd-notice bd-notice--plain bd-ifaces__note">
            <icon-info-circle />
            <span>LAN/WAN 由管理员指定：网关没有可靠依据自动分辨哪张卡对公网（有默认路由 ≠ 对公网）。
            未定性的网卡不能出现在策略里。</span>
          </div>
        </div>
      </div>

      <!-- 策略表 -->
      <div class="bd-tablecard bd-two__main">
        <div class="bd-toolbar">
          <span v-if="loadErr" class="bd-toolbar__c">策略数未读取</span>
          <span v-else class="bd-toolbar__c">共 {{ policies.length }} 条策略</span>
          <div class="bd-toolbar__spacer" />
        </div>
        <!-- 首屏骨架：load() 回来之前不画表头下面的空白，也不画任何假行 -->
        <SkeletonBlock v-if="!loaded" kind="table" :rows="4" :cols="9" />
        <div v-else class="bd-tablewrap">
        <table class="bd-table">
          <thead>
            <tr>
              <!-- ★「管理意图」与「网关回执」必须分成两栏。合成一个「状态」的话，
                   开关本身就是渲染内容，而「网关没开 -nat」「规则灌不进内核」这两种
                   失效与正常完全同形——网关侧还一行日志都不打。 -->
              <th>策略名称</th><th>类型</th><th>网关</th><th>匹配</th><th>转换后</th>
              <th>管理意图</th><th>网关回执</th><th>命中</th><th class="r">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in policies" :key="p.id">
              <td><b>{{ p.name }}</b></td>
              <td>
                <span class="bd-tg" :class="p.type === 'snat' ? 'bd-tg--blue' : 'bd-tg--purple'">
                  {{ p.type === 'snat' ? 'SNAT 代理上网' : 'DNAT 资源发布' }}
                </span>
              </td>
              <td class="bd-mono">{{ p.gatewayId }}</td>
              <td class="bd-mono bd-natmatch">
                {{ p.srcIface }} {{ p.srcAddr }}
                <icon-arrow-right />
                {{ p.dstIface }} {{ p.dstAddr }}<template v-if="p.type === 'dnat' && p.dstPort">:{{ p.dstPort }}</template>
                <span v-if="p.type === 'dnat'" class="bd-tg bd-tg--grey bd-natproto">{{ p.protocol.toUpperCase() }}</span>
              </td>
              <td class="bd-mono">
                <template v-if="p.type === 'dnat'">
                  {{ p.translatedAddr }}<template v-if="p.translatedPort">:{{ p.translatedPort }}</template>
                </template>
                <span v-else class="bd-dim">—（源地址转换为出口地址）</span>
              </td>
              <td>
                <a-switch :model-value="p.enabled" size="small" :disabled="busy"
                  @update:model-value="(v: unknown) => toggle(p, Boolean(v))" />
              </td>
              <!-- 网关回执：这条规则此刻在那台网关的内核里到底是什么状态。
                   策略停用时不渲染回执——管理员本来就不指望它生效，报「没生效」是噪声。 -->
              <td>
                <span v-if="!p.enabled" class="bd-dim">—</span>
                <span v-else class="bd-tg" :class="rcptTagClass(p)" :title="rcptSay(p)">
                  {{ rcptText(p) }}
                </span>
              </td>
              <!-- 命中计数（FR-NAT-17）。★读不到时显示「不可判定」而不是 0：
                   「规则没灌进去」与「灌进去了但没流量」排障方向完全相反。 -->
              <td class="bd-mono">
                <span v-if="!hitsKnown" class="bd-dim" title="没有任何网关报得出计数（pf 拆不到规则粒度 / nft -j 读失败 / 网关版本旧）">不可判定</span>
                <span v-else-if="hits[p.id]">{{ hits[p.id].packets }} 包</span>
                <span v-else class="bd-dim" title="网关报得出计数，但这条规则一次都没被命中">0 包</span>
              </td>
              <td class="r">
                <span class="bd-acts">
                  <button type="button" class="bd-link" @click="openWizard(p)">编辑</button>
                  <button type="button" class="bd-link bd-link--danger" @click="askRemove(p)">删除</button>
                </span>
              </td>
            </tr>
            <tr v-if="!policies.length" class="bd-table__emptyrow">
              <td colspan="9">
                <!-- 读取失败 ≠ 没有策略：这一页决定的是「哪些内网端口对公网可达」，把「拉不到」画成
                     「尚无策略」等于替一份根本没读到的配置背书。原话 + 重试，不编造归因。 -->
                <EmptyState v-if="loadErr" size="md" tone="danger" title="地址转换配置未读取">
                  <div>{{ loadErr }}——这里显示的不是「没有策略」。</div>
                  <div class="bd-natempty__p">
                    本页读的是控制面 <code>GET /api/v1/nat</code>，这次请求失败了：库里有多少条策略、网关内核里
                    此刻灌着什么规则都<b>不可判定</b>。请按上面那句原话排查控制面这一侧。
                  </div>
                  <template #action><button class="bd-btn bd-btn--ghost" :disabled="busy" @click="load()"><icon-refresh />重试</button></template>
                </EmptyState>
                <EmptyState v-else size="md" title="尚无地址转换策略。"
                  :desc="ifaceReady ? '' : '先在左侧给网关网卡指定 LAN/WAN 类型，才能新增策略。'" />
              </td>
            </tr>
          </tbody>
        </table>
        </div>
      </div>
    </div>

    <!-- 策略向导：按 SNAT/DNAT 动态显隐字段（FR-NAT-03/09/10） -->
    <a-drawer v-model:visible="wz.open" :width="640" :title="wz.id ? '编辑地址转换策略' : '新增地址转换策略'" :footer="false" unmount-on-close>
      <div class="bd-wz">
        <div class="bd-wz__body">
          <div class="bd-fld"><label>策略名称</label><a-input v-model="wz.name" :max-length="64" placeholder="如：内网代理上网" /></div>

          <div class="bd-fld"><label>转换类型</label>
            <a-radio-group v-model="wz.type" type="button" @change="onTypeChange">
              <a-radio value="snat">SNAT · 代理上网</a-radio>
              <a-radio value="dnat">DNAT · 资源发布</a-radio>
            </a-radio-group>
            <span class="bd-fld__d">{{ wz.type === 'snat'
              ? '内网网段经网关统一出口访问外部：源接口选 LAN 口，目的接口选 WAN 口。'
              : '把公网 IP:端口映射到内网真实业务地址：源接口选 WAN 口，目的接口选 LAN 口。' }}</span>
          </div>

          <div class="bd-fld"><label>下发到网关</label>
            <a-select v-model="wz.gatewayId" placeholder="选择网关" @change="wz.srcIface = ''; wz.dstIface = ''">
              <a-option v-for="g in gatewayIds" :key="g" :value="g">{{ g }}</a-option>
            </a-select>
            <span class="bd-fld__d">地址转换是设备本地能力，规则只灌到选中的这台网关。</span>
          </div>

          <div class="bd-fld"><label>源接口（{{ wz.type === 'snat' ? 'LAN 口' : 'WAN 口' }}）</label>
            <a-select v-model="wz.srcIface" placeholder="选择网卡" :disabled="!wz.gatewayId">
              <a-option v-for="f in pickable(wz.type === 'snat' ? 'lan' : 'wan')" :key="f.name" :value="f.name">
                {{ f.name }} · {{ f.addrs.join(',') || '无地址' }}
              </a-option>
            </a-select>
          </div>
          <div class="bd-fld"><label>源地址</label>
            <a-input v-model="wz.srcAddr" class="bd-mono" :placeholder="wz.type === 'snat' ? '5.5.0.0/16（需代理上网的内网网段）' : '0.0.0.0/0（允许访问的公网来源）'" />
            <span v-if="wz.type === 'dnat'" class="bd-fld__d">默认 0.0.0.0/0 全放行；改成具体网段可收敛来源，只有该网段能访问被发布的服务。</span>
          </div>

          <div class="bd-fld"><label>目的接口（{{ wz.type === 'snat' ? 'WAN 口' : 'LAN 口' }}）</label>
            <a-select v-model="wz.dstIface" placeholder="选择网卡" :disabled="!wz.gatewayId">
              <a-option v-for="f in pickable(wz.type === 'snat' ? 'wan' : 'lan')" :key="f.name" :value="f.name">
                {{ f.name }} · {{ f.addrs.join(',') || '无地址' }}
              </a-option>
            </a-select>
          </div>
          <div class="bd-fld"><label>{{ wz.type === 'snat' ? '目的地址（出口网段）' : '对外发布地址' }}</label>
            <a-input v-model="wz.dstAddr" class="bd-mono" :placeholder="wz.type === 'snat' ? '155.155.0.0/16' : '5.5.10.102'" />
          </div>

          <!-- 转换后数据仅 DNAT 出现（FR-NAT-10 + 18.5 动态显隐要求） -->
          <template v-if="wz.type === 'dnat'">
            <div class="bd-fld"><label>协议</label>
              <a-radio-group v-model="wz.protocol" type="button" size="small">
                <a-radio value="tcp">TCP</a-radio><a-radio value="udp">UDP</a-radio>
                <a-radio value="icmp">ICMP</a-radio><a-radio value="all">所有协议</a-radio>
              </a-radio-group>
            </div>
            <template v-if="wz.protocol !== 'icmp'">
              <div class="bd-fld"><label>对外发布端口</label>
                <a-input-number v-model="wz.dstPort" :min="1" :max="65535" placeholder="9999" />
              </div>
            </template>
            <div class="bd-form-sec">转换后数据</div>
            <div class="bd-fld"><label>目的地址转换为</label>
              <a-input v-model="wz.translatedAddr" class="bd-mono" placeholder="155.155.235.212（业务系统真实内网 IP）" />
            </div>
            <div v-if="wz.protocol !== 'icmp'" class="bd-fld"><label>端口转换为</label>
              <a-input-number v-model="wz.translatedPort" :min="0" :max="65535" placeholder="8081（留空=与对外端口相同）" />
            </div>
          </template>

          <div class="bd-fld bd-fld--row">
            <div><label>启用</label><span class="bd-fld__d">停用的策略不会下发给网关</span></div>
            <a-switch v-model="wz.enabled" />
          </div>

          <div class="bd-notice bd-notice--plain">
            <icon-info-circle />
            <span>保存后规则由网关编译进内核（需网关以 -nat 启动且具备 root）。零信任隧道与敲门流量已自动从 SNAT 中排除。</span>
          </div>
        </div>
        <div class="bd-drawer__foot">
          <div class="bd-drawer__foot-spacer" />
          <button class="bd-btn bd-btn--ghost" @click="wz.open = false">取消</button>
          <button class="bd-btn" :disabled="busy || !canSave" @click="save">保存</button>
        </div>
      </div>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { api, failReason, type NATBundle, type NATPolicy, type NATReceipt, type NATHit, type GatewayIface, type NATType, type NATProto } from '@/lib/api';
import PageHeader from '@/components/PageHeader.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

/* 连接态三态：undefined = 首轮读取还没回来，页头不画连接标签。
 * ★不能写 ref(false)：那会让红色「数据未读取」在第一次请求回来之前就画出来——
 *   它宣告的是一件**还没发生**的事，慢网 / 大表下能持续好几秒，与「真的读失败了」完全同形。
 * 落定点：load() 的 try 尾（true）与 catch（false）。两条路径都必须落定，漏一条标签就永远不画（比误报更难发现）。 */
const live = ref<boolean | undefined>(undefined);
const busy = ref(false);
/** 首屏是否已完成一次加载（成功或失败都算）——只决定骨架屏何时让位，不改任何数据流。 */
const loaded = ref(false);
/** 本页数据的取回时刻（运行态列的口径）。 */
const fetchedAt = ref('');
const err = ref('');
/** 最近一次 /nat 读取失败的后端原话（failReason）；空串 = 最近一次读成功。
 *  ★它是「读取失败」与「真没有策略 / 真没有网卡」在页面上唯一的分野：失败时数据被清空，
 *  两栏与"全新部署一条都没有"完全同形，此前只靠顶部一条红条区分，两个空态照样用「确实为空」的语气说话。
 *  写操作（保存 / 切换 / 删除 / 定性）的失败仍走 err 顶部红条，不混用。 */
const loadErr = ref('');
const policies = ref<NATPolicy[]>([]);
const ifaces = ref<GatewayIface[]>([]);
const warnings = ref<string[]>([]);
/* ── 网关回执（wave8 行动 3）── */
const receipts = ref<Record<string, NATReceipt>>({});
const hits = ref<Record<string, NATHit>>({});
const hitsKnown = ref(false);

/** 某条策略所在网关的回执。缺失（旧控制面 / 该网关未涉及）按「未上报」处理。 */
function rcptOf(p: NATPolicy): NATReceipt | undefined { return receipts.value[p.gatewayId]; }
/** 回执一句话（挂 title，管理员悬停即知下一步做什么）。 */
function rcptSay(p: NATPolicy): string {
  return rcptOf(p)?.say || '控制面尚未收到该网关的地址转换运行态回报';
}
/** 回执短标签。★「未上报」不是「已生效」——两者必须用不同的字和不同的颜色。 */
function rcptText(p: NATPolicy): string {
  const r = rcptOf(p);
  if (!r) return '未上报';
  const base = ({
    unreported: '未上报', disabled: '网关未开启', failed: '灌入失败',
    dryrun: '仅生成未灌入', applied: '已灌入内核'
  } as Record<string, string>)[r.status] ?? r.status;
  // 转发关着时规则全部正确但一个包都不通，且没有任何报错——这一格必须说出来，
  // 不能被「已灌入内核」这四个字盖住。
  if (r.status === 'applied' && r.forwarding === false) return '已灌入 · 转发未开';
  if (!r.online) return base + ' · 网关离线';
  return base;
}
function rcptTagClass(p: NATPolicy): string {
  const r = rcptOf(p);
  if (!r || r.status === 'unreported') return 'bd-tg--grey';  // 灰 = 不可判定
  if (r.status === 'applied' && r.forwarding !== false && r.online) return 'bd-tg--green'; // 绿 = 真的生效了
  if (r.status === 'dryrun') return 'bd-tg--gold';            // 橙 = 有意的自检模式
  return 'bd-tg--red';                                        // 红 = 配了但不会生效
}

/* 这一页刻意没有降级演示数据：编造的 NAT 策略与真实规则在页面上无法区分，
   而它决定的是「哪些内网端口对公网可达」。连不上就说连不上。 */

const gatewayIds = computed(() => [...new Set(ifaces.value.map((f) => f.gatewayId))].sort());
const ifaceGroups = computed(() => gatewayIds.value.map((id) => ({
  gatewayId: id, list: ifaces.value.filter((f) => f.gatewayId === id)
})));
/** 有没有可用于建策略的网卡：至少一台网关同时有 LAN 与 WAN 口。 */
const ifaceReady = computed(() => gatewayIds.value.some((id) => {
  const mine = ifaces.value.filter((f) => f.gatewayId === id);
  return mine.some((f) => f.type === 'lan') && mine.some((f) => f.type === 'wan');
}));

function pickable(want: 'lan' | 'wan'): GatewayIface[] {
  return ifaces.value.filter((f) => f.gatewayId === wz.gatewayId && f.type === want);
}

const wz = reactive({
  open: false, id: '', name: '', type: 'snat' as NATType, gatewayId: '',
  srcIface: '', srcAddr: '', dstIface: '', dstAddr: '',
  protocol: 'tcp' as NATProto, dstPort: 0, translatedAddr: '', translatedPort: 0, enabled: true
});

const canSave = computed(() =>
  !!wz.name.trim() && !!wz.gatewayId && !!wz.srcIface && !!wz.srcAddr && !!wz.dstIface && !!wz.dstAddr &&
  (wz.type === 'snat' || (!!wz.translatedAddr && (wz.protocol === 'icmp' || wz.dstPort > 0)))
);

// 切换类型时清空接口选择：SNAT 与 DNAT 对源/目的的方向要求相反，
// 留着上一次的选择会让管理员保存时才被后端以「方向选反」拒绝。
function onTypeChange() {
  wz.srcIface = ''; wz.dstIface = '';
  if (wz.type === 'dnat' && !wz.srcAddr) wz.srcAddr = '0.0.0.0/0';
}

function openWizard(p?: NATPolicy) {
  err.value = '';
  if (p) {
    Object.assign(wz, { ...p, open: true });
  } else {
    Object.assign(wz, {
      open: true, id: '', name: '', type: 'snat' as NATType,
      gatewayId: gatewayIds.value[0] ?? '', srcIface: '', srcAddr: '',
      dstIface: '', dstAddr: '', protocol: 'tcp' as NATProto,
      dstPort: 0, translatedAddr: '', translatedPort: 0, enabled: true
    });
  }
}

async function save() {
  busy.value = true; err.value = '';
  try {
    const r = await api<{ warnings?: string[] }>('/nat/policies', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: wz.id, name: wz.name, type: wz.type, gatewayId: wz.gatewayId,
        srcIface: wz.srcIface, srcAddr: wz.srcAddr, dstIface: wz.dstIface, dstAddr: wz.dstAddr,
        protocol: wz.type === 'snat' ? 'all' : wz.protocol,
        dstPort: wz.dstPort, translatedAddr: wz.translatedAddr, translatedPort: wz.translatedPort,
        enabled: wz.enabled
      })
    });
    wz.open = false;
    Message.success(wz.id ? '策略已更新' : '策略已创建');
    // 保存那一刻当面给出风险提示：这是管理员最需要知道「这条 DNAT 让 SPA 对该端口失效」
    // 的时刻，而不是下次打开页面时。
    const w = r.warnings ?? [];
    if (w.length) Modal.warning({ title: '策略已保存，请注意以下影响', content: w.join('\n\n'), width: 560 });
    await load();
  } catch (e) {
    err.value = failReason(e);
  } finally { busy.value = false; }
}

async function toggle(p: NATPolicy, v: boolean) {
  busy.value = true; err.value = '';
  try {
    await api('/nat/policies', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...p, enabled: v })
    });
    await load();
  } catch (e) {
    err.value = failReason(e);
  } finally { busy.value = false; }
}

function askRemove(p: NATPolicy) {
  Modal.confirm({
    title: '删除地址转换策略',
    content: `确定删除「${p.name}」？删除后网关下一轮策略拉取即从内核移除对应规则。`,
    okText: '删除', cancelText: '取消', okButtonProps: { status: 'danger' },
    onOk: async () => {
      try {
        await api(`/nat/policies/${encodeURIComponent(p.id)}`, { method: 'DELETE' });
        Message.success(`已删除策略「${p.name}」`);
        await load();
      } catch (e) { err.value = failReason(e); }
    }
  });
}

async function setType(f: GatewayIface, t: string) {
  busy.value = true; err.value = '';
  try {
    await api(`/nat/ifaces/${encodeURIComponent(f.gatewayId)}/${encodeURIComponent(f.name)}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: t })
    });
    await load();
  } catch (e) {
    err.value = failReason(e);
  } finally { busy.value = false; }
}

async function load() {
  try {
    const b = await api<NATBundle>('/nat');
    policies.value = b.policies ?? [];
    ifaces.value = b.ifaces ?? [];
    warnings.value = b.warnings ?? [];
    receipts.value = b.receipts ?? {};
    fetchedAt.value = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    hits.value = b.hits ?? {};
    // ★缺字段一律按「不可判定」，不是按 0：旧控制面不下发 hitsKnown 时，
    // 显示「0 包」等于替一份我们根本没有的读数背书。
    hitsKnown.value = b.hitsKnown === true;
    live.value = true;
    loadErr.value = '';
  } catch (e) {
    // 拉不到就是拉不到：清空而不是留着上一次读到的那份——留着的话表格里还是旧行、左栏还是旧网卡，
    // 上面两个「未读取」空态根本不会出现，页面唯一的异常信号只剩页头一个红标签；
    // 「数据时间」也一并清掉，否则空表配着一个时刻，像是那一刻确实读到了零条。
    live.value = false;
    loadErr.value = failReason(e);
    policies.value = []; ifaces.value = []; warnings.value = [];
    receipts.value = {}; hits.value = {}; hitsKnown.value = false;
    fetchedAt.value = '';
  } finally { loaded.value = true; }
}
onMounted(load);
</script>

<style scoped>
/* 本页独有：网卡台账的行排布、策略表匹配列。表单节奏 / 抽屉底栏 / 提示条 / 空态都在共享件与 app.css 里。 */
.bd-wz { display: flex; flex-direction: column; height: 100%; }
.bd-wz__body { flex: 1; overflow-y: auto; padding-right: 2px; }
.bd-fld--row .bd-fld__d { margin-top: 0; }

.bd-natts { font-size: var(--bd-fs-sm); color: var(--bd-t3); }

.bd-ifaces { width: 320px; flex: none; }
.bd-ifaces__note { margin: var(--bd-sp-3) 0 0; }
.bd-ifgrp { margin-bottom: var(--bd-sp-3); }
.bd-ifgrp__h { display: flex; align-items: center; gap: 6px; font-size: var(--bd-fs-sm); color: var(--bd-t2); margin-bottom: 6px; }
.bd-ifrow { display: flex; align-items: center; gap: var(--bd-sp-2); padding: 6px 0; border-top: 1px solid var(--bd-border-2); }
.bd-ifrow__l { flex: 1; min-width: 0; }
.bd-ifrow__l b { font-size: var(--bd-fs-sm); }
.bd-ifrow__l > .bd-tg { margin-left: 6px; }
.bd-ifrow__l i { display: block; font-style: normal; font-size: var(--bd-fs-xs); color: var(--bd-t3); margin-top: 2px; }
.bd-iftype { width: 116px; flex: none; }
.bd-tablewrap { overflow-x: auto; }
.bd-natmatch { font-size: var(--bd-fs-xs); }
.bd-natmatch svg { margin: 0 4px; color: var(--bd-t3); }
.bd-natproto { margin-left: 6px; }
.bd-dim { color: var(--bd-t3); }
.bd-natempty__p { margin-top: var(--bd-sp-2); }

/* 1280 视口：左栏收窄 */
@media (max-width: 1320px) {
  .bd-ifaces { width: 280px; }
}
</style>
