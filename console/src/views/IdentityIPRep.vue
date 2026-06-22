<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">IP 信誉与黑白名单<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">流水线尾段「自动加黑」：本地 IP 信誉 / 名单 + CIDR 地理映射，编织进登录门（黑名单硬拒 / 异地判定）；上游<router-link to="/defense/policy">主动防御</router-link>检出威胁自动写入黑名单</div>
      </div>
      <a-button type="primary" @click="openCreate"><template #icon><icon-plus /></template>{{ tab === 'iprep' ? '新建名单条目' : '新建地理映射' }}</a-button>
    </div>

    <!-- 即时反查工具条：输入 IP → GET /ctl/api/iprep/lookup?ip=X -->
    <div class="ir-lookup">
      <span class="ir-lookup__ic">⌖</span>
      <a-input v-model="lookupIp" placeholder="输入 IP 即时反查名单 / 归属地（如 203.0.113.7）" allow-clear style="flex:1;max-width:340px"
               @keyup.enter="doLookup" @clear="lookupResult = null" />
      <a-button type="primary" :loading="looking" @click="doLookup"><template #icon><icon-search /></template>反查</a-button>

      <!-- 反查结果徽标群 -->
      <div v-if="lookupResult" class="ir-result">
        <span class="zl-badge" :class="listClass(lookupResult.list)">{{ listLabel(lookupResult.list) }}</span>
        <span v-if="lookupResult.geo" class="ir-result__chip">📍 {{ lookupResult.geo }}</span>
        <span v-if="lookupResult.country" class="ir-result__chip">{{ lookupResult.country }}</span>
        <span v-if="lookupResult.source" class="zl-badge" :class="srcClass(lookupResult.source)">{{ srcLabel(lookupResult.source) }}</span>
        <span v-if="lookupResult.reason" class="ir-result__reason">{{ lookupResult.reason }}</span>
        <span v-if="!live" class="ir-result__mock">本地求值</span>
      </div>
    </div>

    <a-tabs v-model:active-key="tab" type="rounded">
      <!-- Tab1：IP 名单 -->
      <a-tab-pane key="iprep" title="IP 名单">
        <div class="zl-card">
          <a-table :data="reps" :pagination="reps.length>15?{pageSize:15}:false" :bordered="false" row-key="key">
            <template #columns>
              <a-table-column title="CIDR / IP 段" data-index="cidr" :width="180">
                <template #cell="{ record }">
                  <span class="data" style="font-weight:600;color:var(--ink)">{{ record.cidr }}</span>
                  <div class="data" style="font-size:11px;color:var(--ink-3);margin-top:2px">{{ record.key }}</div>
                </template>
              </a-table-column>
              <a-table-column title="名单" align="center" :width="100">
                <template #cell="{ record }">
                  <span class="zl-badge" :class="listClass(record.list)">{{ listLabel(record.list) }}</span>
                </template>
              </a-table-column>
              <a-table-column title="地理" :width="140">
                <template #cell="{ record }">
                  <span style="font-size:12px;color:var(--ink-2)">{{ record.geo || '—' }}</span>
                </template>
              </a-table-column>
              <a-table-column title="原因">
                <template #cell="{ record }">
                  <span style="font-size:12px;color:var(--ink-2)">{{ record.reason || '—' }}</span>
                </template>
              </a-table-column>
              <a-table-column title="来源" align="center" :width="100">
                <template #cell="{ record }">
                  <span class="zl-badge" :class="srcClass(record.source)">{{ srcLabel(record.source) }}</span>
                </template>
              </a-table-column>
              <a-table-column title="启用" align="center" :width="80">
                <template #cell="{ record }">
                  <a-switch v-model="record.enabled" size="small" @change="toggleRep(record)" />
                </template>
              </a-table-column>
              <a-table-column title="" align="center" :width="120">
                <template #cell="{ record }">
                  <a-space>
                    <a-button size="mini" @click="openEdit(record)">编辑</a-button>
                    <a-button size="mini" type="text" status="danger" @click="del(record)">删除</a-button>
                  </a-space>
                </template>
              </a-table-column>
            </template>
            <template #empty>
              <div class="ir-empty">
                <div class="ir-empty__big">未配置 IP 名单 · 不命中（旧行为）</div>
                <div class="ir-empty__sub">名单为空时登录门不做黑白名单判定。新建 deny 条目可在登录门硬拒来源 IP；主动防御检出威胁会自动写入 source=defense 的黑名单条目。</div>
              </div>
            </template>
          </a-table>
        </div>
      </a-tab-pane>

      <!-- Tab2：地理库 -->
      <a-tab-pane key="geoip" title="地理库">
        <div class="zl-card">
          <a-table :data="geos" :pagination="geos.length>15?{pageSize:15}:false" :bordered="false" row-key="key">
            <template #columns>
              <a-table-column title="CIDR / IP 段" data-index="cidr" :width="200">
                <template #cell="{ record }">
                  <span class="data" style="font-weight:600;color:var(--ink)">{{ record.cidr }}</span>
                  <div class="data" style="font-size:11px;color:var(--ink-3);margin-top:2px">{{ record.key }}</div>
                </template>
              </a-table-column>
              <a-table-column title="地理（geo）">
                <template #cell="{ record }">
                  <span style="font-size:12px;color:var(--ink-2)">📍 {{ record.geo || '—' }}</span>
                </template>
              </a-table-column>
              <a-table-column title="国家 / 地区" :width="160">
                <template #cell="{ record }">
                  <span style="font-size:12px;color:var(--ink-2)">{{ record.country || '—' }}</span>
                </template>
              </a-table-column>
              <a-table-column title="" align="center" :width="120">
                <template #cell="{ record }">
                  <a-space>
                    <a-button size="mini" @click="openEdit(record)">编辑</a-button>
                    <a-button size="mini" type="text" status="danger" @click="del(record)">删除</a-button>
                  </a-space>
                </template>
              </a-table-column>
            </template>
            <template #empty>
              <div class="ir-empty">
                <div class="ir-empty__big">未配置地理库 · 空地理（旧行为）</div>
                <div class="ir-empty__sub">地理库为空时来源 IP 不解析归属地，异地登录判定退回旧逻辑。新建 CIDR→地理映射后，登录门可据「常用地之外」触发异地提醒 / 二次鉴权。</div>
              </div>
            </template>
          </a-table>
        </div>
      </a-tab-pane>
    </a-tabs>

    <!-- IP 名单 编辑 / 新建 -->
    <a-modal v-if="tab === 'iprep'" v-model:visible="show" :title="editing ? '编辑名单条目' : '新建名单条目'" width="560px" @ok="submit" :ok-text="editing ? '保存' : '创建'">
      <a-form :model="rForm" layout="vertical">
        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="条目标识（key）" required>
              <a-input v-model="rForm.key" placeholder="例如：deny-cn-honeypot" :disabled="editing" />
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="CIDR / IP 段" required>
              <a-input v-model="rForm.cidr" placeholder="例如：203.0.113.0/24 或 198.51.100.7/32" />
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="名单（list）">
              <a-select v-model="rForm.list">
                <a-option v-for="o in listOpts" :key="o.value" :value="o.value">{{ o.label }}</a-option>
              </a-select>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="来源（source）">
              <a-select v-model="rForm.source">
                <a-option v-for="o in srcOpts" :key="o.value" :value="o.value">{{ o.label }}</a-option>
              </a-select>
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="地理（geo）">
              <a-input v-model="rForm.geo" placeholder="例如：中国 · 浙江 · 杭州" />
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="ASN">
              <a-input v-model="rForm.asn" placeholder="例如：AS4134" />
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-form-item label="原因（reason）">
          <a-textarea v-model="rForm.reason" placeholder="例如：蜜罐探测来源 / 情报标记 C2 / 业务白名单出口" :auto-size="{ minRows: 2, maxRows: 4 }" />
        </a-form-item>

        <a-form-item label="启用本条目">
          <a-switch v-model="rForm.enabled" />
          <span class="ir-hint" style="margin-left:10px">关闭 = 不参与名单匹配（既不拒绝也不放行豁免）。</span>
        </a-form-item>
      </a-form>
      <div class="ir-modal-note">提示：deny 段经登录门最长前缀匹配硬拒（deny 优先 allow，安全侧从严）；source=defense 通常由主动防御自动写入。名单调整 ≤60s 下发并写审计。</div>
    </a-modal>

    <!-- 地理库 编辑 / 新建 -->
    <a-modal v-else v-model:visible="show" :title="editing ? '编辑地理映射' : '新建地理映射'" width="520px" @ok="submit" :ok-text="editing ? '保存' : '创建'">
      <a-form :model="gForm" layout="vertical">
        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="映射标识（key）" required>
              <a-input v-model="gForm.key" placeholder="例如：geo-cn-zj" :disabled="editing" />
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="CIDR / IP 段" required>
              <a-input v-model="gForm.cidr" placeholder="例如：36.152.0.0/16" />
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-form-item label="地理（geo）">
          <a-input v-model="gForm.geo" placeholder="例如：中国 · 浙江 · 杭州" />
        </a-form-item>

        <a-form-item label="国家 / 地区（country）">
          <a-input v-model="gForm.country" placeholder="例如：CN / 中国" />
        </a-form-item>
      </a-form>
      <div class="ir-modal-note">提示：地理映射用于来源 IP 归属地解析（最长前缀匹配），喂给登录门的异地判定。地理库调整 ≤60s 下发并写审计。</div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

/* —— 类型（与后端 internal/iprep 结构对齐） —— */
// IP 名单条目（kind=iprep，每条一文档）。
interface Rep {
  key: string;
  cidr: string;
  list: 'deny' | 'allow';
  geo: string;
  asn: string;
  reason: string;
  source: 'manual' | 'defense' | 'intel';
  enabled: boolean;
}
// CIDR→地理映射（kind=geoip，每条一文档）。
interface Geo {
  key: string;
  cidr: string;
  geo: string;
  country: string;
}

/* —— 选项与中文化 —— */
const listOpts = [
  { value: 'deny', label: 'deny 黑名单' },
  { value: 'allow', label: 'allow 白名单' }
];
const srcOpts = [
  { value: 'manual', label: 'manual 手工' },
  { value: 'defense', label: 'defense 自动' },
  { value: 'intel', label: 'intel 情报' }
];
// 名单徽标：deny 红 / allow 绿 / 空 = 未命中。
const listLabel = (l: string) => (l === 'deny' ? '黑名单' : l === 'allow' ? '白名单' : '未命中');
const listClass = (l: string) => (l === 'deny' ? 'zl-badge--danger' : l === 'allow' ? 'zl-badge--ok' : 'zl-badge--idle');
const srcLabel = (s: string) => srcOpts.find((o) => o.value === s)?.label.replace(/^\S+\s/, '') ?? s;
const srcClass = (s: string) => (s === 'defense' ? 'zl-badge--warn' : s === 'intel' ? 'zl-badge--accent' : 'zl-badge--idle');

/* —— 前端默认（mock，加载后端后覆盖；与后端 seed 同形） —— */
const repFallback: Rep[] = [
  { key: 'deny-c2-intel', cidr: '198.51.100.0/24', list: 'deny', geo: '俄罗斯 · 莫斯科', asn: 'AS12389', reason: '威胁情报标记 C2 控制端', source: 'intel', enabled: true },
  { key: 'deny-auto-203.0.113.7', cidr: '203.0.113.7/32', list: 'deny', geo: '美国 · 弗吉尼亚', asn: 'AS14618', reason: '主动防御检出端口扫描自动加黑', source: 'defense', enabled: true },
  { key: 'allow-office-egress', cidr: '36.152.44.0/24', list: 'allow', geo: '中国 · 浙江 · 杭州', asn: 'AS4134', reason: '总部办公网出口豁免', source: 'manual', enabled: true }
];
const geoFallback: Geo[] = [
  { key: 'geo-cn-zj', cidr: '36.152.0.0/16', geo: '中国 · 浙江 · 杭州', country: 'CN / 中国' },
  { key: 'geo-cn-bj', cidr: '111.206.0.0/16', geo: '中国 · 北京', country: 'CN / 中国' },
  { key: 'geo-us-va', cidr: '203.0.113.0/24', geo: '美国 · 弗吉尼亚', country: 'US / 美国' }
];

const reps = ref<Rep[]>(repFallback.map((r) => ({ ...r })));
const geos = ref<Geo[]>(geoFallback.map((g) => ({ ...g })));

const tab = ref<'iprep' | 'geoip'>('iprep');
const liveRep = ref(false);
const liveGeo = ref(false);
// 页头徽标：两 tab 任一持久化即视为 live。
const live = computed(() => liveRep.value || liveGeo.value);

/* —— 加载（两 tab 各自探活；失败保留前端默认 mock 降级） —— */
async function loadReps() {
  try {
    const res = await fetch('/ctl/api/coll?kind=iprep');
    if (!res.ok) return;
    const docs = await res.json();
    reps.value = (docs as any[]).map((d) => ({
      key: d.key ?? d.k ?? '',
      cidr: d.cidr ?? '',
      list: d.list === 'allow' ? 'allow' : 'deny',
      geo: d.geo ?? '',
      asn: d.asn ?? '',
      reason: d.reason ?? '',
      source: ['manual', 'defense', 'intel'].includes(d.source) ? d.source : 'manual',
      enabled: typeof d.enabled === 'boolean' ? d.enabled : true
    }));
    liveRep.value = true;
  } catch { liveRep.value = false; }
}
async function loadGeos() {
  try {
    const res = await fetch('/ctl/api/coll?kind=geoip');
    if (!res.ok) return;
    const docs = await res.json();
    geos.value = (docs as any[]).map((d) => ({
      key: d.key ?? d.k ?? '',
      cidr: d.cidr ?? '',
      geo: d.geo ?? '',
      country: d.country ?? ''
    }));
    liveGeo.value = true;
  } catch { liveGeo.value = false; }
}
onMounted(() => { loadReps(); loadGeos(); });

/* —— 即时反查：GET /ctl/api/iprep/lookup?ip=X；控制面不可达时降级本地最长前缀匹配 —— */
const lookupIp = ref('');
const looking = ref(false);
const lookupResult = ref<{ list: string; geo: string; country: string; reason?: string; source?: string } | null>(null);

// 本地降级求值（与后端 iprep.Match / GeoOf 同语义：最长前缀，deny 优先 allow）。
function localLookup(ip: string) {
  const inCidr = (cidr: string): number => {
    const [base, bitsStr] = cidr.split('/');
    const bits = parseInt(bitsStr ?? '32', 10);
    const toInt = (s: string) => s.split('.').reduce((a, p) => (a << 8) + (parseInt(p, 10) & 255), 0) >>> 0;
    const ipN = toInt(ip), baseN = toInt(base);
    if (Number.isNaN(ipN) || Number.isNaN(baseN)) return -1;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (ipN & mask) === (baseN & mask) ? bits : -1;
  };
  // 名单：最长前缀，前缀相同 deny 压过 allow。
  let bestOnes = -1, list = '', hit: Rep | null = null;
  for (const r of reps.value) {
    if (!r.enabled) continue;
    const ones = inCidr(r.cidr);
    if (ones < 0) continue;
    if (ones > bestOnes || (ones === bestOnes && r.list === 'deny' && list !== 'deny')) { bestOnes = ones; list = r.list; hit = r; }
  }
  // 地理：最长前缀。
  let gOnes = -1, geo = '', country = '';
  for (const g of geos.value) {
    const ones = inCidr(g.cidr);
    if (ones < 0) continue;
    if (ones > gOnes) { gOnes = ones; geo = g.geo; country = g.country; }
  }
  return { list, geo, country, reason: hit?.reason, source: hit?.source };
}

async function doLookup() {
  const ip = lookupIp.value.trim();
  if (!ip) return Message.warning('请输入要反查的 IP');
  looking.value = true;
  try {
    const res = await fetch(`/ctl/api/iprep/lookup?ip=${encodeURIComponent(ip)}`);
    if (res.ok) {
      const d = await res.json();
      lookupResult.value = { list: d.list ?? '', geo: d.geo ?? '', country: d.country ?? '', reason: d.reason, source: d.source };
    } else {
      lookupResult.value = localLookup(ip);
    }
  } catch {
    // 控制面不可达，降级本地求值
    lookupResult.value = localLookup(ip);
  } finally {
    looking.value = false;
  }
}

/* —— 持久化（POST 单条文档，后端写审计） —— */
async function persistRep(r: Rep) {
  if (!liveRep.value) return true;
  try {
    const res = await fetch('/ctl/api/coll?kind=iprep', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: r.key, doc: { ...r } })
    });
    return res.ok;
  } catch { return false; }
}
async function persistGeo(g: Geo) {
  if (!liveGeo.value) return true;
  try {
    const res = await fetch('/ctl/api/coll?kind=geoip', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: g.key, doc: { ...g } })
    });
    return res.ok;
  } catch { return false; }
}

/* —— 行内启用开关：即时 toggle，写失败回滚 —— */
async function toggleRep(r: Rep) {
  const ok = await persistRep(r);
  if (!ok && liveRep.value) { r.enabled = !r.enabled; return Message.error('操作失败，已回滚'); }
  Message.info(`名单条目「${r.cidr}」已${r.enabled ? '启用' : '停用'}${liveRep.value ? ' · 已持久化' : ''}`);
}

/* —— 新建 / 编辑 —— */
const show = ref(false);
const editing = ref(false);
const rForm = reactive<Rep>({ key: '', cidr: '', list: 'deny', geo: '', asn: '', reason: '', source: 'manual', enabled: true });
const gForm = reactive<Geo>({ key: '', cidr: '', geo: '', country: '' });

function resetForms() {
  Object.assign(rForm, { key: '', cidr: '', list: 'deny', geo: '', asn: '', reason: '', source: 'manual', enabled: true });
  Object.assign(gForm, { key: '', cidr: '', geo: '', country: '' });
}
function openCreate() { editing.value = false; resetForms(); show.value = true; }
function openEdit(record: any) {
  editing.value = true;
  // 克隆，避免引用污染列表行。
  if (tab.value === 'iprep') Object.assign(rForm, JSON.parse(JSON.stringify(record)));
  else Object.assign(gForm, JSON.parse(JSON.stringify(record)));
  show.value = true;
}

async function submit() {
  if (tab.value === 'iprep') {
    if (!rForm.key) return Message.warning('请填写条目标识（key）');
    if (!rForm.cidr) return Message.warning('请填写 CIDR / IP 段');
    if (!editing.value && reps.value.some((x) => x.key === rForm.key)) return Message.warning(`条目标识「${rForm.key}」已存在`);
    const doc: Rep = { ...rForm };
    if (editing.value) {
      const i = reps.value.findIndex((x) => x.key === doc.key);
      if (liveRep.value && !(await persistRep(doc))) return Message.error('保存失败');
      if (i >= 0) reps.value[i] = doc;
      Message.success(`名单条目「${doc.cidr}」已更新${liveRep.value ? ' · 已持久化' : '（mock）'}`);
    } else {
      if (liveRep.value && !(await persistRep(doc))) return Message.error('创建失败');
      reps.value.push(doc);
      Message.success(`名单条目「${doc.cidr}」已创建${liveRep.value ? ' · 已持久化' : '（mock）'}`);
    }
  } else {
    if (!gForm.key) return Message.warning('请填写映射标识（key）');
    if (!gForm.cidr) return Message.warning('请填写 CIDR / IP 段');
    if (!editing.value && geos.value.some((x) => x.key === gForm.key)) return Message.warning(`映射标识「${gForm.key}」已存在`);
    const doc: Geo = { ...gForm };
    if (editing.value) {
      const i = geos.value.findIndex((x) => x.key === doc.key);
      if (liveGeo.value && !(await persistGeo(doc))) return Message.error('保存失败');
      if (i >= 0) geos.value[i] = doc;
      Message.success(`地理映射「${doc.cidr}」已更新${liveGeo.value ? ' · 已持久化' : '（mock）'}`);
    } else {
      if (liveGeo.value && !(await persistGeo(doc))) return Message.error('创建失败');
      geos.value.push(doc);
      Message.success(`地理映射「${doc.cidr}」已创建${liveGeo.value ? ' · 已持久化' : '（mock）'}`);
    }
  }
  show.value = false;
}

/* —— 删除（二次确认 + DELETE） —— */
function del(record: any) {
  const isRep = tab.value === 'iprep';
  const noun = isRep ? '名单条目' : '地理映射';
  Modal.warning({
    title: `删除${noun}「${record.cidr}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: isRep
      ? '删除后该 IP 段不再参与名单匹配（登录门不再据此硬拒 / 豁免）。此操作进入审计链。'
      : '删除后该 CIDR 不再解析归属地，异地登录判定退回旧逻辑。此操作进入审计链。',
    onOk: async () => {
      const kind = isRep ? 'iprep' : 'geoip';
      const isLive = isRep ? liveRep.value : liveGeo.value;
      if (isLive) {
        try {
          const res = await fetch(`/ctl/api/coll?kind=${kind}&key=${encodeURIComponent(record.key)}`, { method: 'DELETE' });
          if (!res.ok) return Message.error('删除失败');
        } catch { return Message.error('控制面不可达'); }
      }
      if (isRep) reps.value = reps.value.filter((x) => x.key !== record.key);
      else geos.value = geos.value.filter((x) => x.key !== record.key);
      Message.success(`${noun}「${record.cidr}」已删除${isLive ? ' · 已持久化' : ''}`);
    }
  });
}
</script>

<style scoped>
:deep(.arco-table-tr) { cursor: default; }

/* 反查工具条 */
.ir-lookup { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; background: var(--accent-soft); border: 1px solid var(--line); border-radius: var(--r-md); padding: 12px 14px; margin-bottom: 16px; }
.ir-lookup__ic { color: var(--accent-2); font-weight: 700; font-size: 16px; flex-shrink: 0; }
.ir-result { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-left: 4px; }
.ir-result__chip { font-size: 11.5px; color: var(--ink-2); background: var(--surface); border: 1px solid var(--line); border-radius: var(--r-pill); padding: 3px 10px; }
.ir-result__reason { font-size: 11.5px; color: var(--ink-3); }
.ir-result__mock { font-size: 10.5px; color: var(--ink-3); border: 1px dashed var(--line); border-radius: var(--r-pill); padding: 2px 8px; }

/* 空态 */
.ir-empty { padding: 30px 16px; text-align: center; }
.ir-empty__big { font-size: 14px; font-weight: 650; color: var(--ink-2); }
.ir-empty__sub { font-size: 12px; color: var(--ink-3); margin-top: 8px; line-height: 1.6; max-width: 560px; margin-left: auto; margin-right: auto; }

.ir-hint { font-size: 11px; color: var(--ink-3); line-height: 1.5; }
.ir-modal-note { font-size: 11.5px; color: var(--ink-3); line-height: 1.6; margin-top: 4px; }
</style>
