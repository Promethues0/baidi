<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">策略管理</div>
        <div class="bd-page__sub">全局兜底 + 个性覆盖 · 用户策略沿组织树继承，差异处按需打破继承做个性化</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'user' }" @click="tab = 'user'">用户策略 · 继承编辑器</span>
      <span class="bd-tab" :class="{ on: tab === 'global' }" @click="tab = 'global'">全局策略</span>
    </div>

    <!-- ============ 用户策略（继承编辑器）============ -->
    <div v-show="tab === 'user'" class="bd-two">
      <!-- 左：继承树 -->
      <div class="bd-card bd-tree">
        <div class="bd-tree__h">组织 / 用户组继承树</div>
        <button
          v-for="n in flatTree"
          :key="n.key"
          class="bd-tnode"
          :class="{ on: n.key === selected }"
          :style="{ paddingLeft: 10 + n.depth * 16 + 'px' }"
          @click="select(n.key)"
        >
          <span class="bd-tnode__dot" :class="n.hasCustom ? 'custom' : 'inherit'" />
          <span class="bd-tnode__t">{{ n.title }}</span>
          <span class="bd-tnode__tag" :class="n.hasCustom ? 'custom' : 'inherit'">{{ n.hasCustom ? '自定义' : '继承' }}</span>
          <span class="bd-tnode__m">{{ n.members }}</span>
        </button>
      </div>

      <!-- 右：编辑器 -->
      <div class="bd-editor">
        <!-- 继承链 -->
        <div class="bd-card bd-chain">
          <div class="bd-chain__top">
            <div>
              <span class="bd-chain__name">{{ node?.title }}</span>
              <span class="bd-chain__sub">{{ node?.members }} 名成员 · 有效策略 = 本级自定义项 + 上级继承项</span>
            </div>
            <div class="bd-chain__stat">
              <span class="bd-pill bd-pill--blue">{{ customCount }} 项自定义</span>
              <span class="bd-pill bd-pill--grey">{{ inheritCount }} 项继承</span>
            </div>
          </div>
          <div class="bd-chain__path">
            <span class="bd-chain__label">继承链</span>
            <template v-for="(c, i) in chain" :key="c.key">
              <span class="bd-node" :class="{ self: i === 0 }">{{ c.title }}</span>
              <icon-left v-if="i < chain.length - 1" class="bd-chain__arrow" />
            </template>
          </div>
        </div>

        <!-- 设置分区 -->
        <div v-for="sec in sections" :key="sec.title" class="bd-card bd-sec">
          <div class="bd-sec__h">{{ sec.title }}</div>
          <div v-for="row in sec.rows" :key="row.key" class="bd-row">
            <div class="bd-row__main">
              <div class="bd-row__label">
                {{ row.label }}
                <span v-if="row.risk" class="bd-risk">高影响</span>
              </div>
              <div class="bd-row__desc">{{ row.desc }}</div>
            </div>

            <!-- 继承态：只读继承值 + 覆盖 -->
            <template v-if="row.source === 'inherited'">
              <span class="bd-row__inval">继承值：{{ fmt(row, row.inherited) }}</span>
              <span class="bd-row__badge inherit">继承</span>
              <span class="bd-row__act" @click="askOverride(row)">覆盖</span>
            </template>
            <!-- 自定义态：可编辑控件 + 恢复继承 -->
            <template v-else>
              <span class="bd-row__ctrl">
                <a-switch v-if="row.type === 'toggle'" v-model="row.value" size="small" />
                <a-input-number v-else-if="row.type === 'number'" v-model="numRow(row).value" :min="0" size="small" style="width: 92px" />
                <a-select v-else-if="row.type === 'select'" v-model="row.value" size="small" style="width: 150px">
                  <a-option v-for="o in row.options" :key="o" :value="o">{{ o }}</a-option>
                </a-select>
                <span v-if="row.unit" class="bd-row__unit">{{ row.unit }}</span>
              </span>
              <span class="bd-row__badge custom">自定义</span>
              <span class="bd-row__act" @click="restore(row)">恢复继承</span>
            </template>
          </div>
        </div>

        <div class="bd-editor__foot">
          <button class="bd-btn--ghost bd-btn" @click="reset">重置改动</button>
          <button class="bd-btn" @click="impact.open = true">
            <icon-eye />保存并预览影响
          </button>
        </div>
      </div>
    </div>

    <!-- ============ 全局策略（复刻设计稿开关行）============ -->
    <div v-show="tab === 'global'" class="bd-two">
      <div class="bd-card bd-gsec-nav">
        <button v-for="g in globalSecs" :key="g.key" class="bd-gnav" :class="{ on: gsec === g.key }" @click="gsec = g.key">
          {{ g.label }}
        </button>
      </div>
      <div class="bd-card bd-gbody">
        <div v-for="g in globalSecs" v-show="gsec === g.key" :key="g.key">
          <div class="bd-sec__h plain">{{ g.label }}</div>
          <div v-for="r in g.rows" :key="r.label" class="bd-row">
            <div class="bd-row__main">
              <div class="bd-row__label">{{ r.label }}<span v-if="r.risk" class="bd-risk">高影响</span></div>
              <div class="bd-row__desc">{{ r.desc }}</div>
            </div>
            <span v-if="r.threshold !== undefined" class="bd-thr">阈值 <b>{{ r.threshold }}</b> 次</span>
            <a-switch v-model="r.on" size="small" />
          </div>
        </div>
      </div>
    </div>

    <!-- 打破继承确认 -->
    <a-modal v-model:visible="brk.open" title="打破继承" :width="460" @ok="confirmOverride" ok-text="确认覆盖" cancel-text="取消">
      <div class="bd-brk">
        <icon-exclamation-circle-fill class="bd-brk__ic" />
        <div>
          将对<b>「{{ node?.title }}」</b>的<b>「{{ brk.row?.label }}」</b>打破继承：该项今后<b>不再随上级
          「{{ parentTitle }}」</b>的策略更新而变化，需在本级单独维护。
        </div>
      </div>
    </a-modal>

    <!-- 提交影响预览（P4） -->
    <a-modal v-model:visible="impact.open" title="保存前 · 影响预览" :width="560" :footer="false">
      <div class="bd-imp">
        <div class="bd-imp__hl">
          本次变更将作用于 <b>{{ node?.title }}</b> 的 <b class="num">{{ node?.members }}</b> 名成员
          （{{ customCount }} 项自定义，其余继承自 {{ parentTitle }}）。
        </div>

        <div class="bd-imp__t">受影响终端平台分布</div>
        <div v-for="p in platforms" :key="p.name" class="bd-bar">
          <span class="bd-bar__l">{{ p.name }}</span>
          <span class="bd-bar__track"><span class="bd-bar__fill" :style="{ width: p.pct + '%' }" /></span>
          <span class="bd-bar__v">{{ p.count }}</span>
        </div>

        <div class="bd-imp__t">与全局策略的冲突检查</div>
        <div class="bd-conf warn">
          <icon-exclamation-circle-fill />
          全局「禁止浏览器登录」开启，本级未配置客户端强制安装 —— <b>{{ Math.round(node!.members * 0.18) }}</b> 名纯浏览器用户可能无法登录。
        </div>
        <div class="bd-conf ok"><icon-check-circle-fill />其余 5 项设置与全局策略无冲突。</div>

        <div class="bd-imp__risk">
          风险评级 <a-tag color="orange">中</a-tag>
          <span class="bd-imp__rk">建议先在小范围灰度后再全量。</span>
        </div>

        <a-checkbox v-model="impact.ack" class="bd-imp__ack">我已知悉上述影响范围与冲突</a-checkbox>
        <div class="bd-imp__foot">
          <button class="bd-btn--ghost bd-btn" @click="impact.open = false">取消</button>
          <button class="bd-btn" :disabled="!impact.ack" :style="{ opacity: impact.ack ? 1 : 0.5 }" @click="doSave">确认保存并下发</button>
        </div>
      </div>
    </a-modal>

    <!-- 30s 撤销条（P3） -->
    <transition name="bd-fade">
      <div v-if="undo.row" class="bd-undo">
        <icon-info-circle-fill />
        已打破「{{ undo.row.label }}」的继承
        <span class="bd-undo__btn" @click="doUndo">撤销</span>
        <span class="bd-undo__t">{{ undo.left }}s</span>
      </div>
    </transition>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted, onUnmounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type PolicyBundle, type OrgNode } from '@/lib/api';

type Src = 'inherited' | 'custom';
type Val = string | number | boolean;
interface Row {
  key: string; label: string; desc: string;
  type: 'toggle' | 'number' | 'select';
  source: Src; value: Val; inherited: Val;
  unit?: string; options?: string[]; risk?: boolean;
}
interface Section { title: string; rows: Row[] }

const tab = ref<'user' | 'global'>('user');
const live = ref(false);

/* ── 继承树 ── */
const MOCK_TREE: OrgNode[] = [
  { key: 'root', title: '根策略（全局兜底）', hasCustom: true, members: 1284, children: [
    { key: 'east', title: '华东大区', hasCustom: true, members: 420, children: [
      { key: 'east-sales', title: '销售部', hasCustom: true, members: 86 },
      { key: 'east-dev', title: '研发部', hasCustom: false, members: 210 }
    ] },
    { key: 'south', title: '华南大区', hasCustom: false, members: 300, children: [
      { key: 'south-cs', title: '客服中心', hasCustom: true, members: 64 }
    ] },
    { key: 'contractor', title: '外包人员', hasCustom: true, members: 48 }
  ] }
];
const tree = ref<OrgNode[]>(MOCK_TREE);
const selected = ref('east-sales');

interface Flat extends OrgNode { depth: number }
const flatTree = computed<Flat[]>(() => {
  const out: Flat[] = [];
  const walk = (ns: OrgNode[], d: number) => ns.forEach((n) => { out.push({ ...n, depth: d }); n.children && walk(n.children, d + 1); });
  walk(tree.value, 0);
  return out;
});
const node = computed(() => flatTree.value.find((n) => n.key === selected.value));

/** 找从根到目标的路径，返回 [self, parent, ..., root] */
function pathTo(key: string): OrgNode[] {
  const res: OrgNode[] = [];
  const walk = (ns: OrgNode[], trail: OrgNode[]): boolean => {
    for (const n of ns) {
      const t = [...trail, n];
      if (n.key === key) { res.push(...t.reverse()); return true; }
      if (n.children && walk(n.children, t)) return true;
    }
    return false;
  };
  walk(tree.value, []);
  return res;
}
const chain = computed(() => pathTo(selected.value));
const parentTitle = computed(() => chain.value[1]?.title ?? '上级');

/* ── 设置模型（按节点是否 hasCustom 播种自定义项）── */
const CUSTOM_KEYS = new Set(['concurrency', 'idle', 'vline', 'procGuard']);
function seed(custom: boolean): Section[] {
  const mk = (r: Omit<Row, 'source'>): Row => ({ ...r, source: custom && CUSTOM_KEYS.has(r.key) ? 'custom' : 'inherited' });
  return [
    { title: '设备与会话', rows: [
      mk({ key: 'concurrency', label: '设备并发数', desc: '同一账号允许的同时在线终端数（0 = 不限）', type: 'number', value: 2, inherited: 3, unit: '台' }),
      mk({ key: 'idle', label: '会话空闲超时', desc: 'PC 端无流量超时自动注销', type: 'number', value: 15, inherited: 30, unit: '分钟' })
    ] },
    { title: '网络与路由', rows: [
      mk({ key: 'dns', label: '专用 DNS 下发', desc: '为隧道应用下发专用 DNS 与解析白名单', type: 'toggle', value: false, inherited: false }),
      mk({ key: 'vline', label: '虚拟专线隔离', desc: '仅放行已发布应用 + 白名单，其余互联网阻断（仅 Windows）', type: 'toggle', value: true, inherited: false, risk: true })
    ] },
    { title: '访问控制', rows: [
      mk({ key: 'window', label: '登录时段限制', desc: '仅允许在指定时段内登录', type: 'select', value: '不限', inherited: '不限', options: ['不限', '工作日 09-18', '夜班 20-06'] }),
      mk({ key: 'mfaExempt', label: '二次认证豁免期', desc: '授信终端在豁免期内免二次认证', type: 'number', value: 7, inherited: 7, unit: '天' })
    ] },
    { title: '客户端防护', rows: [
      mk({ key: 'uninstall', label: '卸载防护', desc: '禁止用户自行卸载客户端', type: 'toggle', value: true, inherited: true }),
      mk({ key: 'procGuard', label: '进程防护', desc: '防调试 / 防 dump / 防 hook 摘除', type: 'toggle', value: true, inherited: false })
    ] }
  ];
}
const sections = ref<Section[]>(seed(true));
const allRows = computed(() => sections.value.flatMap((s) => s.rows));
const customCount = computed(() => allRows.value.filter((r) => r.source === 'custom').length);
const inheritCount = computed(() => allRows.value.filter((r) => r.source === 'inherited').length);

async function select(key: string) {
  selected.value = key;
  const n = flatTree.value.find((x) => x.key === key);
  sections.value = seed(!!n?.hasCustom);
  clearUndo();
  // 已保存的覆盖优先（落库的编辑回填）
  try {
    const r = await api<{ exists: boolean; override?: { settings: string } }>(`/policies/${key}`);
    if (r.exists && r.override?.settings) {
      const saved = JSON.parse(r.override.settings);
      if (Array.isArray(saved) && saved.length) sections.value = saved;
    }
  } catch { /* 离线则用种子 */ }
}
function fmt(row: Row, v: unknown) {
  if (row.type === 'toggle') return v ? '开启' : '关闭';
  return `${v}${row.unit ?? ''}`;
}
/**
 * Arco a-input-number 的 modelValue 严格类型为 number|undefined（第三方组件类型限制）；
 * Row.value/inherited 是 toggle/number/select 三种控件共用的 Val 联合类型，
 * MOCK 数据保证 row.type === 'number' 分支下其值恒为 number。仅此处按最窄范围断言收窄，
 * 不改变运行时取值/赋值语义（同一 row 引用，读写均直达原属性）。
 */
function numRow(row: Row) {
  return row as Row & { value: number };
}

/* ── 打破继承（P3）── */
const brk = reactive<{ open: boolean; row: Row | null }>({ open: false, row: null });
function askOverride(row: Row) { brk.row = row; brk.open = true; }
function confirmOverride() {
  const row = brk.row!;
  row.source = 'custom';
  row.value = row.inherited;
  brk.open = false;
  startUndo(row);
}

/* ── 30s 撤销条 ── */
const undo = reactive<{ row: Row | null; left: number }>({ row: null, left: 30 });
let undoTimer: number | undefined;
function startUndo(row: Row) {
  undo.row = row; undo.left = 30;
  clearInterval(undoTimer);
  undoTimer = window.setInterval(() => { if (--undo.left <= 0) clearUndo(); }, 1000);
}
function clearUndo() { clearInterval(undoTimer); undo.row = null; }
function doUndo() { if (undo.row) undo.row.source = 'inherited'; clearUndo(); }
function restore(row: Row) { row.source = 'inherited'; if (undo.row === row) clearUndo(); }
function reset() { select(selected.value); clearUndo(); Message.info('已重置为最近一次保存的状态'); }
onUnmounted(() => clearInterval(undoTimer));

/* ── 影响预览（P4）── */
const impact = reactive({ open: false, ack: false });
const platforms = computed(() => {
  const m = node.value?.members ?? 0;
  const win = Math.round(m * 0.62), mac = Math.round(m * 0.16), mob = m - win - mac;
  const max = Math.max(win, mac, mob, 1);
  return [
    { name: 'Windows', count: win, pct: Math.round((win / max) * 100) },
    { name: 'macOS', count: mac, pct: Math.round((mac / max) * 100) },
    { name: '移动端', count: mob, pct: Math.round((mob / max) * 100) }
  ];
});
async function doSave() {
  const title = node.value?.title ?? '';
  try {
    await api(`/policies/${selected.value}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, settings: sections.value, customCount: customCount.value })
    });
    Message.success(`策略已保存并下发至「${title}」的代理网关（已落库）`);
  } catch {
    Message.error('保存失败，请检查后端连接');
  }
  impact.open = false; impact.ack = false;
}

/* ── 全局策略（复刻设计稿开关行）── */
const gsec = ref('brute');
const globalSecs = reactive([
  { key: 'brute', label: '防暴力破解', rows: [
    { label: '图形校验码', desc: '登录时要求输入校验码（支持中文 / 英文）', on: true },
    { label: '同 IP 连续登录错误锁定', desc: '同一 IP 密码错误达阈值后锁定该 IP 一段时间', on: true, threshold: 5 },
    { label: '同用户名连续登录错误锁定', desc: '锁定的用户需管理员在「用户状态」处手动解封', on: true, threshold: 5 }
  ] },
  { key: 'access', label: '接入加速与限制', rows: [
    { label: '弱网带宽优化', desc: '优化 TCP，抗丢包抗抖动，提升弱网访问体验', on: true },
    { label: '时延优化（0RTT）', desc: 'Local Handshake + Early Data，仅 PC 短隧道资源生效', on: false },
    { label: '禁止用户通过浏览器登录', desc: '强制走客户端接入（暂不支持 Linux）', on: false, risk: true }
  ] },
  { key: 'client', label: '客户端强管控', rows: [
    { label: '强制安装客户端', desc: 'Web 认证页检测未装客户端则弹框引导安装', on: true },
    { label: '强制升级至最新客户端', desc: '检测到新版本则阻断登录直至更新；开启后自动关闭灰度', on: false, risk: true },
    { label: '开机自动启动客户端', desc: '默认开关，用户可在客户端侧个性化覆盖', on: true }
  ] }
] as { key: string; label: string; rows: { label: string; desc: string; on: boolean; threshold?: number; risk?: boolean }[] }[]);

/* ── 拉取 ── */
onMounted(async () => {
  try {
    const pb = await api<PolicyBundle>('/policies');
    tree.value = pb.tree; live.value = true;
  } catch { live.value = false; }
  await select(selected.value); // 回填初始节点的已存覆盖
});
</script>

<style scoped>
.bd-head__right { margin-left: auto; }

/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

.bd-two { display: flex; gap: 16px; align-items: flex-start; }

/* 树 */
.bd-tree { width: 286px; flex: none; padding: 10px; }
.bd-tree__h { font-size: 12px; font-weight: 600; color: var(--bd-t3); padding: 4px 8px 10px; }
.bd-tnode {
  width: 100%; display: flex; align-items: center; gap: 8px; height: 38px; padding-right: 10px;
  border: none; background: transparent; border-radius: 7px; cursor: pointer; font-size: 13px;
  color: var(--bd-t2); text-align: left; transition: background .12s;
}
.bd-tnode:hover { background: var(--bd-fill-2); }
.bd-tnode.on { background: var(--bd-primary-1); }
.bd-tnode.on .bd-tnode__t { color: var(--bd-primary); font-weight: 600; }
.bd-tnode__dot { width: 7px; height: 7px; border-radius: 50%; flex: none; }
.bd-tnode__dot.custom { background: var(--bd-primary); }
.bd-tnode__dot.inherit { background: #fff; border: 1.5px solid var(--bd-t4); }
.bd-tnode__t { flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bd-tnode__tag { font-size: 10px; padding: 1px 6px; border-radius: 4px; flex: none; }
.bd-tnode__tag.custom { background: var(--bd-primary-1); color: var(--bd-primary); }
.bd-tnode__tag.inherit { background: var(--bd-fill-2); color: var(--bd-t3); }
.bd-tnode__m { font-size: 11px; color: var(--bd-t3); width: 38px; text-align: right; flex: none; }

/* 编辑器 */
.bd-editor { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 14px; }
.bd-chain { padding: 16px 18px; }
.bd-chain__top { display: flex; align-items: flex-start; }
.bd-chain__name { font-size: 16px; font-weight: 700; }
.bd-chain__sub { font-size: 12px; color: var(--bd-t3); margin-left: 10px; }
.bd-chain__stat { margin-left: auto; display: flex; gap: 8px; }
.bd-pill { font-size: 12px; padding: 3px 10px; border-radius: 12px; font-weight: 500; }
.bd-pill--blue { background: var(--bd-primary-1); color: var(--bd-primary); }
.bd-pill--grey { background: var(--bd-fill-2); color: var(--bd-t3); }
.bd-chain__path { display: flex; align-items: center; gap: 8px; margin-top: 14px; flex-wrap: wrap; }
.bd-chain__label { font-size: 12px; color: var(--bd-t3); }
.bd-node { font-size: 12px; padding: 4px 12px; border-radius: 6px; background: var(--bd-fill-2); color: var(--bd-t2); }
.bd-node.self { background: var(--bd-primary); color: #fff; font-weight: 600; }
.bd-chain__arrow { color: var(--bd-t4); font-size: 13px; }

.bd-sec { padding: 4px 20px 8px; }
.bd-sec__h { font-size: 14px; font-weight: 600; padding: 16px 0 6px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-sec__h.plain { border: none; padding: 8px 0 12px; }
.bd-row { display: flex; align-items: center; gap: 12px; padding: 15px 0; border-bottom: 1px solid var(--bd-fill-1); }
.bd-row:last-child { border-bottom: none; }
.bd-row__main { flex: 1; min-width: 0; }
.bd-row__label { font-size: 13.5px; font-weight: 500; color: var(--bd-t1); display: flex; align-items: center; gap: 6px; }
.bd-row__desc { font-size: 12px; color: var(--bd-t3); margin-top: 3px; }
.bd-risk { font-size: 11px; color: var(--bd-warning); background: var(--bd-tag-gold-bg); padding: 1px 6px; border-radius: 4px; font-weight: 400; }
.bd-row__inval { font-size: 12.5px; color: var(--bd-t3); }
.bd-row__ctrl { display: inline-flex; align-items: center; gap: 6px; }
.bd-row__unit { font-size: 12.5px; color: var(--bd-t3); }
.bd-row__badge { font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: 500; }
.bd-row__badge.inherit { background: var(--bd-fill-2); color: var(--bd-t3); }
.bd-row__badge.custom { background: var(--bd-primary-1); color: var(--bd-primary); }
.bd-row__act { font-size: 12.5px; color: var(--bd-primary); cursor: pointer; font-weight: 500; }
.bd-row__act:hover { text-decoration: underline; }
.bd-thr { font-size: 12.5px; color: var(--bd-t2); }
.bd-thr b { display: inline-block; min-width: 30px; text-align: center; }

.bd-editor__foot { display: flex; justify-content: flex-end; gap: 10px; padding: 4px 0 10px; }

/* 全局策略 */
.bd-gsec-nav { width: 200px; flex: none; padding: 8px; }
.bd-gnav { width: 100%; text-align: left; border: none; background: transparent; font-size: 13px; color: var(--bd-t2); padding: 10px 12px; border-radius: 7px; cursor: pointer; }
.bd-gnav:hover { background: var(--bd-fill-2); }
.bd-gnav.on { background: var(--bd-primary-1); color: var(--bd-primary); font-weight: 600; }
.bd-gbody { flex: 1; min-width: 0; padding: 8px 24px 14px; }

/* 打破继承 modal */
.bd-brk { display: flex; gap: 12px; font-size: 13.5px; line-height: 1.7; color: var(--bd-t2); }
.bd-brk__ic { color: var(--bd-warning); font-size: 20px; flex: none; margin-top: 2px; }

/* impact modal */
.bd-imp__hl { font-size: 13.5px; line-height: 1.7; color: var(--bd-t2); background: var(--bd-primary-1); border: 1px solid var(--bd-primary-b); border-radius: 8px; padding: 12px 14px; }
.bd-imp__hl .num { color: var(--bd-primary); }
.bd-imp__t { font-size: 13px; font-weight: 600; margin: 18px 0 10px; }
.bd-bar { display: flex; align-items: center; gap: 12px; padding: 5px 0; }
.bd-bar__l { width: 64px; font-size: 12.5px; color: var(--bd-t2); }
.bd-bar__track { flex: 1; height: 10px; background: var(--bd-fill-2); border-radius: 6px; overflow: hidden; }
.bd-bar__fill { display: block; height: 100%; background: var(--bd-primary); border-radius: 6px; }
.bd-bar__v { width: 44px; text-align: right; font-size: 12.5px; }
.bd-conf { display: flex; align-items: flex-start; gap: 8px; font-size: 12.5px; line-height: 1.6; padding: 10px 12px; border-radius: 8px; margin-bottom: 8px; }
.bd-conf.warn { background: var(--bd-tag-gold-bg); color: #9A6300; }
.bd-conf.ok { background: var(--bd-tag-green-bg); color: #0B8235; }
.bd-imp__risk { display: flex; align-items: center; gap: 8px; margin: 14px 0; font-size: 13px; }
.bd-imp__rk { font-size: 12.5px; color: var(--bd-t3); }
.bd-imp__ack { margin: 4px 0 16px; }
.bd-imp__foot { display: flex; justify-content: flex-end; gap: 10px; }
.bd-btn[disabled] { cursor: not-allowed; }

/* 撤销条 */
.bd-undo {
  position: fixed; left: 50%; bottom: 28px; transform: translateX(-50%); z-index: 1000;
  display: flex; align-items: center; gap: 10px; background: #1D2129; color: #fff;
  padding: 10px 16px; border-radius: 8px; font-size: 13px; box-shadow: 0 6px 20px rgba(0, 0, 0, .25);
}
.bd-undo__btn { color: #6AA1FF; cursor: pointer; font-weight: 600; }
.bd-undo__t { color: #86909C; font-variant-numeric: tabular-nums; }
.bd-fade-enter-active, .bd-fade-leave-active { transition: opacity .2s; }
.bd-fade-enter-from, .bd-fade-leave-to { opacity: 0; }
</style>
