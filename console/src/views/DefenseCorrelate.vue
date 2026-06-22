<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">事件关联规则<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">流水线中段「关联聚合」：在<router-link to="/defense/policy">主动防御</router-link>单会话检测之上做跨事件时间窗聚合（N 次失败 + M 个新设备 = 高风险），命中按处置动作 + 投递告警渠道</div>
      </div>
      <a-button v-if="tab === 'rule'" type="primary" @click="openCreate"><template #icon><icon-plus /></template>新建关联规则</a-button>
    </div>

    <!-- 顶部说明条：关联引擎在统一审计流上滑窗聚合 -->
    <div class="cr-tip">
      <span class="cr-tip__ic">ⓘ</span>
      <span>关联引擎在统一审计流上按<b>聚合维度</b>分组、按<b>时间窗</b>滑窗计数；同一维度内命中事件数 ≥ <b>阈值</b>即触发处置动作并投递告警渠道，<b>冷却期</b>内不重复触发。处置当前为建议，自动收权待与策略引擎联动。</span>
    </div>

    <a-tabs v-model:active-key="tab" type="rounded">
      <!-- Tab1：关联规则 -->
      <a-tab-pane key="rule" title="关联规则">
        <div class="zl-card">
          <a-table :data="rules" :pagination="false" :bordered="false" row-key="key">
            <template #columns>
              <a-table-column title="规则名称" data-index="name" :width="190">
                <template #cell="{ record }">
                  <span style="font-weight:600;color:var(--ink)">{{ record.name }}</span>
                  <div class="data" style="font-size:11px;color:var(--ink-3);margin-top:2px">{{ record.key }}</div>
                </template>
              </a-table-column>
              <a-table-column title="匹配条件">
                <template #cell="{ record }">
                  <div style="font-size:12px;color:var(--ink-2)">
                    <span class="zl-badge zl-badge--idle" style="font-size:10.5px">{{ catLabel(record.match.category) }}</span>
                    <span style="margin-left:8px">命中
                      <template v-if="record.match.decisions.length">
                        <code v-for="d in record.match.decisions" :key="d" class="cr-code">{{ d }}</code>
                      </template>
                      <span v-else style="color:var(--ink-3)">任意判定</span>
                    </span>
                  </div>
                </template>
              </a-table-column>
              <a-table-column title="窗口" align="center" :width="84">
                <template #cell="{ record }"><span class="data" style="font-size:12px;color:var(--ink-2)">{{ fmtSec(record.window) }}</span></template>
              </a-table-column>
              <a-table-column title="阈值" align="center" :width="76">
                <template #cell="{ record }"><span class="data" style="font-weight:650;color:var(--accent-2)">≥{{ record.threshold }}</span><span class="data" style="font-size:11px;color:var(--ink-3)"> 次</span></template>
              </a-table-column>
              <a-table-column title="聚合维度" align="center" :width="92">
                <template #cell="{ record }"><span style="font-size:12px;color:var(--ink-2)">{{ groupLabel(record.groupBy) }}</span></template>
              </a-table-column>
              <a-table-column title="处置" align="center" :width="100">
                <template #cell="{ record }"><span class="zl-badge" :class="actClass(record.action)">{{ actLabel(record.action) }}</span></template>
              </a-table-column>
              <a-table-column title="启用" align="center" :width="74">
                <template #cell="{ record }"><a-switch v-model="record.enabled" size="small" @change="toggleRule(record)" /></template>
              </a-table-column>
              <a-table-column title="" align="center" :width="116">
                <template #cell="{ record }">
                  <a-space>
                    <a-button size="mini" @click="openEdit(record)">编辑</a-button>
                    <a-button size="mini" type="text" status="danger" @click="del(record)">删除</a-button>
                  </a-space>
                </template>
              </a-table-column>
            </template>
            <template #empty>
              <div class="cr-empty">
                <div class="cr-empty__big">未配置关联规则 · 仅单会话检测生效</div>
                <div class="cr-empty__sub">没有关联规则时，跨事件研判不生效，仅各页单点检测独立判定。新建规则可把多次失败 / 多设备异常聚合成高风险信号并触发处置。</div>
              </div>
            </template>
          </a-table>
        </div>
      </a-tab-pane>

      <!-- Tab2：触发历史 -->
      <a-tab-pane key="hits" title="触发历史">
        <div class="zl-card">
          <a-table :data="hits" :pagination="hits.length>15?{pageSize:15}:false" :bordered="false" row-key="key">
            <template #columns>
              <a-table-column title="时间" :width="150">
                <template #cell="{ record }"><span class="data" style="color:var(--ink-3)">{{ record.ts }}</span></template>
              </a-table-column>
              <a-table-column title="命中实体" data-index="actor" :width="180">
                <template #cell="{ record }"><span class="data" style="color:var(--ink)">{{ record.actor || '—' }}</span></template>
              </a-table-column>
              <a-table-column title="规则动作" align="center" :width="110">
                <template #cell="{ record }"><span class="zl-badge" :class="actClass(record.decision)">{{ actLabel(record.decision) }}</span></template>
              </a-table-column>
              <a-table-column title="详情">
                <template #cell="{ record }"><span style="font-size:12px;color:var(--ink-2)">{{ record.detail || '—' }}</span></template>
              </a-table-column>
            </template>
            <template #empty>
              <div class="cr-empty">
                <div class="cr-empty__big">暂无关联告警</div>
                <div class="cr-empty__sub">关联规则尚未在时间窗内命中任何聚合阈值。一旦某聚合维度内的事件数达到阈值，命中记录将出现在此并进入审计链。</div>
              </div>
            </template>
          </a-table>
        </div>
      </a-tab-pane>
    </a-tabs>

    <!-- 关联规则 编辑 / 新建 -->
    <a-modal v-model:visible="show" :title="editing ? '编辑关联规则' : '新建关联规则'" width="600px" @ok="submit" :ok-text="editing ? '保存' : '创建'">
      <a-form :model="form" layout="vertical">
        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="规则标识（key）" required>
              <a-input v-model="form.key" placeholder="例如：cr-bruteforce" :disabled="editing" />
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="规则名称" required>
              <a-input v-model="form.name" placeholder="例如：暴力破解关联告警" />
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <div class="cr-sec">匹配条件（match）</div>
        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="事件类别（category）">
              <a-select v-model="form.match.category">
                <a-option v-for="c in catOpts" :key="c.value" :value="c.value">{{ c.label }}</a-option>
              </a-select>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="命中判定（decisions）">
              <a-input-tag v-model="form.match.decisions" placeholder="如 deny / fail / lock，回车添加" allow-clear />
            </a-form-item>
          </a-grid-item>
        </a-grid>
        <div class="cr-hint" style="margin-top:-8px">仅统计该类别中判定命中任一标签的事件；留空 = 该类别全部判定均计入。</div>

        <div class="cr-sec">聚合参数</div>
        <a-grid :cols="3" :col-gap="16">
          <a-grid-item>
            <a-form-item label="时间窗（window 秒）">
              <a-input-number v-model="form.window" :min="10" :step="10" :style="{width:'100%'}">
                <template #suffix>秒</template>
              </a-input-number>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="阈值（threshold 次）">
              <a-input-number v-model="form.threshold" :min="1" :style="{width:'100%'}">
                <template #suffix>次</template>
              </a-input-number>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="聚合维度（groupBy）">
              <a-select v-model="form.groupBy">
                <a-option v-for="g in groupOpts" :key="g.value" :value="g.value">{{ g.label }}</a-option>
              </a-select>
            </a-form-item>
          </a-grid-item>
        </a-grid>
        <div class="cr-hint" style="margin-top:-8px">同一<b>聚合维度</b>分组内、<b>{{ fmtSec(form.window) }}</b>滑窗中命中事件数 ≥ <b>{{ form.threshold }}</b> 次即触发。维度选「全局」则不分组、跨实体合并计数。</div>

        <div class="cr-sec">处置与抑制</div>
        <a-grid :cols="3" :col-gap="16">
          <a-grid-item>
            <a-form-item label="严重级（severity）">
              <a-select v-model="form.severity">
                <a-option v-for="s in sevOpts" :key="s.value" :value="s.value">{{ s.label }}</a-option>
              </a-select>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="处置动作（action）">
              <a-select v-model="form.action">
                <a-option v-for="a in actOpts" :key="a.value" :value="a.value">{{ a.label }}</a-option>
              </a-select>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="冷却期（cooldown 秒）">
              <a-input-number v-model="form.cooldown" :min="0" :step="30" :style="{width:'100%'}">
                <template #suffix>秒</template>
              </a-input-number>
            </a-form-item>
          </a-grid-item>
        </a-grid>
        <div class="cr-hint" style="margin-top:-8px">冷却期 = 同一分组命中后的抑制时长，期内不重复触发；0 = 不抑制（每达阈值即触发）。</div>

        <a-form-item label="告警渠道（channels）">
          <a-input-tag v-model="form.channels" placeholder="渠道 key，如 syslog / webhook-soc / mail-admin，回车添加" allow-clear />
          <div class="cr-hint">命中后投递到这些通知渠道（对应「系统 · 通知」中配置的渠道 key）；留空 = 仅写审计不外发。</div>
        </a-form-item>

        <a-form-item label="启用本规则">
          <a-switch v-model="form.enabled" />
          <span class="cr-hint" style="margin-left:10px">关闭 = 规则不参与关联研判（不聚合、不触发、不告警）。</span>
        </a-form-item>
      </a-form>
      <div class="cr-modal-note">提示：关联规则调整 ≤60s 生效 · 命中写审计链（HMAC-SM3）。阈值过低易误报，建议先以 alert 告警观察聚合命中频率后再上锁定 / 隔离。</div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { defenseAction, defenseActionOptions } from '@/lib/defense';

/* —— 类型 —— */
// 关联规则文档（kind=correlrule，每条一文档）。
interface CorrelRule {
  key: string;
  name: string;
  match: {
    category: string;    // 后端审计 category 原值：访问决策/登录认证/设备态势/主动防御/配置变更
    decisions: string[]; // 如 deny / fail / lock，空=任意判定
  };
  allOf?: { category: string; decisions: string[] }[]; // 复合 AND 子条件（高级；UI 暂不编辑，但 round-trip 保留）
  window: number;       // 时间窗（秒）
  threshold: number;    // 阈值（次）
  groupBy: 'actor' | 'source' | '';                                 // 聚合维度，''=全局
  cooldown: number;     // 冷却抑制（秒）
  severity: 'low' | 'medium' | 'high' | 'critical';
  action: 'alert' | 'lock' | 'stepup' | 'quarantine';              // 告警/锁定/二次鉴权/隔离
  channels: string[];   // 告警渠道 key
  enabled: boolean;
}
// 触发历史行（GET /ctl/api/correlate/hits 返回审计事件数组）。
interface Hit { key: string; ts: string; actor: string; decision: string; detail: string }

/* —— 选项与中文化 —— */
// value 必须是后端审计事件的真实 category 字符串（correlator 按 e.Category 精确匹配），不能用英文代号。
const catOpts = [
  { value: '访问决策', label: '访问决策' },
  { value: '登录认证', label: '登录认证' },
  { value: '设备态势', label: '设备态势' },
  { value: '主动防御', label: '主动防御' },
  { value: '配置变更', label: '配置变更' }
];
const groupOpts = [
  { value: 'actor', label: 'actor（按主体）' },
  { value: 'source', label: 'source（按来源）' },
  { value: '', label: '全局（不分组）' }
];
const sevOpts = [
  { value: 'low', label: 'low（低）' },
  { value: 'medium', label: 'medium（中）' },
  { value: 'high', label: 'high（高）' },
  { value: 'critical', label: 'critical（严重）' }
];
const actOpts = defenseActionOptions(['alert', 'lock', 'stepup', 'quarantine']);
const catLabel = (c: string) => catOpts.find((x) => x.value === c)?.label ?? c;
const groupLabel = (g: string) => (g === 'actor' ? '主体' : g === 'source' ? '来源' : '全局');
const actLabel = (a: string) => defenseAction(a).label;
const actClass = (a: string) => defenseAction(a).badge;
// 秒 → 人类可读（窗口/冷却展示）。
const fmtSec = (s: number) => {
  if (!s || s <= 0) return '0 秒';
  if (s % 3600 === 0) return s / 3600 + ' 小时';
  if (s % 60 === 0) return s / 60 + ' 分钟';
  return s + ' 秒';
};

/* —— 前端默认（mock，加载后端后覆盖；与后端 seed 同形） —— */
const ruleFallback: CorrelRule[] = [
  { key: 'cr-bruteforce', name: '暴力破解关联告警', match: { category: '登录认证', decisions: ['fail'] }, window: 300, threshold: 5, groupBy: 'actor', cooldown: 600, severity: 'high', action: 'lock', channels: ['syslog', 'mail-admin'], enabled: true },
  { key: 'cr-impossible-travel', name: '异地多源高频访问', match: { category: '访问决策', decisions: ['deny', 'step-up'] }, window: 600, threshold: 8, groupBy: 'actor', cooldown: 900, severity: 'critical', action: 'stepup', channels: ['webhook-soc'], enabled: true },
  { key: 'cr-new-device-burst', name: '新设备态势异常聚集', match: { category: '设备态势', decisions: [] }, window: 1800, threshold: 3, groupBy: 'source', cooldown: 1800, severity: 'medium', action: 'alert', channels: ['syslog'], enabled: false }
];

const rules = ref<CorrelRule[]>(ruleFallback.map((r) => ({ ...r, match: { ...r.match, decisions: [...r.match.decisions] }, channels: [...r.channels] })));
const hits = ref<Hit[]>([]);

const tab = ref<'rule' | 'hits'>('rule');
const live = ref(false);

/* —— 加载关联规则（失败保留前端默认 mock 降级） —— */
async function loadRules() {
  try {
    const r = await fetch('/ctl/api/coll?kind=correlrule');
    if (!r.ok) return;
    const docs = await r.json();
    if (Array.isArray(docs) && docs.length) {
      rules.value = docs.map((d: any) => ({
        key: d.key ?? d.k,
        name: d.name ?? '',
        match: {
          category: typeof d.match?.category === 'string' && d.match.category ? d.match.category : '访问决策',
          decisions: Array.isArray(d.match?.decisions) ? d.match.decisions : []
        },
        allOf: Array.isArray(d.allOf) ? d.allOf : [], // 保留复合子条件（即便 UI 不编辑也不丢）
        window: typeof d.window === 'number' ? d.window : 300,
        threshold: typeof d.threshold === 'number' ? d.threshold : 5,
        groupBy: ['actor', 'source', ''].includes(d.groupBy) ? d.groupBy : 'actor',
        cooldown: typeof d.cooldown === 'number' ? d.cooldown : 0,
        severity: ['low', 'medium', 'high', 'critical'].includes(d.severity) ? d.severity : 'medium',
        action: actOpts.some((a) => a.value === d.action) ? d.action : 'alert',
        channels: Array.isArray(d.channels) ? d.channels : [],
        enabled: typeof d.enabled === 'boolean' ? d.enabled : true
      }));
    }
    live.value = true;
  } catch { live.value = false; }
}

/* —— 加载触发历史（命中即审计事件数组；不可达保留空态「暂无关联告警」） —— */
async function loadHits() {
  try {
    const r = await fetch('/ctl/api/correlate/hits');
    if (!r.ok) return;
    const list = await r.json();
    if (Array.isArray(list)) {
      hits.value = list.map((e: any, i: number) => ({
        key: (e.seq || 'hit') + '-' + i,
        ts: e.ts ?? '',
        actor: e.actor ?? '',
        decision: e.decision ?? e.action ?? 'alert',
        detail: e.detail ?? e.note ?? ''
      }));
    }
  } catch { /* 控制面不可达：保留空态 */ }
}

onMounted(() => { loadRules(); loadHits(); });

/* —— 持久化（POST 单条文档，后端写审计） —— */
async function persistRule(r: CorrelRule): Promise<boolean> {
  if (!live.value) return true; // mock 态仅前端反馈
  try {
    const res = await fetch('/ctl/api/coll?kind=correlrule', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: r.key, doc: JSON.parse(JSON.stringify(r)) })
    });
    return res.ok;
  } catch { return false; }
}

/* —— 行内启用开关：即时 toggle，写失败回滚 —— */
async function toggleRule(r: CorrelRule) {
  const ok = await persistRule(r);
  if (!ok && live.value) { r.enabled = !r.enabled; return Message.error('操作失败，已回滚'); }
  Message.info(`关联规则「${r.name}」已${r.enabled ? '启用' : '停用'}${live.value ? ' · 已持久化' : ''}`);
}

/* —— 新建 / 编辑 —— */
const show = ref(false);
const editing = ref(false);
function blank(): CorrelRule {
  return { key: '', name: '', match: { category: '登录认证', decisions: [] }, allOf: [], window: 300, threshold: 5, groupBy: 'actor', cooldown: 600, severity: 'medium', action: 'alert', channels: [], enabled: true };
}
const form = reactive<CorrelRule>(blank());

function openCreate() { editing.value = false; Object.assign(form, blank()); form.match = { category: '登录认证', decisions: [] }; show.value = true; }
function openEdit(r: CorrelRule) {
  editing.value = true;
  // 克隆，避免引用污染列表行。
  const clone: CorrelRule = JSON.parse(JSON.stringify(r));
  Object.assign(form, clone);
  form.match = { ...clone.match, decisions: [...clone.match.decisions] };
  form.channels = [...clone.channels];
  show.value = true;
}

async function submit() {
  if (!form.key) return Message.warning('请填写规则标识（key）');
  if (!form.name) return Message.warning('请填写规则名称');
  if (!editing.value && rules.value.some((x) => x.key === form.key)) return Message.warning(`规则标识「${form.key}」已存在`);
  const doc: CorrelRule = JSON.parse(JSON.stringify(form));
  if (editing.value) {
    const i = rules.value.findIndex((x) => x.key === doc.key);
    if (live.value && !(await persistRule(doc))) return Message.error('保存失败');
    if (i >= 0) rules.value[i] = doc;
    Message.success(`关联规则「${doc.name}」已更新${live.value ? ' · 已持久化' : '（mock）'}`);
  } else {
    if (live.value && !(await persistRule(doc))) return Message.error('创建失败');
    rules.value.push(doc);
    Message.success(`关联规则「${doc.name}」已创建${live.value ? ' · 已持久化' : '（mock）'}`);
  }
  show.value = false;
}

/* —— 删除（二次确认 + DELETE） —— */
function del(r: CorrelRule) {
  Modal.warning({
    title: `删除关联规则「${r.name}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: '删除后该规则不再参与跨事件研判（不聚合、不触发、不告警）。此操作进入审计链。',
    onOk: async () => {
      if (live.value) {
        try {
          const res = await fetch(`/ctl/api/coll?kind=correlrule&key=${encodeURIComponent(r.key)}`, { method: 'DELETE' });
          if (!res.ok) return Message.error('删除失败');
        } catch { return Message.error('控制面不可达'); }
      }
      rules.value = rules.value.filter((x) => x.key !== r.key);
      Message.success(`关联规则「${r.name}」已删除${live.value ? ' · 已持久化' : ''}`);
    }
  });
}
</script>

<style scoped>
:deep(.arco-table-tr) { cursor: default; }

/* 顶部说明条 */
.cr-tip { display: flex; align-items: flex-start; gap: 10px; background: var(--accent-soft); border: 1px solid var(--line); border-radius: var(--r-md); padding: 11px 14px; margin-bottom: 16px; font-size: 12.5px; color: var(--ink-2); line-height: 1.6; }
.cr-tip__ic { color: var(--accent-2); font-weight: 700; flex-shrink: 0; }
.cr-tip b { color: var(--accent-2); font-weight: 700; }

/* 匹配条件内的判定标签 */
.cr-code { display: inline-block; font-family: var(--font-data, monospace); font-size: 11px; color: var(--accent-2); background: var(--accent-soft); border-radius: 4px; padding: 0 5px; margin-right: 4px; }

/* modal 内分节标题 */
.cr-sec { font-size: 11.5px; font-weight: 700; color: var(--ink-3); margin: 6px 0 10px; }

/* 空态 */
.cr-empty { padding: 30px 16px; text-align: center; }
.cr-empty__big { font-size: 14px; font-weight: 650; color: var(--ink-2); }
.cr-empty__sub { font-size: 12px; color: var(--ink-3); margin-top: 8px; line-height: 1.6; max-width: 560px; margin-left: auto; margin-right: auto; }

.cr-hint { font-size: 11px; color: var(--ink-3); margin-top: 6px; line-height: 1.5; }
.cr-hint b { color: var(--accent-2); font-weight: 650; }
.cr-modal-note { font-size: 11.5px; color: var(--ink-3); line-height: 1.6; margin-top: 4px; }
</style>
