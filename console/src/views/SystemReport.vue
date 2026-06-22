<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">运营报表<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">报表为只读聚合（审计 / 用户）；定时订阅由网关内置调度按周期经 webhook / 钉钉渠道真发（邮件 / 厂商短信待外部网关）</div>
      </div>
      <a-button size="small" :loading="loadingReport" @click="loadReport(curReport)">
        <template #icon><icon-refresh /></template>刷新报表
      </a-button>
    </div>

    <!-- 上半：报表查看 -->
    <div class="zl-card zl-card__pad">
      <div class="rp-head">
        <div>
          <div class="zl-card__title">报表查看</div>
          <div class="rp-sub">切换报表即时聚合 · 数据来自统一审计流与用户库{{ generatedAt ? ' · 生成于 ' + generatedAt : '' }}</div>
        </div>
        <a-radio-group v-model="curReport" type="button" size="small" @change="(v:any)=>loadReport(v)">
          <a-radio v-for="r in REPORTS" :key="r.value" :value="r.value">{{ r.label }}</a-radio>
        </a-radio-group>
      </div>

      <!-- 安全概览 -->
      <div v-if="curReport === 'security-overview'" class="rp-body">
        <div class="rp-statline">
          <div class="rp-stat">
            <div class="rp-stat__label">审计事件总数</div>
            <div class="rp-stat__value">{{ sec.events }}</div>
            <div class="rp-stat__foot">入 HMAC-SM3 审计链的全量事件</div>
          </div>
          <div class="rp-stat">
            <div class="rp-stat__label">事件类别数</div>
            <div class="rp-stat__value">{{ secCategoryRows.length }}</div>
            <div class="rp-stat__foot">登录 / 策略 / 配置 / 访问决策</div>
          </div>
          <div class="rp-stat">
            <div class="rp-stat__label">拒绝 + 失败</div>
            <div class="rp-stat__value" :class="{ 'rp-stat__value--danger': secDenyFail > 0 }">{{ secDenyFail }}</div>
            <div class="rp-stat__foot">命中拒绝 / 登录失败判定</div>
          </div>
        </div>
        <div class="rp-two">
          <div>
            <div class="rp-block-title">审计类别分布</div>
            <div v-if="secCategoryRows.length" class="rp-bars">
              <div v-for="row in secCategoryRows" :key="row.name" class="rp-brow">
                <div class="rp-brow__lab">{{ row.name }}</div>
                <div class="rp-brow__track"><div class="rp-brow__fill" :style="{ width: row.w + '%' }"></div></div>
                <div class="rp-brow__val data">{{ row.val }}</div>
              </div>
            </div>
            <div v-else class="rp-empty">暂无审计类别数据</div>
          </div>
          <div>
            <div class="rp-block-title">判定分布</div>
            <div v-if="secDecisionRows.length" class="rp-bars">
              <div v-for="row in secDecisionRows" :key="row.key" class="rp-brow">
                <div class="rp-brow__lab"><span class="zl-badge" :class="decClass(row.key)">{{ decLabel(row.key) }}</span></div>
                <div class="rp-brow__track"><div class="rp-brow__fill" :class="decFill(row.key)" :style="{ width: row.w + '%' }"></div></div>
                <div class="rp-brow__val data">{{ row.val }}</div>
              </div>
            </div>
            <div v-else class="rp-empty">暂无判定数据</div>
          </div>
        </div>
      </div>

      <!-- 实体风险 TOP -->
      <div v-else-if="curReport === 'entity-risk'" class="rp-body">
        <div class="rp-block-title">实体风险 TOP（按账号累计风险分）</div>
        <div v-if="riskTop.length" class="rp-risk">
          <div v-for="(r, i) in riskTop" :key="r.actor + i" class="rp-risk__row">
            <div class="rp-risk__rank">{{ i + 1 }}</div>
            <div class="rp-risk__actor data">{{ r.actor }}</div>
            <div class="rp-risk__track"><div class="rp-risk__fill" :class="riskFill(r.risk)" :style="{ width: riskW(r.risk) + '%' }"></div></div>
            <span class="zl-badge" :class="riskBadge(r.risk)">{{ r.risk }}</span>
          </div>
        </div>
        <div v-else class="rp-empty">暂无风险实体 · 一切正常</div>
        <div class="rp-note">风险分 ≥70 标红、≥40 标橙 · 取自访问决策事件中各账号的最高风险评分</div>
      </div>

      <!-- 用户状态 -->
      <div v-else class="rp-body">
        <div class="rp-statline">
          <div class="rp-stat">
            <div class="rp-stat__label">纳管账号总数</div>
            <div class="rp-stat__value">{{ usr.total }}</div>
            <div class="rp-stat__foot">含正常 / 禁用 / 锁定 / 闲置</div>
          </div>
          <div class="rp-stat">
            <div class="rp-stat__label">锁定账号</div>
            <div class="rp-stat__value" :class="{ 'rp-stat__value--warn': usrLocked > 0 }">{{ usrLocked }}</div>
            <div class="rp-stat__foot">含防爆破 / 管理员锁定</div>
          </div>
          <div class="rp-stat">
            <div class="rp-stat__label">锁定原因种类</div>
            <div class="rp-stat__value">{{ usrLockReasonRows.length }}</div>
            <div class="rp-stat__foot">按 lockReason 聚合</div>
          </div>
        </div>
        <div class="rp-two">
          <div>
            <div class="rp-block-title">账号状态分布</div>
            <div v-if="usrStatusRows.length" class="rp-bars">
              <div v-for="row in usrStatusRows" :key="row.key" class="rp-brow">
                <div class="rp-brow__lab"><span class="zl-badge" :class="statusClass(row.key)">{{ statusLabel(row.key) }}</span></div>
                <div class="rp-brow__track"><div class="rp-brow__fill" :class="statusFill(row.key)" :style="{ width: row.w + '%' }"></div></div>
                <div class="rp-brow__val data">{{ row.val }}</div>
              </div>
            </div>
            <div v-else class="rp-empty">暂无账号状态数据</div>
          </div>
          <div>
            <div class="rp-block-title">锁定原因分布</div>
            <div v-if="usrLockReasonRows.length" class="rp-bars">
              <div v-for="row in usrLockReasonRows" :key="row.name" class="rp-brow">
                <div class="rp-brow__lab">{{ row.name }}</div>
                <div class="rp-brow__track"><div class="rp-brow__fill rp-brow__fill--warn" :style="{ width: row.w + '%' }"></div></div>
                <div class="rp-brow__val data">{{ row.val }}</div>
              </div>
            </div>
            <div v-else class="rp-empty">无锁定账号 · 一切正常</div>
          </div>
        </div>
      </div>
    </div>

    <!-- 下半：定时订阅 -->
    <div class="zl-card" style="margin-top:16px">
      <div class="zl-card__pad rp-sub-head">
        <div>
          <div class="zl-card__title">定时订阅</div>
          <div class="rp-sub">按周期生成报表并经通知渠道自动推送 · enabled=false 或空订阅 = 不推送（旧行为）</div>
        </div>
        <a-button type="primary" size="small" @click="openCreate"><template #icon><icon-plus /></template>新建订阅</a-button>
      </div>
      <a-table :data="subs" :pagination="false" :bordered="false" row-key="key">
        <template #columns>
          <a-table-column title="订阅标识" data-index="key" :width="180">
            <template #cell="{ record }">
              <span class="data" style="font-weight:600;color:var(--ink)">{{ record.key }}</span>
            </template>
          </a-table-column>
          <a-table-column title="报表" :width="160">
            <template #cell="{ record }">
              <span style="font-size:12.5px;color:var(--ink-2)">{{ reportLabel(record.report) }}</span>
            </template>
          </a-table-column>
          <a-table-column title="推送周期" align="center" :width="120">
            <template #cell="{ record }">
              <span v-if="record.intervalH > 0" class="data" style="color:var(--ink)">每 {{ record.intervalH }} 小时</span>
              <span v-else class="zl-badge zl-badge--idle">未设周期</span>
            </template>
          </a-table-column>
          <a-table-column title="通知渠道" :width="180">
            <template #cell="{ record }">
              <span class="zl-badge" :class="channelKnown(record.channel) ? 'zl-badge--accent' : 'zl-badge--idle'">{{ channelLabel(record.channel) }}</span>
            </template>
          </a-table-column>
          <a-table-column title="上次推送" :width="150">
            <template #cell="{ record }">
              <span class="data" style="font-size:12px;color:var(--ink-3)">{{ record.lastPushUnix > 0 ? fmtTs(record.lastPushUnix) : '从未推送' }}</span>
            </template>
          </a-table-column>
          <a-table-column title="启用" align="center" :width="80">
            <template #cell="{ record }">
              <a-switch v-model="record.enabled" size="small" @change="toggleSub(record)" />
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
          <div class="rp-tbl-empty">
            <div class="rp-tbl-empty__big">未配置定时订阅 · 不推送（旧行为）</div>
            <div class="rp-tbl-empty__sub">没有任何订阅时网关不会主动推送报表。新建订阅后由内置调度按周期经 webhook / 钉钉渠道真发。</div>
          </div>
        </template>
      </a-table>
    </div>

    <!-- 订阅 编辑 / 新建 -->
    <a-modal v-model:visible="show" :title="editing ? '编辑订阅' : '新建订阅'" width="520px" @ok="submit" :ok-text="editing ? '保存' : '创建'">
      <a-form :model="form" layout="vertical">
        <a-form-item label="订阅标识（key）" required>
          <a-input v-model="form.key" placeholder="例如：rs-daily-sec" :disabled="editing" />
        </a-form-item>
        <a-form-item label="报表类型（report）">
          <a-select v-model="form.report">
            <a-option v-for="r in REPORTS" :key="r.value" :value="r.value">{{ r.label }}</a-option>
          </a-select>
        </a-form-item>
        <a-form-item label="推送周期（intervalH）">
          <a-input-number v-model="form.intervalH" :min="0" :style="{ width: '200px' }">
            <template #suffix>小时</template>
          </a-input-number>
          <div class="rp-hint">每隔多少小时推送一次；0 = 不推送（停用调度）。常用 24（每日）/ 168（每周）。</div>
        </a-form-item>
        <a-form-item label="通知渠道（channel）">
          <a-select v-model="form.channel" placeholder="选择已配置的通知渠道" allow-clear>
            <a-option v-for="c in channels" :key="c.key" :value="c.key">{{ c.name || c.key }}（{{ c.key }}）</a-option>
          </a-select>
          <div class="rp-hint">渠道来源「告警通知渠道」配置 · 仅 webhook / 钉钉为真发，邮件 / 短信待外部网关。</div>
        </a-form-item>
        <a-form-item label="启用本订阅">
          <a-switch v-model="form.enabled" />
          <span class="rp-hint" style="margin-left:10px">关闭 = 调度跳过本订阅（不推送）。</span>
        </a-form-item>
      </a-form>
      <div class="rp-modal-note">提示：订阅由网关内置 ticker 按周期检查并经渠道投递，回写上次推送时间 · 写审计。</div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

/* —— 报表类型选项 —— */
const REPORTS = [
  { value: 'security-overview', label: '安全概览' },
  { value: 'entity-risk', label: '实体风险' },
  { value: 'user-status', label: '用户状态' }
];
const reportLabel = (v: string) => REPORTS.find((r) => r.value === v)?.label ?? v;

/* —— 报表聚合结构（与后端 buildReport 输出同形） —— */
interface SecOverview { byCategory: Record<string, number>; byDecision: Record<string, number>; events: number }
interface RiskItem { actor: string; risk: number }
interface UserStatus { total: number; byStatus: Record<string, number>; byLockReason: Record<string, number> }

/* —— 前端默认（mock，加载后端后覆盖；与后端聚合同形） —— */
const secFallback: SecOverview = {
  byCategory: { 访问决策: 1284, 登录认证: 642, 策略变更: 73, 配置变更: 41 },
  byDecision: { allow: 1106, 'step-up': 138, deny: 96, success: 588, fail: 54 },
  events: 2040
};
const riskFallback: RiskItem[] = [
  { actor: 'wang.lei@corp', risk: 82 },
  { actor: 'contractor.zhao', risk: 67 },
  { actor: 'li.fang@corp', risk: 51 },
  { actor: 'svc-backup', risk: 38 },
  { actor: 'chen.bo@corp', risk: 22 }
];
const usrFallback: UserStatus = {
  total: 312,
  byStatus: { active: 286, disabled: 12, locked: 4, idle: 10 },
  byLockReason: { 防爆破锁定: 3, 管理员锁定: 1 }
};

const curReport = ref<'security-overview' | 'entity-risk' | 'user-status'>('security-overview');
const sec = ref<SecOverview>({ ...secFallback });
const riskTop = ref<RiskItem[]>(riskFallback.map((r) => ({ ...r })));
const usr = ref<UserStatus>({ ...usrFallback });
const generatedAt = ref('');

const live = ref(false);
const loadingReport = ref(false);

/* —— 报表加载（按当前类型拉对应端点；失败保留前端默认 mock 降级） —— */
async function loadReport(name: string) {
  loadingReport.value = true;
  try {
    const r = await fetch(`/ctl/api/report/${name}`);
    if (!r.ok) { live.value = false; return; }
    const data = await r.json();
    if (name === 'security-overview') {
      sec.value = {
        byCategory: data.byCategory && typeof data.byCategory === 'object' ? data.byCategory : secFallback.byCategory,
        byDecision: data.byDecision && typeof data.byDecision === 'object' ? data.byDecision : secFallback.byDecision,
        events: typeof data.events === 'number' ? data.events : secFallback.events
      };
    } else if (name === 'entity-risk') {
      riskTop.value = Array.isArray(data.entityRiskTop) ? data.entityRiskTop : [];
    } else {
      usr.value = {
        total: typeof data.total === 'number' ? data.total : 0,
        byStatus: data.byStatus && typeof data.byStatus === 'object' ? data.byStatus : {},
        byLockReason: data.byLockReason && typeof data.byLockReason === 'object' ? data.byLockReason : {}
      };
    }
    generatedAt.value = data.generatedAt ?? '';
    live.value = true;
  } catch { live.value = false; } finally { loadingReport.value = false; }
}

/* —— 安全概览派生：类别 / 判定横向条 —— */
const secCategoryRows = computed(() => {
  const e = Object.entries(sec.value.byCategory || {});
  if (!e.length) return [];
  const max = Math.max(...e.map(([, v]) => v as number), 1);
  return e.map(([name, val]) => ({ name, val: val as number, w: Math.round(((val as number) / max) * 100) })).sort((a, b) => b.val - a.val);
});
const DEC_ORDER = ['allow', 'step-up', 'deny', 'success', 'fail'];
const secDecisionRows = computed(() => {
  const m = sec.value.byDecision || {};
  const known = DEC_ORDER.filter((k) => k in m);
  const extra = Object.keys(m).filter((k) => !DEC_ORDER.includes(k));
  const keys = [...known, ...extra];
  if (!keys.length) return [];
  const max = Math.max(...keys.map((k) => m[k] as number), 1);
  return keys.map((key) => ({ key, val: m[key] as number, w: Math.round(((m[key] as number) / max) * 100) }));
});
const secDenyFail = computed(() => (sec.value.byDecision?.deny ?? 0) + (sec.value.byDecision?.fail ?? 0));

/* —— 判定中文化 / 配色（与监控大屏一致） —— */
const decLabel = (k: string) => ({ allow: '允许', 'step-up': '二次鉴权', deny: '拒绝', success: '成功', fail: '失败' } as Record<string, string>)[k] || k || '—';
const decClass = (k: string) => ({ allow: 'zl-badge--ok', 'step-up': 'zl-badge--warn', deny: 'zl-badge--danger', success: 'zl-badge--ok', fail: 'zl-badge--danger' } as Record<string, string>)[k] || 'zl-badge--idle';
const decFill = (k: string) => (k === 'allow' || k === 'success' ? 'rp-brow__fill--ok' : k === 'deny' || k === 'fail' ? 'rp-brow__fill--danger' : k === 'step-up' ? 'rp-brow__fill--warn' : '');

/* —— 实体风险阶梯（≥70 红 · ≥40 橙 · 其余中性） —— */
const riskW = (r: number) => Math.max(4, Math.min(100, Math.round((r / 100) * 100)));
const riskFill = (r: number) => (r >= 70 ? 'rp-risk__fill--danger' : r >= 40 ? 'rp-risk__fill--warn' : 'rp-risk__fill--accent');
const riskBadge = (r: number) => (r >= 70 ? 'zl-badge--danger' : r >= 40 ? 'zl-badge--warn' : 'zl-badge--accent');

/* —— 用户状态派生 —— */
const STATUS_ORDER = ['active', 'disabled', 'locked', 'idle'];
const usrStatusRows = computed(() => {
  const m = usr.value.byStatus || {};
  const known = STATUS_ORDER.filter((k) => k in m);
  const extra = Object.keys(m).filter((k) => !STATUS_ORDER.includes(k));
  const keys = [...known, ...extra];
  if (!keys.length) return [];
  const max = Math.max(...keys.map((k) => m[k] as number), 1);
  return keys.map((key) => ({ key, val: m[key] as number, w: Math.round(((m[key] as number) / max) * 100) }));
});
const usrLockReasonRows = computed(() => {
  const e = Object.entries(usr.value.byLockReason || {});
  if (!e.length) return [];
  const max = Math.max(...e.map(([, v]) => v as number), 1);
  return e.map(([name, val]) => ({ name, val: val as number, w: Math.round(((val as number) / max) * 100) })).sort((a, b) => b.val - a.val);
});
const usrLocked = computed(() => usr.value.byStatus?.locked ?? 0);
const statusLabel = (k: string) => ({ active: '正常', disabled: '禁用', locked: '锁定', idle: '闲置' } as Record<string, string>)[k] || k || '—';
const statusClass = (k: string) => ({ active: 'zl-badge--ok', disabled: 'zl-badge--idle', locked: 'zl-badge--danger', idle: 'zl-badge--warn' } as Record<string, string>)[k] || 'zl-badge--idle';
const statusFill = (k: string) => (k === 'active' ? 'rp-brow__fill--ok' : k === 'locked' ? 'rp-brow__fill--danger' : k === 'idle' ? 'rp-brow__fill--warn' : '');

/* ============ 下半：定时订阅 ============ */
// 报表订阅文档（kind=reportsub，每条一文档）。
interface ReportSub { key: string; report: string; intervalH: number; channel: string; enabled: boolean; lastPushUnix: number }
// 通知渠道（kind=notifychannel）下拉来源，仅取 key/name 展示。
interface Channel { key: string; name: string; type: string; enabled: boolean }

const subsFallback: ReportSub[] = [
  { key: 'rs-daily-sec', report: 'security-overview', intervalH: 24, channel: 'ch-soc-webhook', enabled: false, lastPushUnix: 0 }
];
const channelsFallback: Channel[] = [
  { key: 'ch-soc-webhook', name: 'SOC Webhook', type: 'webhook', enabled: true },
  { key: 'ch-ops-dingtalk', name: '运维钉钉群', type: 'dingtalk', enabled: false },
  { key: 'ch-admin-sms', name: '管理员短信', type: 'sms', enabled: false }
];

const subs = ref<ReportSub[]>(subsFallback.map((s) => ({ ...s })));
const channels = ref<Channel[]>(channelsFallback.map((c) => ({ ...c })));
const liveSub = ref(false);

// 订阅集合：失败保留前端默认 mock 降级。
async function loadSubs() {
  try {
    const r = await fetch('/ctl/api/coll?kind=reportsub');
    if (!r.ok) return;
    const docs = await r.json();
    subs.value = (Array.isArray(docs) ? docs : []).map((d: any) => ({
      key: d.key ?? d.k,
      report: REPORTS.some((x) => x.value === d.report) ? d.report : 'security-overview',
      intervalH: typeof d.intervalH === 'number' ? d.intervalH : 0,
      channel: d.channel ?? '',
      enabled: typeof d.enabled === 'boolean' ? d.enabled : false,
      lastPushUnix: typeof d.lastPushUnix === 'number' ? d.lastPushUnix : 0
    }));
    liveSub.value = true;
  } catch { liveSub.value = false; }
}
// 渠道下拉来源（取 key/name）；失败保留前端默认。
async function loadChannels() {
  try {
    const r = await fetch('/ctl/api/coll?kind=notifychannel');
    if (!r.ok) return;
    const docs = await r.json();
    if (Array.isArray(docs) && docs.length) {
      channels.value = docs.map((d: any) => ({ key: d.key ?? d.k, name: d.name ?? '', type: d.type ?? '', enabled: !!d.enabled }));
    }
  } catch { /* 保留默认渠道 */ }
}

onMounted(() => { loadReport(curReport.value); loadSubs(); loadChannels(); });

const channelKnown = (k: string) => !!k && channels.value.some((c) => c.key === k);
const channelLabel = (k: string) => {
  if (!k) return '未指定渠道';
  const c = channels.value.find((x) => x.key === k);
  return c ? (c.name || c.key) : k;
};
// Unix 秒 → 本地时间字符串。
const fmtTs = (unix: number) => new Date(unix * 1000).toLocaleString('zh-CN', { hour12: false });

/* —— 持久化（POST 单条文档，后端写审计） —— */
async function persistSub(s: ReportSub) {
  if (!liveSub.value) return true;
  try {
    const res = await fetch('/ctl/api/coll?kind=reportsub', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: s.key, doc: { ...s } })
    });
    return res.ok;
  } catch { return false; }
}

/* —— 行内启用开关：即时 toggle，写失败回滚 —— */
async function toggleSub(s: ReportSub) {
  const ok = await persistSub(s);
  if (!ok && liveSub.value) { s.enabled = !s.enabled; return Message.error('操作失败，已回滚'); }
  Message.info(`订阅「${s.key}」已${s.enabled ? '启用' : '停用'}${liveSub.value ? ' · 已持久化' : ''}`);
}

/* —— 新建 / 编辑 —— */
const show = ref(false);
const editing = ref(false);
const form = reactive<ReportSub>({ key: '', report: 'security-overview', intervalH: 24, channel: '', enabled: true, lastPushUnix: 0 });

function openCreate() {
  editing.value = false;
  Object.assign(form, { key: '', report: 'security-overview', intervalH: 24, channel: channels.value[0]?.key ?? '', enabled: true, lastPushUnix: 0 });
  show.value = true;
}
function openEdit(r: ReportSub) {
  editing.value = true;
  // 克隆，避免引用污染列表行。
  Object.assign(form, JSON.parse(JSON.stringify(r)));
  show.value = true;
}

async function submit() {
  if (!form.key) return Message.warning('请填写订阅标识（key）');
  if (!editing.value && subs.value.some((x) => x.key === form.key)) return Message.warning(`订阅标识「${form.key}」已存在`);
  const doc: ReportSub = { key: form.key, report: form.report, intervalH: form.intervalH, channel: form.channel, enabled: form.enabled, lastPushUnix: form.lastPushUnix };
  if (editing.value) {
    const i = subs.value.findIndex((x) => x.key === doc.key);
    if (liveSub.value && !(await persistSub(doc))) return Message.error('保存失败');
    if (i >= 0) subs.value[i] = doc;
    Message.success(`订阅「${doc.key}」已更新${liveSub.value ? ' · 已持久化' : '（mock）'}`);
  } else {
    if (liveSub.value && !(await persistSub(doc))) return Message.error('创建失败');
    subs.value.push(doc);
    Message.success(`订阅「${doc.key}」已创建${liveSub.value ? ' · 已持久化' : '（mock）'}`);
  }
  show.value = false;
}

/* —— 删除（二次确认 + DELETE） —— */
function del(r: ReportSub) {
  Modal.warning({
    title: `删除订阅「${r.key}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: '删除后该订阅停止推送，网关调度不再为其生成与投递报表。此操作进入审计链。',
    onOk: async () => {
      if (liveSub.value) {
        try {
          const res = await fetch(`/ctl/api/coll?kind=reportsub&key=${encodeURIComponent(r.key)}`, { method: 'DELETE' });
          if (!res.ok) return Message.error('删除失败');
        } catch { return Message.error('控制面不可达'); }
      }
      subs.value = subs.value.filter((x) => x.key !== r.key);
      Message.success(`订阅「${r.key}」已删除${liveSub.value ? ' · 已持久化' : ''}`);
    }
  });
}
</script>

<style scoped>
:deep(.arco-table-tr) { cursor: default; }

/* 报表查看 头部 */
.rp-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
.rp-sub { font-size: 11.5px; color: var(--ink-3); margin-top: 4px; line-height: 1.5; }
.rp-body { margin-top: 4px; }

/* 数字卡条 */
.rp-statline { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 22px; }
.rp-stat { padding: 14px 16px; border: 1px solid var(--line); border-radius: var(--r-md); background: var(--accent-soft); }
.rp-stat__label { font-size: 12px; color: var(--ink-3); }
.rp-stat__value { font-size: 26px; font-weight: 750; color: var(--ink); line-height: 1.15; letter-spacing: -0.02em; font-family: var(--font-data); margin: 4px 0; }
.rp-stat__value--warn { color: var(--warn); }
.rp-stat__value--danger { color: var(--danger); }
.rp-stat__foot { font-size: 11px; color: var(--ink-3); }

/* 两栏分布 */
.rp-two { display: grid; grid-template-columns: repeat(2, 1fr); gap: 28px; align-items: start; }
.rp-block-title { font-size: 12.5px; font-weight: 650; color: var(--ink-2); margin-bottom: 14px; }
.rp-empty { padding: 24px 8px; text-align: center; font-size: 12.5px; color: var(--ink-3); }

/* 横向条形 */
.rp-bars { display: flex; flex-direction: column; gap: 12px; }
.rp-brow { display: grid; grid-template-columns: 96px 1fr 56px; align-items: center; gap: 12px; }
.rp-brow__lab { font-size: 12.5px; color: var(--ink-2); font-weight: 600; }
.rp-brow__track { height: 14px; border-radius: 5px; background: var(--line); overflow: hidden; }
.rp-brow__fill { height: 100%; border-radius: 5px; background: var(--accent-2); transition: width .3s ease; min-width: 3px; }
.rp-brow__fill--ok { background: var(--ok); }
.rp-brow__fill--danger { background: var(--danger); }
.rp-brow__fill--warn { background: var(--warn); }
.rp-brow__val { text-align: right; font-size: 13px; font-weight: 650; color: var(--ink); }

/* 实体风险 TOP */
.rp-risk { display: flex; flex-direction: column; }
.rp-risk__row { display: grid; grid-template-columns: 22px 160px 1fr 48px; align-items: center; gap: 12px; padding: 9px 0; }
.rp-risk__row + .rp-risk__row { border-top: 1px solid var(--line); }
.rp-risk__rank { font-size: 12px; font-weight: 700; color: var(--ink-3); text-align: center; }
.rp-risk__actor { font-size: 12.5px; color: var(--ink); font-weight: 600; overflow: hidden; text-overflow: ellipsis; }
.rp-risk__track { height: 8px; border-radius: 4px; background: var(--line); overflow: hidden; }
.rp-risk__fill { height: 100%; border-radius: 4px; background: var(--accent-2); transition: width .3s ease; }
.rp-risk__fill--danger { background: var(--danger); }
.rp-risk__fill--warn { background: var(--warn); }
.rp-risk__fill--accent { background: var(--accent-2); }
.rp-note { margin-top: 16px; padding: 10px 12px; border-radius: var(--r-md); background: var(--accent-soft); font-size: 11.5px; color: var(--ink-2); line-height: 1.6; }

/* 定时订阅 头部 */
.rp-sub-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }

/* 表格空态 */
.rp-tbl-empty { padding: 30px 16px; text-align: center; }
.rp-tbl-empty__big { font-size: 14px; font-weight: 650; color: var(--ink-2); }
.rp-tbl-empty__sub { font-size: 12px; color: var(--ink-3); margin-top: 8px; line-height: 1.6; max-width: 560px; margin-left: auto; margin-right: auto; }

.rp-hint { font-size: 11px; color: var(--ink-3); margin-top: 6px; line-height: 1.5; }
.rp-modal-note { font-size: 11.5px; color: var(--ink-3); line-height: 1.6; margin-top: 4px; }
</style>
