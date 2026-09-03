<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">业务告警</div>
        <div class="bd-page__sub">设备异常 · 授权信息 · 安全事件 —— 每条规则都读一份真实信号</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'red'" bordered>{{ live ? '已连 baidi-control' : '未连控制中心' }}</a-tag>
        <button class="bd-btn bd-btn--ghost" :disabled="busy" @click="evaluateNow">
          <icon-play-arrow />立即检测
        </button>
        <button class="bd-btn bd-btn--ghost" @click="loadAll"><icon-refresh />刷新</button>
      </div>
    </div>

    <!-- ★不连后端时**不给演示告警**：一页编造的"未处理告警"会让人以为系统正在监控。
         这里如实空着并说明原因，与其余页面的降级演示刻意不同。 -->
    <div v-if="err" class="bd-warn"><icon-exclamation-circle-fill />{{ err }}</div>

    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'list' }" @click="tab = 'list'">
        告警列表
        <span v-if="counts.pending" class="bd-badge">{{ counts.pending }}</span>
      </span>
      <span class="bd-tab" :class="{ on: tab === 'rules' }" @click="tab = 'rules'">
        告警规则 <em>{{ rules.length }}</em>
      </span>
    </div>

    <!-- ============ 告警列表 ============ -->
    <div v-show="tab === 'list'">
      <div class="bd-stats">
        <div class="bd-stat" :class="{ on: status === 'pending' }" @click="setStatus('pending')">
          <span class="bd-stat__n" style="color: var(--bd-danger)">{{ counts.pending }}</span>
          <span class="bd-stat__l">未处理</span>
        </div>
        <div class="bd-stat" :class="{ on: status === 'handled' }" @click="setStatus('handled')">
          <span class="bd-stat__n">{{ counts.handled }}</span>
          <span class="bd-stat__l">已处理</span>
        </div>
        <div class="bd-stat" :class="{ on: status === 'ignored' }" @click="setStatus('ignored')">
          <span class="bd-stat__n" style="color: var(--bd-t3)">{{ counts.ignored }}</span>
          <span class="bd-stat__l">已忽略</span>
        </div>
        <div class="bd-stat bd-stat--note">
          计数为全局量，不随下方筛选变化
        </div>
      </div>

      <div class="bd-tablecard">
        <div class="bd-toolbar">
          <div class="bd-filters">
            <a-select v-model="status" :style="{ width: '130px' }" placeholder="全部状态" allow-clear @change="loadAlerts">
              <a-option value="pending">未处理</a-option>
              <a-option value="handled">已处理</a-option>
              <a-option value="ignored">已忽略</a-option>
            </a-select>
            <a-select v-model="category" :style="{ width: '140px' }" placeholder="全部类别" allow-clear @change="loadAlerts">
              <a-option value="device">设备异常</a-option>
              <a-option value="authz">授权信息</a-option>
              <a-option value="security">安全事件</a-option>
            </a-select>
            <a-range-picker v-model="range" style="width: 250px" @change="loadAlerts" />
          </div>
          <!-- ★截断必须可见：列表被后端 AlertListLimit 硬截，而页头那三个计数是全局量。
               不说的话，「未处理 350」会和一张 200 行的表并排显示，第 201 条之后的告警
               在管理台上根本不存在，页面上也没有任何线索。 -->
          <span class="bd-toolbar__c" :class="{ 'bd-toolbar__c--warn': listTruncated }">
            <template v-if="listTotal !== undefined">
              共 {{ listTotal }} 条<template v-if="listTruncated">，本页只显示最近 {{ alerts.length }} 条</template>
            </template>
            <template v-else>当前列表 {{ alerts.length }} 条</template>
          </span>
        </div>

        <table class="bd-table">
          <thead>
            <tr>
              <th style="width: 92px">严重度</th>
              <th style="width: 96px">类别</th>
              <th>告警</th>
              <th style="width: 160px">触发时间</th>
              <th style="width: 132px">状态</th>
              <th class="r" style="width: 130px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!alerts.length">
              <td colspan="6" class="bd-tcenter">{{ live ? '当前筛选下没有告警' : '未连接控制中心，无法读取告警' }}</td>
            </tr>
            <tr v-for="a in alerts" :key="a.id">
              <td><span class="bd-pill" :class="'sev-' + a.severity">{{ sevZh[a.severity] }}</span></td>
              <td>{{ catZh[a.category] || a.category }}</td>
              <td>
                <div class="bd-al__t">{{ a.title }}</div>
                <div class="bd-al__d">{{ a.detail }}</div>
                <div class="bd-al__o bd-mono">{{ a.objectKey }}</div>
              </td>
              <td class="bd-mono">{{ fmtTs(a.triggeredAt) }}</td>
              <td>
                <span class="bd-pill" :class="'st-' + a.status">{{ statusZh[a.status] }}</span>
                <div v-if="a.handledBy" class="bd-al__by">{{ a.handledBy }} · {{ fmtTs(a.handledAt || 0) }}</div>
              </td>
              <td class="r">
                <template v-if="a.status === 'pending'">
                  <span class="bd-link" @click="decide(a, 'handle')">标记已处理</span>
                  <span class="bd-link bd-link--grey" style="margin-left: 10px" @click="decide(a, 'ignore')">忽略</span>
                </template>
                <span v-else class="bd-link bd-link--grey">—</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ============ 告警规则 ============ -->
    <div v-show="tab === 'rules'">
      <div class="bd-sep__note">
        <icon-safe />
        <span>
          每条规则读的都是<b>真实存在</b>的信号（「信号来源」写的就是取数点）。
          同一规则同一对象在<b>冷却期</b>内只产生一条——网关离线这类条件会持续成立，
          不冷却的话每轮评估刷一条，告警页当场不可用。
        </span>
      </div>
      <div v-if="notify" class="bd-sep__note" :class="{ 'bd-sep__note--warn': !notify.wired }">
        <icon-notification />
        <span v-if="notify.wired">{{ notify.note }}（可用通道 {{ notify.channels.filter(c => c.enabled).length }} 条）</span>
        <span v-else>{{ notify.reason }}</span>
      </div>

      <div class="bd-tablecard">
        <table class="bd-table">
          <thead>
            <tr>
              <th>规则</th>
              <th style="width: 96px">类别</th>
              <th style="width: 230px">阈值</th>
              <th style="width: 120px">冷却期</th>
              <th style="width: 200px">数据源</th>
              <th style="width: 210px">通知通道</th>
              <th class="r" style="width: 110px">启用</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!rules.length"><td colspan="7" class="bd-tcenter">未读取到告警规则</td></tr>
            <tr v-for="r in rules" :key="r.id">
              <td>
                <div class="bd-al__t">{{ r.name }}</div>
                <div class="bd-al__d">信号来源：{{ specOf(r.kind)?.signal || '—' }}</div>
              </td>
              <td>{{ catZh[specOf(r.kind)?.category || ''] || '—' }}</td>
              <td>
                <div v-if="!Object.keys(r.threshold).length" class="bd-al__o">无阈值（条件成立即报）</div>
                <div v-for="(v, k) in r.threshold" :key="k" class="bd-th">
                  <span>{{ specOf(r.kind)?.thresholdZh?.[k] || k }}</span>
                  <a-input-number
                    :model-value="v" :min="0" size="mini" style="width: 96px"
                    @change="(nv) => saveThreshold(r, k as string, Number(nv ?? 0))"
                  />
                </div>
              </td>
              <td>
                <a-input-number
                  :model-value="r.cooldownSec" :min="cooldown.min" :max="cooldown.max" :step="60"
                  size="mini" style="width: 100px" @change="(nv) => saveCooldown(r, Number(nv ?? cooldown.default))"
                />
                <div class="bd-al__o">秒</div>
              </td>
              <td>
                <template v-if="sourceOf(r.kind)">
                  <span class="bd-pill" :class="sourceOf(r.kind)!.ready ? 'st-handled' : 'st-pending'">
                    {{ sourceOf(r.kind)!.ready ? '数据就绪' : '等待数据面上报' }}
                  </span>
                  <div v-if="!sourceOf(r.kind)!.ready" class="bd-al__d">{{ sourceOf(r.kind)!.reason }}</div>
                </template>
                <span v-else class="bd-al__o">—</span>
              </td>
              <!-- 通知通道多选：留空 = 发给全部启用通道，点名 = 只发这几条
                   （与后端 notifyAlert 的语义逐字一致）。 -->
              <td>
                <a-select
                  :model-value="r.channels ?? []" multiple allow-clear size="mini"
                  placeholder="全部启用通道" :style="{ width: '196px' }"
                  :disabled="!notify?.wired"
                  @change="(v) => saveChannels(r, (v as string[]) ?? [])"
                >
                  <a-option v-for="c in notify?.channels ?? []" :key="c.id" :value="c.id" :disabled="!c.enabled">
                    {{ c.name }}<template v-if="!c.enabled">（已停用）</template>
                  </a-option>
                </a-select>
                <div class="bd-al__o">{{ (r.channels?.length ?? 0) ? `只发这 ${r.channels.length} 条` : '发给全部启用通道' }}</div>
              </td>
              <td class="r">
                <a-switch :model-value="r.enabled" size="small" @change="(v) => saveEnabled(r, v === true)" />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import {
  api,
  type Alert, type AlertCounts, type AlertsResp, type AlertRule, type AlertRulesResp,
  type AlertKindSpec, type AlertDataSource, type AlertNotifyOption, failReason, failStatus } from '@/lib/api';
import { refreshBadges } from '@/lib/badges';

const tab = ref<'list' | 'rules'>('list');
const live = ref(false);
const busy = ref(false);
const err = ref('');

const alerts = ref<Alert[]>([]);
const counts = ref<AlertCounts>({ pending: 0, ignored: 0, handled: 0 });
const rules = ref<AlertRule[]>([]);
const kinds = ref<AlertKindSpec[]>([]);
const sources = ref<AlertDataSource[]>([]);
const notify = ref<{ wired: boolean; channels: AlertNotifyOption[]; note?: string; reason?: string } | null>(null);
const cooldown = ref({ default: 1800, min: 60, max: 86400 });

const status = ref<string | undefined>(undefined);
const category = ref<string | undefined>(undefined);
const range = ref<string[]>([]);

const sevZh: Record<string, string> = { info: '提示', warning: '警告', critical: '严重' };
const statusZh: Record<string, string> = { pending: '未处理', ignored: '已忽略', handled: '已处理' };
const catZh: Record<string, string> = { device: '设备异常', authz: '授权信息', security: '安全事件' };

function specOf(kind: string): AlertKindSpec | undefined { return kinds.value.find(k => k.kind === kind); }
function sourceOf(kind: string): AlertDataSource | undefined { return sources.value.find(s => s.kind === kind); }
function fmtTs(ts: number): string { return ts > 0 ? new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }) : '—'; }

function setStatus(s: string) {
  status.value = status.value === s ? undefined : s;
  void loadAlerts();
}

function query(): string {
  const p = new URLSearchParams();
  if (status.value) p.set('status', status.value);
  if (category.value) p.set('category', category.value);
  if (range.value?.[0]) p.set('from', range.value[0]);
  if (range.value?.[1]) p.set('to', range.value[1]);
  const s = p.toString();
  return s ? `?${s}` : '';
}

/** 当前筛选下库里的总行数与是否被截断（后端下发；旧后端缺席 → undefined）。 */
const listTotal = ref<number | undefined>(undefined);
const listTruncated = ref(false);

async function loadAlerts() {
  try {
    const r = await api<AlertsResp>(`/alerts${query()}`);
    alerts.value = r.alerts ?? [];
    counts.value = r.counts ?? { pending: 0, ignored: 0, handled: 0 };
    // 旧后端不下发这两格 → undefined → 页脚退回「当前列表 N 条」的老说法，
    // 而不是画一个算不出来的 0（那会把"不知道有没有截断"说成"没有截断"）。
    listTotal.value = r.total;
    listTruncated.value = r.truncated === true;
    live.value = true;
    err.value = '';
  } catch (e) {
    live.value = false;
    // 空着比编一页假告警诚实：这一页的存在意义就是"有没有异常"，编不得。
    alerts.value = [];
    counts.value = { pending: 0, ignored: 0, handled: 0 };
    listTotal.value = undefined;
    listTruncated.value = false;
    err.value = `读取告警失败（${failReason(e)}）：本页不提供演示数据，未连接控制中心时一律显示为空。`;
  }
}

async function loadRules() {
  try {
    const r = await api<AlertRulesResp>('/alerts/rules');
    rules.value = r.rules ?? [];
    kinds.value = r.kinds ?? [];
    sources.value = r.sources ?? [];
    notify.value = r.notify ?? null;
    if (r.cooldown) cooldown.value = r.cooldown;
  } catch {
    rules.value = [];
    kinds.value = [];
    sources.value = [];
    notify.value = null;
  }
}

async function loadAll() { await Promise.all([loadAlerts(), loadRules()]); }

async function decide(a: Alert, action: 'handle' | 'ignore') {
  busy.value = true;
  try {
    await api(`/alerts/${a.id}/${action}`, { method: 'POST' });
    Message.success(action === 'handle' ? '已标记为已处理' : '已忽略该告警');
    await loadAlerts();
    void refreshBadges(); // 侧栏未处理角标立刻跟上，不用等下次轮询
  } catch (e) {
    if (failStatus(e) === 409) Message.error('该告警已被处置，请刷新');
    else if (failStatus(e) === 403) Message.error(failReason(e));
    else Message.error('处置失败，请检查后端连接');
  } finally {
    busy.value = false;
  }
}

async function saveRule(r: AlertRule, patch: Partial<AlertRule>) {
  const body = { ...r, ...patch };
  try {
    await api('/alerts/rules', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    Message.success(`规则「${body.name}」已保存`);
    await loadRules();
  } catch (e) {
    // ★必须转述后端原话：api() 抛的是后端中文原文（不以状态码开头，别去匹配 '403'），
    //   而失败多半是「点名了不存在的通道」这类校验拒绝，与后端连接无关。
    Message.error(`规则保存失败：${failReason(e)}`);
    await loadRules(); // 回读，避免界面上留着一个其实没保存成功的值
  }
}
function saveEnabled(r: AlertRule, enabled: boolean) { void saveRule(r, { enabled }); }
function saveCooldown(r: AlertRule, sec: number) { void saveRule(r, { cooldownSec: sec }); }
/** 点名通知通道。留空 = 发给全部启用中的通道（与后端 notifyAlert 的语义逐字一致）。 */
function saveChannels(r: AlertRule, ids: string[]) { void saveRule(r, { channels: ids }); }
function saveThreshold(r: AlertRule, key: string, v: number) {
  void saveRule(r, { threshold: { ...r.threshold, [key]: v } });
}

async function evaluateNow() {
  busy.value = true;
  try {
    const r = await api<{ created: Alert[] }>('/alerts/evaluate', { method: 'POST' });
    const n = r.created?.length ?? 0;
    // 措辞只说已发生的事实：被冷却掉的不算"新增"。
    Message.success(n > 0 ? `检测完成，新增 ${n} 条告警` : '检测完成，没有新增告警（冷却期内的重复条件不会重复产生）');
    await loadAll();
    void refreshBadges();
  } catch (e) {
    Message.error(`立即检测失败：${failReason(e)}`);
  } finally {
    busy.value = false;
  }
}

onMounted(loadAll);
</script>

<style scoped>
.bd-head__right { margin-left: auto; display: flex; align-items: center; gap: 12px; }

.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { display: flex; align-items: center; gap: 7px; font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }
.bd-tab em { font-style: normal; font-size: 11px; color: var(--bd-t3); }
.bd-badge { min-width: 16px; height: 16px; padding: 0 5px; border-radius: 8px; background: var(--bd-danger); color: #fff; font-size: 11px; font-weight: 600; display: inline-flex; align-items: center; justify-content: center; line-height: 1; }

.bd-stats { display: flex; gap: 12px; margin-bottom: 14px; }
.bd-stat { min-width: 108px; padding: 12px 16px; border-radius: 10px; background: var(--bd-fill-1); cursor: pointer; border: 1px solid transparent; }
.bd-stat:hover { background: var(--bd-fill-2); }
.bd-stat.on { border-color: var(--bd-primary-b); background: var(--bd-primary-1); }
.bd-stat__n { display: block; font-size: 22px; font-weight: 700; color: var(--bd-t1); line-height: 1.2; }
.bd-stat__l { font-size: 12px; color: var(--bd-t3); }
.bd-stat--note { display: flex; align-items: center; font-size: 12px; color: var(--bd-t3); background: transparent; cursor: default; }
.bd-stat--note:hover { background: transparent; }

.bd-filters { display: flex; gap: 10px; align-items: center; }
.bd-toolbar__c--warn { color: var(--bd-warning); font-weight: 500; }
.bd-toolbar__c { margin-left: auto; font-size: 12px; color: var(--bd-t3); }

.bd-al__t { font-size: 13.5px; font-weight: 600; color: var(--bd-t1); }
.bd-al__d { font-size: 12px; color: var(--bd-t2); margin-top: 3px; line-height: 1.55; }
.bd-al__o { font-size: 11px; color: var(--bd-t3); margin-top: 3px; }
.bd-al__by { font-size: 11px; color: var(--bd-t3); margin-top: 4px; }

.bd-th { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 12px; color: var(--bd-t2); margin-bottom: 4px; }

.bd-pill { display: inline-flex; align-items: center; padding: 2px 9px; border-radius: 10px; font-size: 11.5px; font-weight: 500; }
.bd-pill.sev-critical { color: var(--bd-danger); background: color-mix(in srgb, var(--bd-danger) 12%, #fff); }
.bd-pill.sev-warning { color: var(--bd-warning); background: color-mix(in srgb, var(--bd-warning) 12%, #fff); }
.bd-pill.sev-info { color: var(--bd-primary); background: var(--bd-primary-1); }
.bd-pill.st-pending { color: var(--bd-warning); background: color-mix(in srgb, var(--bd-warning) 12%, #fff); }
.bd-pill.st-handled { color: var(--bd-success); background: color-mix(in srgb, var(--bd-success) 12%, #fff); }
.bd-pill.st-ignored { color: var(--bd-t3); background: var(--bd-fill-2); }

.bd-sep__note--warn { color: var(--bd-warning); }
</style>
