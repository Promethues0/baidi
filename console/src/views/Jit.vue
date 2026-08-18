<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">JIT 即时访问</div>
        <div class="bd-page__sub">高敏资源自助申请 · 管理员审批 · 时限授予到期自动回收</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <button class="bd-btn bd-btn--ghost" @click="load"><icon-refresh />刷新</button>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'approval' }" @click="tab = 'approval'">
        待审批申请
        <span v-if="pendingCount" class="bd-badge">{{ pendingCount }}</span>
      </span>
      <span class="bd-tab" :class="{ on: tab === 'grants' }" @click="tab = 'grants'">授予台账 <em>{{ grants.length }}</em></span>
    </div>

    <!-- ============ 待审批申请（双栏 + 时间线）============ -->
    <div v-show="tab === 'approval'" class="bd-two">
      <!-- 左：待审批列表 -->
      <div class="bd-card bd-aplist">
        <div class="bd-aplist__h">待审批申请 <em>{{ pending.length }}</em></div>
        <div v-if="!pending.length" class="bd-empty">
          <icon-check-circle-fill />当前没有待处理的访问申请
        </div>
        <button v-for="a in pending" :key="a.id" class="bd-apitem" :class="{ on: a.id === selId }" @click="selId = a.id">
          <div class="bd-apitem__row">
            <span class="bd-apitem__user">{{ a.user }}</span>
            <span class="bd-apitem__time">{{ a.submittedAt }}</span>
          </div>
          <div class="bd-apitem__dev">申请「{{ a.resourceName }}」· {{ a.ttlMinutes }} 分钟</div>
          <div class="bd-apitem__risk"><icon-clock-circle />待审批</div>
        </button>
      </div>

      <!-- 右：详情 + 时间线 -->
      <div class="bd-card bd-apdetail">
        <template v-if="cur">
          <div class="bd-apd__head">
            <div>
              <div class="bd-apd__dev">{{ cur.resourceName }}</div>
              <div class="bd-apd__fp bd-mono">resource: {{ cur.resourceId }}</div>
            </div>
            <span class="bd-tg" :style="tagStyle('var(--bd-warning)')">待审批</span>
          </div>

          <div class="bd-apd__meta">
            <div class="bd-kv"><span>申请人</span><b>{{ cur.user }}</b></div>
            <div class="bd-kv"><span>提交时间</span><b class="bd-mono">{{ cur.submittedAt }}</b></div>
            <div class="bd-kv"><span>期望时长</span><b>{{ cur.ttlMinutes }} 分钟</b></div>
            <div class="bd-kv"><span>申请理由</span><b>{{ cur.reason }}</b></div>
          </div>

          <div class="bd-apd__sec">申请时间线</div>
          <a-timeline class="bd-tl">
            <a-timeline-item
              v-for="(e, i) in cur.timeline"
              :key="i"
              :dot-color="dotColor(e.kind)"
              :line-type="i === cur.timeline.length - 1 ? 'dotted' : 'solid'"
            >
              <div class="bd-tl__row">
                <span class="bd-tl__title">{{ e.title }}</span>
                <span class="bd-tl__time bd-mono">{{ e.time }}</span>
              </div>
              <div class="bd-tl__detail">{{ e.detail }}</div>
            </a-timeline-item>
          </a-timeline>

          <div class="bd-apd__grant">
            <label>授予时长（分钟，可覆盖申请值）</label>
            <a-input-number v-model="grantTtl" :min="15" :max="480" :step="15" style="width: 150px" />
          </div>
          <div class="bd-apd__acts">
            <button class="bd-btn" :disabled="busy" @click="approve"><icon-check />批准并授予</button>
            <button class="bd-btn bd-btn--ghost bd-btn--danger" :disabled="busy" @click="rejectOpen = true"><icon-close />驳回</button>
          </div>
        </template>
        <div v-else class="bd-empty bd-empty--lg">
          <icon-info-circle />请从左侧选择一条待审批申请查看详情
        </div>
      </div>
    </div>

    <!-- ============ 授予台账 ============ -->
    <div v-show="tab === 'grants'" class="bd-tablecard">
      <div class="bd-toolbar">
        <!-- ★截断必须可见：清单只读前 limit 条，不说的话第 limit+1 条之后的授予
             在这一页上根本不存在，而访问审查恰恰是要看「有没有我不知道的授予」。 -->
        <span class="bd-toolbar__c">
          共 {{ grantTotal }} 条授予 · 有效 {{ activeCount }}
          <b v-if="grantTruncated" class="bd-trunc">（本页只显示最近 {{ grants.length }} 条，
            其余 {{ grantTotal - grants.length }} 条未加载——请用 API 或收窄时间范围查看）</b>
        </span>
      </div>
      <table class="bd-table">
        <thead>
          <tr><th>被授予人</th><th>资源</th><th>授予时间</th><th>到期</th><th>状态</th><th class="r">操作</th></tr>
        </thead>
        <tbody>
          <tr v-if="!grants.length"><td colspan="6" class="bd-tcenter">暂无授予记录</td></tr>
          <tr v-for="g in grants" :key="g.id">
            <td><b>{{ g.user }}</b></td>
            <td>{{ g.resourceName }}</td>
            <td class="bd-mono">{{ fmtTs(g.grantedAt) }}</td>
            <td class="bd-mono">
              {{ fmtTs(g.expiresAt) }}
              <span v-if="g.status === 'active'" class="bd-remain" :class="{ soon: remainSec(g.expiresAt) < 300 }">剩 {{ remainText(g.expiresAt) }}</span>
            </td>
            <td><span class="bd-pill" :class="'s-' + effStatus(g)">{{ statusZh[effStatus(g)] }}</span></td>
            <td class="r">
              <span v-if="effStatus(g) === 'active'" class="bd-link bd-link--danger" @click="revoke(g)">撤销</span>
              <span v-else class="bd-link bd-link--grey">—</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 驳回理由 -->
    <a-modal v-model:visible="rejectOpen" title="驳回访问申请" :width="460" @ok="reject" ok-text="确认驳回" cancel-text="取消">
      <div class="bd-reject">
        <icon-exclamation-circle-fill class="bd-reject__ic" />
        <div>将驳回 <b>{{ cur?.user }}</b> 对 <b>「{{ cur?.resourceName }}」</b> 的访问申请，请填写驳回理由（将通知申请人）。</div>
      </div>
      <a-textarea v-model="rejectReason" placeholder="例如：该资源本季度冻结访问，请走线下审批" :max-length="200" allow-clear :auto-size="{ minRows: 3, maxRows: 5 }" />
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type AccessRequestsResp, type JitGrantsResp, type AccessRequest, type JitGrant } from '@/lib/api';

const tab = ref<'approval' | 'grants'>('approval');
const live = ref(false);
const busy = ref(false);
const rejectOpen = ref(false);
const rejectReason = ref('');
const grantTtl = ref(60);
const nowSec = ref(Math.floor(Date.now() / 1000));
let timer: number | undefined;

/* 无后端降级演示数据 */
const now0 = Math.floor(Date.now() / 1000);
const MOCK_REQUESTS: AccessRequest[] = [
  {
    id: 'areq-demo1', user: 'li.fang', resourceId: 'finance', resourceName: '财务核算系统',
    reason: '季度对账，需临时访问财务核算系统查阅凭证', ttlMinutes: 120, status: 'pending',
    submittedAt: '2026-07-23 10:02', decidedAt: '', decideReason: '', decidedBy: '', grantId: '',
    timeline: [
      { time: '2026-07-23 10:02', kind: 'submit', title: '提交访问申请', detail: 'li.fang 申请访问「财务核算系统」，理由：季度对账' },
      { time: '2026-07-23 10:02', kind: 'review', title: '等待管理员审批', detail: '进入 JIT 访问审批队列（当前）' }
    ]
  },
  {
    id: 'areq-demo2', user: 'ext.zhou', resourceId: 'git', resourceName: '研发 Git 仓库',
    reason: '外包联调，需临时拉取代码', ttlMinutes: 60, status: 'pending',
    submittedAt: '2026-07-23 09:40', decidedAt: '', decideReason: '', decidedBy: '', grantId: '',
    timeline: [
      { time: '2026-07-23 09:40', kind: 'submit', title: '提交访问申请', detail: 'ext.zhou 申请访问「研发 Git 仓库」' },
      { time: '2026-07-23 09:40', kind: 'review', title: '等待管理员审批', detail: '外包账号，建议限时授予' }
    ]
  }
];
const MOCK_GRANTS: JitGrant[] = [
  { id: 'grant-demo1', user: 'zhang.wei', resourceId: 'finance', resourceName: '财务核算系统', requestId: 'areq-x', reason: '月末结账', grantedBy: 'admin', grantedAt: now0 - 1200, expiresAt: now0 + 4800, status: 'active', revokedAt: 0, revokeReason: '' },
  { id: 'grant-demo2', user: 'li.fang', resourceId: 'git', resourceName: '研发 Git 仓库', requestId: 'areq-y', reason: '紧急修复', grantedBy: 'admin', grantedAt: now0 - 90000, expiresAt: now0 - 3600, status: 'expired', revokedAt: 0, revokeReason: '' }
];

const requests = ref<AccessRequest[]>([]);
const grants = ref<JitGrant[]>([]);
const selId = ref('');

const statusZh: Record<string, string> = { active: '有效', expired: '已到期', revoked: '已撤销', pending: '待审批', approved: '已批准', rejected: '已驳回' };
const pending = computed(() => requests.value.filter(r => r.status === 'pending'));
const pendingCount = computed(() => pending.value.length);
const cur = computed(() => pending.value.find(a => a.id === selId.value) ?? null);
const activeCount = computed(() => grants.value.filter(g => effStatus(g) === 'active').length);

function effStatus(g: JitGrant): string {
  if (g.status === 'active' && g.expiresAt <= nowSec.value) return 'expired';
  return g.status;
}
function tagStyle(color: string) { return { color, background: `color-mix(in srgb, ${color} 12%, #fff)` }; }
type EventKind = AccessRequest['timeline'][number]['kind'];
function dotColor(kind: EventKind): string {
  return { submit: '#165DFF', risk: '#FF7D00', login: '#C9CDD4', review: '#165DFF', notify: '#00B42A' }[kind];
}
function fmtTs(ts: number): string { return ts > 0 ? new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }) : '—'; }
function remainSec(exp: number): number { return Math.max(0, exp - nowSec.value); }
function remainText(exp: number): string {
  const s = remainSec(exp);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h}h${m}m`;
  if (m > 0) return `${m}m`;
  return `${s}s`;
}

// 选中申请时把授予时长默认置为申请值
function syncGrantTtl() { grantTtl.value = cur.value?.ttlMinutes || 60; }

async function decide(decision: 'approved' | 'rejected', reason: string) {
  const a = cur.value;
  if (!a) return;
  if (!live.value) {
    // 降级演示：不落库，本地摘除该申请，提示演示态
    requests.value = requests.value.filter(r => r.id !== a.id);
    selId.value = pending.value[0]?.id ?? '';
    Message.warning(`演示态：已${decision === 'approved' ? '批准' : '驳回'}（未连后端，不落库）`);
    return;
  }
  busy.value = true;
  try {
    await api(`/access-requests/${a.id}/decide`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, reason, ttlMinutes: decision === 'approved' ? grantTtl.value : 0 })
    });
    if (decision === 'approved') Message.success(`已批准 ${a.user} 访问「${a.resourceName}」，授予 ${grantTtl.value} 分钟（已落库）`);
    else Message.warning(`已驳回 ${a.user} 的访问申请${reason ? `：${reason}` : ''}（已落库）`);
    await load();
  } catch (e) {
    const msg = String((e as Error)?.message ?? '');
    if (msg.startsWith('409')) Message.error('该申请已被处置，请刷新');
    else if (msg.startsWith('403')) Message.error('不能审批自己提交的申请');
    else Message.error('处置失败，请检查后端连接');
  } finally {
    busy.value = false;
  }
}
function approve() { decide('approved', ''); }
function reject() {
  rejectOpen.value = false;
  const r = rejectReason.value;
  rejectReason.value = '';
  decide('rejected', r);
}

async function revoke(g: JitGrant) {
  if (!live.value) {
    grants.value = grants.value.map(x => x.id === g.id ? { ...x, status: 'revoked' as const } : x);
    Message.warning('演示态：已撤销（未连后端，不落库）');
    return;
  }
  try {
    await api(`/jit/grants/${g.id}/revoke`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: '管理员在授予台账主动撤销' })
    });
    Message.success(`已撤销 ${g.user} 对「${g.resourceName}」的授予`);
    await load();
  } catch (e) {
    const msg = String((e as Error)?.message ?? '');
    Message.error(msg.startsWith('409') ? '授予不存在或已失效' : '撤销失败，请检查后端连接');
  }
}

/** 库里的授予总数与「本页是否被截断」（后端 /jit/grants 下发）。 */
const grantTotal = ref(0);
const grantTruncated = ref(false);

async function load() {
  try {
    const [rq, gr] = await Promise.all([
      api<AccessRequestsResp>('/access-requests'),
      api<JitGrantsResp>('/jit/grants')
    ]);
    requests.value = rq.requests ?? [];
    grants.value = gr.grants ?? [];
    grantTotal.value = gr.total ?? (gr.grants?.length ?? 0);
    grantTruncated.value = !!gr.truncated;
    selId.value = pending.value[0]?.id ?? '';
    syncGrantTtl();
    live.value = true;
  } catch {
    requests.value = MOCK_REQUESTS;
    grants.value = MOCK_GRANTS;
    grantTotal.value = MOCK_GRANTS.length;
    grantTruncated.value = false;
    selId.value = MOCK_REQUESTS[0]?.id ?? '';
    syncGrantTtl();
    live.value = false;
  }
}

onMounted(() => {
  load();
  timer = window.setInterval(() => { nowSec.value = Math.floor(Date.now() / 1000); }, 1000);
});
onUnmounted(() => { if (timer) window.clearInterval(timer); });
</script>

<style scoped>
.bd-trunc { color: var(--bd-warning); font-weight: 500; }
.bd-head__right { margin-left: auto; display: flex; align-items: center; gap: 12px; }

/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { display: flex; align-items: center; gap: 7px; font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }
.bd-tab em { font-style: normal; font-size: 11px; color: var(--bd-t3); }
.bd-tab.on em { color: var(--bd-primary); }
.bd-badge { min-width: 16px; height: 16px; padding: 0 5px; border-radius: 8px; background: var(--bd-danger); color: #fff; font-size: 11px; font-weight: 600; display: inline-flex; align-items: center; justify-content: center; line-height: 1; }

/* 审批两栏 */
.bd-two { display: flex; gap: 16px; align-items: flex-start; }
.bd-aplist { width: 300px; flex: none; padding: 10px; }
.bd-aplist__h { font-size: 12px; font-weight: 600; color: var(--bd-t3); padding: 4px 8px 10px; }
.bd-aplist__h em { font-style: normal; margin-left: 4px; }
.bd-apitem { width: 100%; display: block; text-align: left; border: 1px solid transparent; background: transparent; border-radius: 8px; cursor: pointer; padding: 11px 12px; margin-bottom: 4px; transition: background .12s, border-color .12s; }
.bd-apitem:hover { background: var(--bd-fill-1); }
.bd-apitem.on { background: var(--bd-primary-1); border-color: var(--bd-primary-b); }
.bd-apitem__row { display: flex; align-items: center; justify-content: space-between; }
.bd-apitem__user { font-size: 13.5px; font-weight: 600; color: var(--bd-t1); }
.bd-apitem.on .bd-apitem__user { color: var(--bd-primary); }
.bd-apitem__time { font-size: 11px; color: var(--bd-t3); font-family: ui-monospace, monospace; }
.bd-apitem__dev { font-size: 12px; color: var(--bd-t2); margin-top: 4px; }
.bd-apitem__risk { display: flex; align-items: center; gap: 5px; font-size: 11.5px; color: var(--bd-warning); margin-top: 7px; }

.bd-apdetail { flex: 1; min-width: 0; padding: 20px 22px 22px; }
.bd-apd__head { display: flex; align-items: flex-start; justify-content: space-between; padding-bottom: 16px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-apd__dev { font-size: 16px; font-weight: 700; color: var(--bd-t1); }
.bd-apd__fp { font-size: 12px; color: var(--bd-t3); margin-top: 4px; }
.bd-apd__meta { padding: 6px 0 4px; }
.bd-kv { display: flex; align-items: center; justify-content: space-between; padding: 9px 0; border-bottom: 1px solid var(--bd-fill-1); font-size: 13px; }
.bd-kv span { color: var(--bd-t3); }
.bd-kv b { font-weight: 500; color: var(--bd-t1); }
.bd-apd__sec { font-size: 13px; font-weight: 600; margin: 20px 0 14px; }

.bd-tl { padding-left: 2px; }
.bd-tl__row { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
.bd-tl__title { font-size: 13px; font-weight: 600; color: var(--bd-t1); }
.bd-tl__time { font-size: 11.5px; color: var(--bd-t3); flex: none; }
.bd-tl__detail { font-size: 12px; color: var(--bd-t3); line-height: 1.6; margin-top: 3px; }

.bd-apd__grant { margin-top: 22px; }
.bd-apd__grant label { display: block; font-size: 12.5px; font-weight: 500; color: var(--bd-t2); margin-bottom: 8px; }
.bd-apd__acts { display: flex; gap: 10px; margin-top: 18px; }

/* 空态 */
.bd-empty { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--bd-t3); padding: 16px 12px; }
.bd-empty :deep(svg) { color: var(--bd-success); }
.bd-empty--lg { justify-content: center; min-height: 280px; flex-direction: column; gap: 12px; color: var(--bd-t4); }
.bd-empty--lg :deep(svg) { font-size: 28px; color: var(--bd-t4); }

/* 授予台账 */
.bd-toolbar__c { font-size: 12.5px; color: var(--bd-t3); }
.bd-tcenter { text-align: center; color: var(--bd-t3); padding: 28px 0; }
.bd-pill { display: inline-block; font-size: 11.5px; font-weight: 600; padding: 3px 10px; border-radius: 6px; }
.bd-pill.s-active { color: var(--bd-success); background: var(--bd-tag-green-bg); }
.bd-pill.s-expired { color: var(--bd-t3); background: var(--bd-fill-2); }
.bd-pill.s-revoked { color: var(--bd-danger); background: color-mix(in srgb, var(--bd-danger) 12%, #fff); }
.bd-remain { margin-left: 8px; font-size: 11px; color: var(--bd-success); }
.bd-remain.soon { color: var(--bd-warning); }
.bd-link--danger { color: var(--bd-danger); cursor: pointer; }
.bd-link--grey { color: var(--bd-t4); }

/* 驳回 modal */
.bd-reject { display: flex; gap: 12px; font-size: 13.5px; line-height: 1.7; color: var(--bd-t2); margin-bottom: 14px; }
.bd-reject__ic { color: var(--bd-danger); font-size: 20px; flex: none; margin-top: 2px; }
</style>
