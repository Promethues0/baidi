<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">资源权限申请与审批<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">自助申请 → 安全管理员审批 → 自动限时授权（到期前 3 天提醒）</div>
      </div>
      <a-button v-if="tab === 'mine'" type="primary" @click="openSubmit"><template #icon><icon-plus /></template>发起申请</a-button>
    </div>

    <!-- 顶部说明条 -->
    <div class="ra-tip">
      <span class="ra-tip__ic">ⓘ</span>
      <span>申请 / 撤回为用户自助操作；<b>通过 / 驳回需安全管理员令牌</b>。审批通过后自动生成<b>限时授权</b>（按申请时效），到期自动失效、到期前 3 天提醒续期。</span>
    </div>

    <a-tabs v-model:active-key="tab" type="rounded">
      <!-- Tab1：待审批（安全管理员视角） -->
      <a-tab-pane key="pending" :title="`待审批 (${pending.length})`">
        <!-- 审批身份：通过/驳回为受控操作，需安全管理员显式验证身份换取令牌（不硬编码口令） -->
        <div class="zl-card zl-card__pad ra-auth">
          <span v-if="secVerified" class="zl-badge zl-badge--ok">✓ 已验证安全管理员身份</span>
          <template v-else>
            <span class="ra-auth__label">审批身份</span>
            <a-input v-model="secAuth.account" size="small" style="width:140px" placeholder="安全管理员账号" />
            <a-input-password v-model="secAuth.password" size="small" style="width:160px" placeholder="口令" @press-enter="verifySecAdmin" />
            <a-button size="small" type="primary" @click="verifySecAdmin">验证身份</a-button>
            <span class="ra-auth__hint">审批需安全管理员令牌（演示账号 secadmin）</span>
          </template>
        </div>
        <div class="zl-card">
          <a-table :data="pending" :pagination="pending.length>12?{pageSize:12}:false" :bordered="false" row-key="key">
            <template #columns>
              <a-table-column title="申请人" data-index="applicant" :width="140">
                <template #cell="{ record }">
                  <span class="data" style="font-weight:600;color:var(--ink)">{{ record.applicant }}</span>
                  <div style="font-size:11px;color:var(--ink-3);margin-top:2px">{{ typeLabel(record.type) }}</div>
                </template>
              </a-table-column>
              <a-table-column title="申请资源" data-index="resource" :width="180">
                <template #cell="{ record }"><span class="data" style="color:var(--ink-2)">{{ record.resource }}</span></template>
              </a-table-column>
              <a-table-column title="申请事由">
                <template #cell="{ record }"><span style="font-size:12.5px;color:var(--ink-2)">{{ record.reason || '—' }}</span></template>
              </a-table-column>
              <a-table-column title="时效" align="center" :width="92">
                <template #cell="{ record }"><span class="data" style="font-weight:650;color:var(--accent-2)">{{ record.durationDays }} 天</span></template>
              </a-table-column>
              <a-table-column title="提交时间" :width="150">
                <template #cell="{ record }"><span class="data" style="font-size:11.5px;color:var(--ink-3)">{{ record.createdAt }}</span></template>
              </a-table-column>
              <a-table-column title="" align="center" :width="150">
                <template #cell="{ record }">
                  <a-space>
                    <a-button size="mini" type="primary" @click="approve(record)">通过</a-button>
                    <a-button size="mini" status="danger" @click="openReject(record)">驳回</a-button>
                  </a-space>
                </template>
              </a-table-column>
            </template>
            <template #empty>
              <div class="ra-empty">
                <div class="ra-empty__big">暂无待审批申请</div>
                <div class="ra-empty__sub">所有资源权限申请均已处置完毕。新申请提交后将实时出现在此列表，等待安全管理员审批。</div>
              </div>
            </template>
          </a-table>
        </div>
      </a-tab-pane>

      <!-- Tab2：我的申请（申请人视角） -->
      <a-tab-pane key="mine" :title="`我的申请 (${mine.length})`">
        <div class="zl-card">
          <a-table :data="mine" :pagination="mine.length>12?{pageSize:12}:false" :bordered="false" row-key="key">
            <template #columns>
              <a-table-column title="申请资源" data-index="resource" :width="180">
                <template #cell="{ record }">
                  <span class="data" style="font-weight:600;color:var(--ink)">{{ record.resource }}</span>
                  <div style="font-size:11px;color:var(--ink-3);margin-top:2px">{{ typeLabel(record.type) }} · {{ record.durationDays }} 天</div>
                </template>
              </a-table-column>
              <a-table-column title="申请事由">
                <template #cell="{ record }"><span style="font-size:12.5px;color:var(--ink-2)">{{ record.reason || '—' }}</span></template>
              </a-table-column>
              <a-table-column title="提交时间" :width="150">
                <template #cell="{ record }"><span class="data" style="font-size:11.5px;color:var(--ink-3)">{{ record.createdAt }}</span></template>
              </a-table-column>
              <a-table-column title="状态" align="center" :width="100">
                <template #cell="{ record }"><span class="zl-badge" :class="statusClass(record.status)">{{ record.status }}</span></template>
              </a-table-column>
              <a-table-column title="审批意见" :width="200">
                <template #cell="{ record }">
                  <span v-if="record.comment" style="font-size:12px;color:var(--ink-2)">{{ record.comment }}</span>
                  <span v-else style="color:var(--ink-3)">—</span>
                </template>
              </a-table-column>
              <a-table-column title="" align="center" :width="92">
                <template #cell="{ record }">
                  <a-button v-if="record.status === '审批中'" size="mini" status="warning" @click="withdraw(record)">撤回</a-button>
                  <span v-else style="color:var(--ink-3)">—</span>
                </template>
              </a-table-column>
            </template>
            <template #empty>
              <div class="ra-empty">
                <div class="ra-empty__big">你还没有提交过申请</div>
                <div class="ra-empty__sub">点击右上「发起申请」，选择资源对象、填写事由与时效后提交。审批通过即自动生成限时授权。</div>
              </div>
            </template>
          </a-table>
        </div>
      </a-tab-pane>
    </a-tabs>

    <!-- 发起申请 modal -->
    <a-modal v-model:visible="submitShow" title="发起资源权限申请" width="520px" @ok="doSubmit" ok-text="提交申请">
      <a-form :model="sForm" layout="vertical">
        <a-form-item label="申请资源" required>
          <a-select v-model="sForm.resource" placeholder="选择资源对象" allow-search>
            <a-option v-for="r in resourceOpts" :key="r" :value="r">{{ r }}</a-option>
          </a-select>
        </a-form-item>
        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="申请类型（type）">
              <a-select v-model="sForm.type">
                <a-option value="new">new 新授权</a-option>
                <a-option value="renew">renew 续期</a-option>
              </a-select>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="授权时效（durationDays）">
              <a-input-number v-model="sForm.durationDays" :min="1" :max="365" :style="{width:'100%'}">
                <template #suffix>天</template>
              </a-input-number>
            </a-form-item>
          </a-grid-item>
        </a-grid>
        <a-form-item label="申请事由（reason）" required>
          <a-textarea v-model="sForm.reason" placeholder="说明本次申请的业务用途，便于安全管理员审批" :auto-size="{ minRows: 3, maxRows: 5 }" />
        </a-form-item>
      </a-form>
      <div class="ra-modal-note">提示：提交即进入「审批中」，安全管理员通过后自动生成按此时效的限时授权；审批中可随时撤回。提交免令牌。</div>
    </a-modal>

    <!-- 驳回 modal（填意见） -->
    <a-modal v-model:visible="rejectShow" title="驳回申请" width="480px" @ok="doReject" ok-text="确认驳回" :ok-button-props="{ status: 'danger' }">
      <div v-if="rejectTarget" class="ra-reject-head">
        <div><b>{{ rejectTarget.applicant }}</b> 申请 <b class="data">{{ rejectTarget.resource }}</b></div>
        <div style="font-size:12px;color:var(--ink-3);margin-top:4px">事由：{{ rejectTarget.reason || '—' }}</div>
      </div>
      <a-form :model="rejectForm" layout="vertical" style="margin-top:14px">
        <a-form-item label="驳回意见（comment）" required>
          <a-textarea v-model="rejectForm.comment" placeholder="说明驳回原因，将反馈给申请人" :auto-size="{ minRows: 3, maxRows: 5 }" />
        </a-form-item>
      </a-form>
      <div class="ra-modal-note">驳回需安全管理员令牌。提交后申请状态置为「已驳回」，意见回显给申请人。</div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

/* —— 类型 —— */
// 申请单（kind=appreq，每条一文档）。status：审批中 / 已通过 / 已驳回 / 已撤回。
interface AppReq {
  key: string;
  applicant: string;
  type: 'new' | 'renew';
  resource: string;
  reason: string;
  durationDays: number;
  status: '审批中' | '已通过' | '已驳回' | '已撤回';
  comment: string;
  createdAt: string;
}

/* —— 当前申请人（演示用固定；真实环境取当前登录用户） —— */
const ME = 'zhang.wei';

/* —— 中文化 —— */
const typeLabel = (t: string) => (t === 'renew' ? '续期 renew' : '新授权 new');
const statusClass = (s: string) =>
  s === '已通过' ? 'zl-badge--ok' : s === '审批中' ? 'zl-badge--warn' : s === '已驳回' ? 'zl-badge--danger' : 'zl-badge--idle';

/* —— 前端默认（mock，加载后端后覆盖） —— */
const fallback: AppReq[] = [
  { key: 'req-1001', applicant: 'li.qiang', type: 'new', resource: '核心数据库 db.corp:5432', reason: '数据迁移项目需读写权限，工期约一个月', durationDays: 30, status: '审批中', comment: '', createdAt: '2026-06-14 09:21' },
  { key: 'req-1002', applicant: 'wang.fang', type: 'new', resource: '财务系统 finance', reason: '季度对账临时取数', durationDays: 7, status: '审批中', comment: '', createdAt: '2026-06-14 14:05' },
  { key: 'req-1003', applicant: 'zhang.wei', type: 'new', resource: '代码仓库 gitlab', reason: '加入新研发组，需仓库读写权限', durationDays: 90, status: '已通过', comment: '已生成 90 天限时授权', createdAt: '2026-06-10 10:30' },
  { key: 'req-1004', applicant: 'zhang.wei', type: 'renew', resource: '运维跳板机 bastion', reason: '运维值班延续，续期 30 天', durationDays: 30, status: '已驳回', comment: '值班排期已调整，本月无需跳板机权限，请按需重申', createdAt: '2026-06-08 16:48' },
  { key: 'req-1005', applicant: 'zhang.wei', type: 'new', resource: '测试环境 test-env', reason: '联调测试', durationDays: 14, status: '已撤回', comment: '', createdAt: '2026-06-05 11:12' }
];

const rows = ref<AppReq[]>(fallback.map((r) => ({ ...r })));
const live = ref(false);
const tab = ref<'pending' | 'mine'>('pending');

// Tab1：全局审批中；Tab2：当前申请人全部申请。
const pending = computed(() => rows.value.filter((r) => r.status === '审批中'));
const mine = computed(() => rows.value.filter((r) => r.applicant === ME));

/* —— 资源候选：从 GET /ctl/api/resources 取每条 name；失败保留静态兜底 —— */
const resourceOpts = ref<string[]>(['核心数据库 db.corp:5432', '财务系统 finance', '代码仓库 gitlab', '运维跳板机 bastion', '测试环境 test-env', '应用门户 portal']);

/* —— 加载（失败保留前端默认 mock 降级） —— */
async function load() {
  try {
    const r = await fetch('/ctl/api/appreq');
    if (!r.ok) return;
    const docs = await r.json();
    rows.value = (Array.isArray(docs) ? docs : []).map((d: any) => ({
      key: d.key ?? d.k,
      applicant: d.applicant ?? '',
      type: d.type === 'renew' ? 'renew' : 'new',
      resource: d.resource ?? '',
      reason: d.reason ?? '',
      durationDays: typeof d.durationDays === 'number' ? d.durationDays : 30,
      status: ['审批中', '已通过', '已驳回', '已撤回'].includes(d.status) ? d.status : '审批中',
      comment: d.comment ?? '',
      createdAt: d.createdAt ?? ''
    }));
    live.value = true;
  } catch { live.value = false; }
}
async function loadResourceOpts() {
  try {
    const r = await fetch('/ctl/api/resources');
    if (!r.ok) return;
    const docs = await r.json();
    // 只列开放自助申请的资源（Resource.allowSelfRequest）——与控制面 resourceSelfRequestable 门一致
    const opts = (Array.isArray(docs) ? docs : []).filter((d: any) => d.allowSelfRequest).map((d: any) => d.name).filter(Boolean);
    if (opts.length) resourceOpts.value = opts;
  } catch { /* 保留静态兜底 */ }
}
onMounted(() => { load(); loadResourceOpts(); });

/* —— 安全管理员身份：审批为受控操作，需安全管理员显式验证身份换取令牌（不在前端硬编码口令）。
   approver 在「审批身份」栏输入自己的安全管理员账号/口令验证一次，令牌缓存于本次会话供后续审批。 */
const secAuth = reactive({ account: 'secadmin', password: '' });
const secToken = ref('');
const secVerified = computed(() => !!secToken.value);
async function verifySecAdmin() {
  if (!secAuth.password) return Message.warning('请输入安全管理员口令');
  try {
    const r = await fetch('/ctl/auth/login', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ account: secAuth.account, password: secAuth.password })
    });
    if (!r.ok) { secToken.value = ''; return Message.error('身份验证失败'); }
    const d = await r.json();
    secToken.value = d.token ?? '';
    secAuth.password = '';
    secToken.value ? Message.success('安全管理员身份已验证') : Message.error('身份验证失败');
  } catch { Message.error('控制面不可达'); }
}
function fetchSecToken(): string { return secToken.value; }

/* —— 发起申请（免令牌） —— */
const submitShow = ref(false);
const sForm = reactive({ resource: '', type: 'new' as 'new' | 'renew', reason: '', durationDays: 30 });
function openSubmit() {
  Object.assign(sForm, { resource: '', type: 'new', reason: '', durationDays: 30 });
  submitShow.value = true;
}
async function doSubmit() {
  if (!sForm.resource) return Message.warning('请选择申请资源');
  if (!sForm.reason) return Message.warning('请填写申请事由');
  const payload = { applicant: ME, type: sForm.type, resource: sForm.resource, reason: sForm.reason, durationDays: sForm.durationDays };
  if (live.value) {
    try {
      const res = await fetch('/ctl/api/appreq/submit', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload)
      });
      if (!res.ok) return Message.error('提交失败');
    } catch { return Message.error('控制面不可达'); }
    await load();
  } else {
    // mock 降级：本地插入一条审批中。
    rows.value.unshift({
      key: 'req-' + Date.now(), ...payload, status: '审批中', comment: '',
      createdAt: new Date().toISOString().slice(0, 16).replace('T', ' ')
    });
  }
  submitShow.value = false;
  Message.success(`申请已提交「${sForm.resource}」· 等待安全管理员审批${live.value ? ' · 已持久化' : '（mock）'}`);
}

/* —— 通过（需安全管理员令牌） —— */
async function approve(r: AppReq) {
  if (live.value) {
    const token = fetchSecToken();
    if (!token) return Message.error('请先在「审批身份」栏验证安全管理员身份');
    try {
      const res = await fetch(`/ctl/api/appreq/decide?key=${encodeURIComponent(r.key)}&decision=approve`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', Authorization: 'Bearer ' + token },
        body: JSON.stringify({ comment: '' })
      });
      if (res.status === 403) return Message.error('无权限：审批需安全管理员');
      if (res.status === 401) return Message.error('令牌失效');
      if (!res.ok) return Message.error('审批失败');
    } catch { return Message.error('控制面不可达'); }
    await load();
  } else {
    r.status = '已通过';
    r.comment = `已生成 ${r.durationDays} 天限时授权`;
  }
  Message.success(`已通过「${r.applicant}→${r.resource}」· 已生成 ${r.durationDays} 天限时授权（到期前 3 天提醒）${live.value ? ' · 已持久化' : ''}`);
}

/* —— 驳回（需安全管理员令牌，填意见） —— */
const rejectShow = ref(false);
const rejectTarget = ref<AppReq | null>(null);
const rejectForm = reactive({ comment: '' });
function openReject(r: AppReq) {
  rejectTarget.value = r;
  rejectForm.comment = '';
  rejectShow.value = true;
}
async function doReject() {
  const r = rejectTarget.value;
  if (!r) return;
  if (!rejectForm.comment.trim()) return Message.warning('请填写驳回意见');
  if (live.value) {
    const token = fetchSecToken();
    if (!token) return Message.error('请先在「审批身份」栏验证安全管理员身份');
    try {
      const res = await fetch(`/ctl/api/appreq/decide?key=${encodeURIComponent(r.key)}&decision=reject`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', Authorization: 'Bearer ' + token },
        body: JSON.stringify({ comment: rejectForm.comment })
      });
      if (res.status === 403) return Message.error('无权限：审批需安全管理员');
      if (res.status === 401) return Message.error('令牌失效');
      if (!res.ok) return Message.error('驳回失败');
    } catch { return Message.error('控制面不可达'); }
    await load();
  } else {
    r.status = '已驳回';
    r.comment = rejectForm.comment;
  }
  rejectShow.value = false;
  Message.success(`已驳回「${r.applicant}→${r.resource}」${live.value ? ' · 已持久化' : ''}`);
}

/* —— 撤回（免令牌，二次确认） —— */
function withdraw(r: AppReq) {
  Modal.warning({
    title: `撤回申请「${r.resource}」？`, hideCancel: false, okText: '确认撤回', cancelText: '取消',
    content: '撤回后该申请退出审批流，状态置为「已撤回」。如仍需权限，请重新发起申请。此操作进入审计链。',
    onOk: async () => {
      if (live.value) {
        try {
          const res = await fetch(`/ctl/api/appreq/withdraw?key=${encodeURIComponent(r.key)}`, { method: 'POST' });
          if (!res.ok) return Message.error('撤回失败');
        } catch { return Message.error('控制面不可达'); }
        await load();
      } else {
        r.status = '已撤回';
      }
      Message.success(`申请「${r.resource}」已撤回${live.value ? ' · 已持久化' : ''}`);
    }
  });
}
</script>

<style scoped>
:deep(.arco-table-tr) { cursor: default; }

/* 顶部说明条 */
.ra-tip { display: flex; align-items: flex-start; gap: 10px; background: var(--accent-soft); border: 1px solid var(--line); border-radius: var(--r-md); padding: 11px 14px; margin-bottom: 16px; font-size: 12.5px; color: var(--ink-2); line-height: 1.6; }
.ra-auth { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
.ra-auth__label { font-size: 12.5px; font-weight: 650; color: var(--ink-2); }
.ra-auth__hint { font-size: 11px; color: var(--ink-3); }
.ra-tip__ic { color: var(--accent-2); font-weight: 700; flex-shrink: 0; }
.ra-tip b { color: var(--accent-2); font-weight: 700; }

/* 空态 */
.ra-empty { padding: 30px 16px; text-align: center; }
.ra-empty__big { font-size: 14px; font-weight: 650; color: var(--ink-2); }
.ra-empty__sub { font-size: 12px; color: var(--ink-3); margin-top: 8px; line-height: 1.6; max-width: 560px; margin-left: auto; margin-right: auto; }

/* 驳回弹窗头 */
.ra-reject-head { background: var(--accent-soft); border: 1px solid var(--line); border-radius: var(--r-md); padding: 11px 14px; font-size: 13px; color: var(--ink-2); }
.ra-reject-head b { color: var(--ink); font-weight: 650; }

.ra-modal-note { font-size: 11.5px; color: var(--ink-3); line-height: 1.6; margin-top: 4px; }
</style>
