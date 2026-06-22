<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">终端管理</div>
        <div class="bd-page__sub">设备纳管台账 · 硬件指纹绑定 · 风险驱动分级</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <button class="bd-btn bd-btn--ghost" @click="setOpen = true"><icon-settings />信任绑定设置</button>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'list' }" @click="tab = 'list'">设备清单 <em>{{ devices.length }}</em></span>
      <span class="bd-tab" :class="{ on: tab === 'approval' }" @click="tab = 'approval'">
        绑定审批
        <span v-if="pendingCount" class="bd-badge">{{ pendingCount }}</span>
      </span>
    </div>

    <!-- ============ 设备清单 ============ -->
    <div v-show="tab === 'list'" class="bd-tablecard">
      <div class="bd-toolbar">
        <span class="bd-toolbar__c">共 {{ devices.length }} 台终端 · 在线 {{ onlineCount }}</span>
        <div style="flex: 1" />
        <div class="bd-searchbox" style="width: 240px"><icon-search />按设备名 / 指纹 / 归属用户搜索</div>
      </div>
      <table class="bd-table">
        <thead>
          <tr>
            <th>设备</th><th>归属用户</th><th>资产分类</th><th>系统 / 客户端</th><th>在线</th><th class="r">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in devices" :key="d.id">
            <td>
              <div class="bd-cellname">
                <span><b>{{ d.name }}</b><i class="bd-mono">{{ d.fingerprint }}</i></span>
                <span v-for="t in d.tags" :key="t" class="bd-tg bd-tg--grey">{{ t }}</span>
              </div>
            </td>
            <td>{{ d.user }}</td>
            <td><span class="bd-tg" :style="tagStyle(assetMeta(d.assetClass).color)">{{ assetMeta(d.assetClass).label }}</span></td>
            <td>{{ d.os }}<span class="bd-dmono">客户端 {{ d.clientVersion }}</span></td>
            <td>
              <span class="bd-st"><span class="d" :style="{ background: d.online ? 'var(--bd-success)' : 'var(--bd-t4)' }" />{{ d.online ? '在线' : '离线' }}</span>
            </td>
            <td class="r">
              <span class="bd-link" @click="bind(d)">绑定</span>
              <span class="bd-link bd-link--grey" style="margin-left: 14px" @click="bind(d)">详情</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- ============ 绑定审批（P9 时间线）============ -->
    <div v-show="tab === 'approval'" class="bd-two">
      <!-- 左：待审批列表 -->
      <div class="bd-card bd-aplist">
        <div class="bd-aplist__h">待审批申请 <em>{{ approvals.length }}</em></div>
        <div v-if="!approvals.length" class="bd-empty">
          <icon-check-circle-fill />当前没有待处理的绑定申请
        </div>
        <button v-for="a in approvals" :key="a.id" class="bd-apitem" :class="{ on: a.id === selId }" @click="selId = a.id">
          <div class="bd-apitem__row">
            <span class="bd-apitem__user">{{ a.user }}</span>
            <span class="bd-apitem__time">{{ a.submittedAt }}</span>
          </div>
          <div class="bd-apitem__dev">{{ a.device }}</div>
          <div v-if="riskOf(a)" class="bd-apitem__risk"><icon-exclamation-circle-fill />{{ riskOf(a) }}</div>
        </button>
      </div>

      <!-- 右：详情 + 时间线 -->
      <div class="bd-card bd-apdetail">
        <template v-if="cur">
          <div class="bd-apd__head">
            <div>
              <div class="bd-apd__dev">{{ cur.device }}</div>
              <div class="bd-apd__fp bd-mono">{{ cur.fingerprint }}</div>
            </div>
            <span class="bd-tg" :style="tagStyle('var(--bd-warning)')">待审批</span>
          </div>

          <div class="bd-apd__meta">
            <div class="bd-kv"><span>申请人</span><b>{{ cur.user }}</b></div>
            <div class="bd-kv"><span>提交时间</span><b class="bd-mono">{{ cur.submittedAt }}</b></div>
            <div class="bd-kv"><span>申请理由</span><b>{{ cur.reason }}</b></div>
          </div>

          <div class="bd-apd__sec">绑定与风险时间线</div>
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

          <div class="bd-apd__acts">
            <button class="bd-btn" @click="approve"><icon-check />通过绑定</button>
            <button class="bd-btn bd-btn--ghost bd-btn--danger" @click="rejectOpen = true"><icon-close />驳回</button>
          </div>
        </template>
        <div v-else class="bd-empty bd-empty--lg">
          <icon-info-circle />请从左侧选择一条待审批申请查看详情
        </div>
      </div>
    </div>

    <!-- 信任绑定设置 -->
    <a-modal v-model:visible="setOpen" title="信任绑定设置" :width="480" @ok="saveSettings" ok-text="保存" cancel-text="取消">
      <div class="bd-setrow">
        <div class="bd-setrow__main">
          <div class="bd-setrow__label">启用终端信任绑定</div>
          <div class="bd-setrow__desc">仅允许已绑定的授信终端建立隧道接入</div>
        </div>
        <a-switch v-model="settings.enabled" size="small" />
      </div>
      <div class="bd-setrow">
        <div class="bd-setrow__main">
          <div class="bd-setrow__label">绑定方式</div>
          <div class="bd-setrow__desc">自动绑定首登终端，或经管理员审批后纳管</div>
        </div>
        <a-radio-group v-model="settings.bindMethod" type="button" size="small">
          <a-radio value="auto">自动绑定</a-radio>
          <a-radio value="approval">审批绑定</a-radio>
        </a-radio-group>
      </div>
      <div class="bd-setrow">
        <div class="bd-setrow__main">
          <div class="bd-setrow__label">每用户绑定上限</div>
          <div class="bd-setrow__desc">同一账号可绑定的授信终端数量（0 = 不限）</div>
        </div>
        <a-input-number v-model="settings.perUserQuota" :min="0" size="small" style="width: 96px" />
      </div>
    </a-modal>

    <!-- 驳回理由 -->
    <a-modal v-model:visible="rejectOpen" title="驳回绑定申请" :width="460" @ok="reject" ok-text="确认驳回" cancel-text="取消">
      <div class="bd-reject">
        <icon-exclamation-circle-fill class="bd-reject__ic" />
        <div>将驳回 <b>{{ cur?.user }}</b> 对 <b>「{{ cur?.device }}」</b> 的绑定申请，请填写驳回理由（将通知申请人）。</div>
      </div>
      <a-textarea v-model="rejectReason" placeholder="例如：指纹与历史记录不符，疑似设备克隆，请联系 IT 现场核验" :max-length="200" allow-clear :auto-size="{ minRows: 3, maxRows: 5 }" />
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type DeviceBundle, type Device, type TrustApproval, type DeviceTrustSetting } from '@/lib/api';

const tab = ref<'list' | 'approval'>('list');
const live = ref(false);
const setOpen = ref(false);
const rejectOpen = ref(false);
const rejectReason = ref('');

/* ── 内置 mock（结构同后端 DeviceBundle）── */
const MOCK_SETTINGS: DeviceTrustSetting = { enabled: true, bindMethod: 'approval', perUserQuota: 3 };
const MOCK_DEVICES: Device[] = [
  { id: 'd1', name: 'LAPTOP-WANGFANG', fingerprint: 'FP-7A3C-9E21-4F88', user: '王芳', assetClass: 'enterprise', os: 'Windows 11 23H2', clientVersion: '4.2.1', online: true, tags: ['财务专网', '已加密'] },
  { id: 'd2', name: 'MBP-LIWEI', fingerprint: 'FP-2D5B-77AC-10E3', user: '李伟', assetClass: 'managed', os: 'macOS 14.4', clientVersion: '4.2.1', online: true, tags: ['MDM 托管'] },
  { id: 'd3', name: 'iPhone-zhangmin', fingerprint: 'FP-9F01-3B6D-A442', user: '张敏', assetClass: 'personal', os: 'iOS 17.4', clientVersion: '3.9.0', online: false, tags: ['BYOD'] },
  { id: 'd4', name: 'DESKTOP-OPS-07', fingerprint: 'FP-1C8E-55A0-77B9', user: '陈强', assetClass: 'enterprise', os: 'Windows 10 22H2', clientVersion: '4.1.6', online: true, tags: ['运维堡垒'] },
  { id: 'd5', name: 'HUAWEI-MateBook', fingerprint: 'FP-6B22-D914-2E0F', user: '赵磊', assetClass: 'personal', os: 'Windows 11 23H2', clientVersion: '4.2.0', online: false, tags: ['BYOD', '待核验'] }
];
const MOCK_APPROVALS: TrustApproval[] = [
  {
    id: 'a1', user: '赵磊', device: 'HUAWEI-MateBook', fingerprint: 'FP-6B22-D914-2E0F',
    submittedAt: '2026-06-22 09:14', reason: '居家办公，需绑定个人笔记本接入研发专网', status: 'pending',
    timeline: [
      { time: '06-22 09:14', kind: 'submit', title: '提交绑定申请', detail: '用户在客户端首次登录后发起设备绑定，目标资源：研发代码仓' },
      { time: '06-22 09:14', kind: 'login', title: '记录登录上下文', detail: '出口 IP 113.88.x.x（广东·深圳）· 客户端 4.2.0 · 非企业网段' },
      { time: '06-22 09:15', kind: 'risk', title: '风险评估：中', detail: '个人 BYOD 终端 + 新指纹，未检出 MDM 托管，建议人工核验设备归属' },
      { time: '06-22 09:16', kind: 'notify', title: '已通知审批人', detail: '推送至管理员王芳（财务/IT），待处置' }
    ]
  },
  {
    id: 'a2', user: '孙浩', device: 'LAPTOP-SUNHAO', fingerprint: 'FP-44A1-90C7-EE5D',
    submittedAt: '2026-06-22 08:02', reason: '更换新办公笔记本，原终端已报废', status: 'pending',
    timeline: [
      { time: '06-22 08:02', kind: 'submit', title: '提交绑定申请', detail: '用户申请将新企业终端纳入授信，替换已注销设备' },
      { time: '06-22 08:02', kind: 'login', title: '记录登录上下文', detail: '出口 IP 10.20.x.x（企业内网·上海）· 客户端 4.2.1' },
      { time: '06-22 08:03', kind: 'review', title: '资产系统比对', detail: '指纹匹配 IT 资产台账 SN-2026-0451，归属确认为企业资产' },
      { time: '06-22 08:03', kind: 'notify', title: '已通知审批人', detail: '低风险，建议直接通过' }
    ]
  },
  {
    id: 'a3', user: '周婷', device: 'iPad-zhouting', fingerprint: 'FP-0E73-2BB8-91A6',
    submittedAt: '2026-06-21 21:40', reason: '出差期间需用平板临时审批流程', status: 'pending',
    timeline: [
      { time: '06-21 21:40', kind: 'submit', title: '提交绑定申请', detail: '非工作时段发起，目标资源：OA 审批' },
      { time: '06-21 21:40', kind: 'login', title: '记录登录上下文', detail: '出口 IP 1.32.x.x（境外·新加坡）· 客户端 3.9.0' },
      { time: '06-21 21:41', kind: 'risk', title: '风险评估：高', detail: '境外 IP + 个人终端 + 非工作时段，触发异地登录策略，建议二次确认' }
    ]
  }
];

const settings = reactive<DeviceTrustSetting>({ ...MOCK_SETTINGS });
const devices = ref<Device[]>(MOCK_DEVICES);
const approvals = ref<TrustApproval[]>(MOCK_APPROVALS);
const selId = ref<string>(MOCK_APPROVALS[0]?.id ?? '');

const cur = computed(() => approvals.value.find((a) => a.id === selId.value) ?? null);
const pendingCount = computed(() => approvals.value.filter((a) => a.status === 'pending').length);
const onlineCount = computed(() => devices.value.filter((d) => d.online).length);

function assetMeta(c: Device['assetClass']) {
  return {
    enterprise: { label: '企业资产', color: 'var(--bd-primary)' },
    managed: { label: '托管', color: '#722ED1' },
    personal: { label: '个人', color: 'var(--bd-warning)' }
  }[c];
}
function tagStyle(color: string) { return { color, background: `color-mix(in srgb, ${color} 12%, #fff)` }; }
function dotColor(kind: ApprovalKind): string {
  return { submit: '#165DFF', risk: '#FF7D00', login: '#C9CDD4', review: '#165DFF', notify: '#00B42A' }[kind];
}
type ApprovalKind = TrustApproval['timeline'][number]['kind'];

/** 取该申请最高风险事件的提示文案，用于左侧列表角标 */
function riskOf(a: TrustApproval): string {
  const r = a.timeline.find((e) => e.kind === 'risk');
  return r ? r.title : '';
}

function bind(d: Device) { Message.info(`「${d.name}」绑定操作（演示）`); }

function saveSettings() {
  setOpen.value = false;
  Message.success(settings.enabled ? `已保存：${settings.bindMethod === 'auto' ? '自动绑定' : '审批绑定'} · 每用户上限 ${settings.perUserQuota || '不限'}` : '已关闭终端信任绑定');
}

function approve() {
  const a = cur.value;
  if (!a) return;
  approvals.value = approvals.value.filter((x) => x.id !== a.id);
  selId.value = approvals.value[0]?.id ?? '';
  Message.success(`已通过 ${a.user} 对「${a.device}」的绑定，已下发授信指纹`);
}
function reject() {
  const a = cur.value;
  if (!a) return;
  rejectOpen.value = false;
  approvals.value = approvals.value.filter((x) => x.id !== a.id);
  selId.value = approvals.value[0]?.id ?? '';
  Message.warning(`已驳回 ${a.user} 的绑定申请${rejectReason.value ? `：${rejectReason.value}` : ''}`);
  rejectReason.value = '';
}

onMounted(async () => {
  try {
    const b = await api<DeviceBundle>('/devices');
    Object.assign(settings, b.settings);
    devices.value = b.devices;
    approvals.value = b.approvals;
    selId.value = b.approvals[0]?.id ?? '';
    live.value = true;
  } catch { live.value = false; }
});
</script>

<style scoped>
.bd-head__right { margin-left: auto; }

/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { display: flex; align-items: center; gap: 7px; font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }
.bd-tab em { font-style: normal; font-size: 11px; color: var(--bd-t3); }
.bd-tab.on em { color: var(--bd-primary); }
.bd-badge { min-width: 16px; height: 16px; padding: 0 5px; border-radius: 8px; background: var(--bd-danger); color: #fff; font-size: 11px; font-weight: 600; display: inline-flex; align-items: center; justify-content: center; line-height: 1; }

/* 设备清单 */
.bd-toolbar__c { font-size: 12.5px; color: var(--bd-t3); }
.bd-tg--grey { background: var(--bd-fill-2); color: var(--bd-t3); font-weight: 400; }
.bd-cellname { gap: 9px; flex-wrap: wrap; cursor: default; }
.bd-dmono { display: block; font-size: 11px; color: var(--bd-t3); margin-top: 3px; font-family: ui-monospace, monospace; }

/* 审批两栏 */
.bd-two { display: flex; gap: 16px; align-items: flex-start; }

/* 左：待审批列表 */
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

/* 右：详情 */
.bd-apdetail { flex: 1; min-width: 0; padding: 20px 22px 22px; }
.bd-apd__head { display: flex; align-items: flex-start; justify-content: space-between; padding-bottom: 16px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-apd__dev { font-size: 16px; font-weight: 700; color: var(--bd-t1); }
.bd-apd__fp { font-size: 12px; color: var(--bd-t3); margin-top: 4px; }
.bd-apd__meta { padding: 6px 0 4px; }
.bd-kv { display: flex; align-items: center; justify-content: space-between; padding: 9px 0; border-bottom: 1px solid var(--bd-fill-1); font-size: 13px; }
.bd-kv span { color: var(--bd-t3); }
.bd-kv b { font-weight: 500; color: var(--bd-t1); }
.bd-apd__sec { font-size: 13px; font-weight: 600; margin: 20px 0 14px; }

/* 时间线 */
.bd-tl { padding-left: 2px; }
.bd-tl__row { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
.bd-tl__title { font-size: 13px; font-weight: 600; color: var(--bd-t1); }
.bd-tl__time { font-size: 11.5px; color: var(--bd-t3); flex: none; }
.bd-tl__detail { font-size: 12px; color: var(--bd-t3); line-height: 1.6; margin-top: 3px; }

.bd-apd__acts { display: flex; gap: 10px; margin-top: 22px; }

/* 空态 */
.bd-empty { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--bd-t3); padding: 16px 12px; }
.bd-empty :deep(svg) { color: var(--bd-success); }
.bd-empty--lg { justify-content: center; min-height: 280px; flex-direction: column; gap: 12px; color: var(--bd-t4); }
.bd-empty--lg :deep(svg) { font-size: 28px; color: var(--bd-t4); }

/* 设置 modal */
.bd-setrow { display: flex; align-items: center; gap: 12px; padding: 14px 0; border-bottom: 1px solid var(--bd-fill-1); }
.bd-setrow:last-child { border-bottom: none; }
.bd-setrow__main { flex: 1; min-width: 0; }
.bd-setrow__label { font-size: 13.5px; font-weight: 500; color: var(--bd-t1); }
.bd-setrow__desc { font-size: 12px; color: var(--bd-t3); margin-top: 3px; }

/* 驳回 modal */
.bd-reject { display: flex; gap: 12px; font-size: 13.5px; line-height: 1.7; color: var(--bd-t2); margin-bottom: 14px; }
.bd-reject__ic { color: var(--bd-danger); font-size: 20px; flex: none; margin-top: 2px; }
</style>
