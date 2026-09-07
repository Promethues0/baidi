<template>
  <div class="bd-portal">
    <PortalBar title="白帝 · 我的申请" :user="displayName">
      <button class="bd-pquit" @click="router.push('/portal/apps')">
        <icon-apps /><span>返回应用</span>
      </button>
    </PortalBar>

    <main class="bd-pmain">
      <div class="bd-pwrap">
        <div class="bd-phead">
          <div class="bd-phead__l">
            <h1 class="bd-phead__hi">我的访问申请</h1>
            <p class="bd-phead__sub">
              <b>{{ activeGrants.length }}</b> 个有效授予
              <span class="bd-dot">·</span>
              <i>{{ pendingCount }}</i> 个待审批
            </p>
          </div>
          <!-- 连接态三态：live == null（首轮请求还在路上）不画标签——那一刻既不是"已连"
               也不是"降级演示"，与 PageHeader 的口径一致。 -->
          <a-tag v-if="live != null" :color="live ? 'green' : 'orange'" bordered>
            <template #icon><icon-cloud /></template>
            {{ live ? '已连 baidi-control' : '降级演示' }}
          </a-tag>
        </div>

        <!-- ★读取失败时，后端那句原话必须在页面上有地方看。改造前唯一的线索是右上角
             那枚橙色「降级演示」标签——用户看得出"出事了"，看不到"是什么事"，
             而这里恰恰是他判断「我那条申请到底批没批」的地方。 -->
        <div v-if="live === false" class="bd-notice bd-notice--warn bd-preq__warn">
          <icon-exclamation-circle-fill />
          <div class="bd-notice__body">
            申请记录未读取（后端原话：<b>{{ loadErr }}</b>），下面的授予与申请单是<b>内置演示数据</b>，
            <b>不代表你的真实申请状态</b>。请稍后刷新，或联系管理员。
          </div>
        </div>

        <!-- 首屏骨架：第一次 load() 回来之前不画演示数据，也不画「还没有提交过申请」 -->
        <template v-if="!loaded">
          <div class="bd-psec">
            <div class="bd-psec__t"><icon-history />申请记录</div>
            <div class="bd-tablecard"><SkeletonBlock kind="table" :rows="3" :cols="5" /></div>
          </div>
        </template>

        <a-spin v-else :loading="loading" class="bd-pspin">
          <!-- 有效授予（时限访问） -->
          <div v-if="activeGrants.length" class="bd-psec">
            <div class="bd-psec__t"><icon-unlock />当前有效授予</div>
            <div class="bd-glist">
              <div v-for="g in activeGrants" :key="g.id" class="bd-card bd-gcard">
                <div class="bd-gcard__l">
                  <div class="bd-gcard__name">{{ g.resourceName }}</div>
                  <div class="bd-gcard__meta bd-mono">授予至 {{ fmtTs(g.expiresAt) }}</div>
                </div>
                <div class="bd-gcard__r">
                  <span class="bd-tg bd-remain" :class="remainSec(g.expiresAt) < 300 ? 'bd-tg--gold' : 'bd-tg--green'">
                    <icon-clock-circle />剩余 {{ remainText(g.expiresAt) }}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <!-- 申请单列表 -->
          <div class="bd-psec">
            <div class="bd-psec__t"><icon-history />申请记录 <em>{{ requests.length }}</em></div>
            <div class="bd-tablecard">
              <table class="bd-table">
                <thead>
                  <tr><th>资源</th><th>理由</th><th>期望时长</th><th>提交时间</th><th>状态</th></tr>
                </thead>
                <tbody>
                  <tr v-for="r in requests" :key="r.id">
                    <td><b class="bd-rres">{{ r.resourceName }}</b></td>
                    <td class="bd-rreason">{{ r.reason }}</td>
                    <td>{{ r.ttlMinutes }} 分钟</td>
                    <td class="bd-mono">{{ r.submittedAt }}</td>
                    <td><span class="bd-tg" :class="statusTag[r.status]">{{ statusZh[r.status] }}</span></td>
                  </tr>
                  <tr v-if="!requests.length && !loading" class="bd-table__emptyrow">
                    <td colspan="5">
                      <EmptyState size="md" title="还没有提交过访问申请" tone="ok">
                        去<button type="button" class="bd-link" @click="router.push('/portal/apps')">应用门户</button>发起吧
                      </EmptyState>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </a-spin>
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useRouter } from 'vue-router';
import { api, failReason, type MyRequestsResp, type AccessRequest, type JitGrant } from '@/lib/api';
import PortalBar from '@/components/PortalBar.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

const router = useRouter();
const loading = ref(false);
/** 首屏是否已完成第一次 load()：只决定骨架屏何时让位（成功 / 降级都算完成），不改任何数据流。 */
const loaded = ref(false);
/** 连接态三态：undefined = 首轮请求还在路上（判不出来，不画标签）/ true 已连 / false 降级演示。
 *  ★初值写 false 的话，首屏那一瞬右上角就挂上一枚橙色「降级演示」——把"还没探过"
 *  说成"确定离线"，而那一刻什么都还没发生。 */
const live = ref<boolean | undefined>(undefined);
/** 读取失败时后端那句原话（failReason 收口，前端不编造归因）。 */
const loadErr = ref('');
const displayName = ref('');
const requests = ref<AccessRequest[]>([]);
const grants = ref<JitGrant[]>([]);
const nowSec = ref(Math.floor(Date.now() / 1000));
let timer: number | undefined;

/* 无后端降级演示数据 */
const MOCK_REQUESTS: AccessRequest[] = [
  { id: 'areq-demo1', user: 'li.fang', resourceId: 'finance', resourceName: '财务核算系统', reason: '季度对账，需临时查阅凭证', ttlMinutes: 120, status: 'approved', timeline: [], submittedAt: '2026-07-23 09:12', decidedAt: '2026-07-23 09:20', decideReason: '', decidedBy: 'admin', grantId: 'grant-demo1' },
  { id: 'areq-demo2', user: 'li.fang', resourceId: 'finance', resourceName: '财务核算系统', reason: '月末结账', ttlMinutes: 60, status: 'pending', timeline: [], submittedAt: '2026-07-23 10:02', decidedAt: '', decideReason: '', decidedBy: '', grantId: '' }
];
const MOCK_GRANTS: JitGrant[] = [
  { id: 'grant-demo1', user: 'li.fang', resourceId: 'finance', resourceName: '财务核算系统', requestId: 'areq-demo1', reason: '季度对账', grantedBy: 'admin', grantedAt: Math.floor(Date.now() / 1000) - 600, expiresAt: Math.floor(Date.now() / 1000) + 6000, status: 'active', revokedAt: 0, revokeReason: '' }
];

const statusZh: Record<AccessRequest['status'], string> = { pending: '待审批', approved: '已批准', rejected: '已驳回' };
/** 状态 → .bd-tg 颜色变体（待审批金 / 已批准绿 / 已驳回红） */
const statusTag: Record<AccessRequest['status'], string> = { pending: 'bd-tg--gold', approved: 'bd-tg--green', rejected: 'bd-tg--red' };
const activeGrants = computed(() => grants.value.filter(g => g.status === 'active' && g.expiresAt > nowSec.value));
const pendingCount = computed(() => requests.value.filter(r => r.status === 'pending').length);

function fmtTs(ts: number): string {
  return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false });
}
function remainSec(exp: number): number { return Math.max(0, exp - nowSec.value); }
function remainText(exp: number): string {
  const s = remainSec(exp);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h} 小时 ${m} 分`;
  if (m > 0) return `${m} 分`;
  return `${s} 秒`;
}

async function load() {
  loading.value = true;
  try {
    const resp = await api<MyRequestsResp>('/portal/access-requests');
    requests.value = resp.requests ?? [];
    grants.value = resp.grants ?? [];
    live.value = true;
    loadErr.value = '';
  } catch (e) {
    // 降级：内置演示数据，页面完整可点；后端原话经 loadErr 落到页面上的提示条里，
    // 不在这里编一句归因（门户用户看到「网络异常」只会反复刷新）。
    requests.value = MOCK_REQUESTS;
    grants.value = MOCK_GRANTS;
    live.value = false;
    loadErr.value = failReason(e);
  } finally {
    loading.value = false;
    loaded.value = true;
  }
}

onMounted(() => {
  const raw = sessionStorage.getItem('baidi_portal');
  if (!raw) { router.replace('/portal/login'); return; }
  try {
    const s = JSON.parse(raw) as { displayName?: string };
    if (!s.displayName) { router.replace('/portal/login'); return; }
    displayName.value = s.displayName;
  } catch { router.replace('/portal/login'); return; }
  load();
  timer = window.setInterval(() => { nowSec.value = Math.floor(Date.now() / 1000); }, 1000);
});
onUnmounted(() => { if (timer) window.clearInterval(timer); });
</script>

<style scoped>
/* 本页独有：授予卡片与申请表里的两处小样式。门户壳在 PortalBar.vue，表格 / 标签 / 空态 / 骨架是全局或共享件。 */
.bd-pspin { display: block; }
/* 门户页头与内容之间没有 PageHeader 的下间距，提示条自己补一档 */
.bd-preq__warn { margin-bottom: var(--bd-sp-5); }

/* 授予卡片：左侧绿色边表达「当前有效」 */
.bd-glist { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: var(--bd-sp-4); }
.bd-gcard {
  border-left: 3px solid var(--bd-success);
  padding: var(--bd-sp-4) var(--bd-sp-5); display: flex; align-items: center; justify-content: space-between; gap: var(--bd-sp-4);
}
.bd-gcard__name { font-size: 15px; font-weight: 600; color: var(--bd-t1); }
.bd-gcard__meta { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin-top: 5px; }
.bd-remain { display: inline-flex; align-items: center; gap: 5px; font-size: var(--bd-fs-sm); font-weight: 600; padding: 5px 10px; border-radius: var(--bd-radius-s); }

/* 申请表 */
.bd-rres { font-weight: 600; color: var(--bd-t1); }
.bd-rreason { max-width: 320px; }
</style>
