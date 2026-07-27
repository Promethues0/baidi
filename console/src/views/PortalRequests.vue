<template>
  <div class="bd-portal">
    <PortalBar title="白帝 · 我的申请">
      <button class="bd-pquit" @click="router.push('/portal/apps')">
        <icon-apps /><span>返回应用</span>
      </button>
      <div class="bd-pacct">
        <span class="bd-pacct__av">{{ avatarText }}</span>
        <span class="bd-pacct__name">{{ displayName }}</span>
      </div>
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
          <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        </div>

        <a-spin :loading="loading" style="display:block">
          <!-- 有效授予（时限访问） -->
          <div v-if="activeGrants.length" class="bd-sec">
            <div class="bd-sec__t"><icon-unlock />当前有效授予</div>
            <div class="bd-glist">
              <div v-for="g in activeGrants" :key="g.id" class="bd-gcard">
                <div class="bd-gcard__l">
                  <div class="bd-gcard__name">{{ g.resourceName }}</div>
                  <div class="bd-gcard__meta bd-mono">授予至 {{ fmtTs(g.expiresAt) }}</div>
                </div>
                <div class="bd-gcard__r">
                  <span class="bd-remain" :class="{ soon: remainSec(g.expiresAt) < 300 }">
                    <icon-clock-circle />剩余 {{ remainText(g.expiresAt) }}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <!-- 申请单列表 -->
          <div class="bd-sec">
            <div class="bd-sec__t"><icon-history />申请记录 <em>{{ requests.length }}</em></div>
            <div v-if="!requests.length && !loading" class="bd-empty">
              <icon-info-circle />还没有提交过访问申请，去<a class="bd-inline" @click="router.push('/portal/apps')">应用门户</a>发起吧
            </div>
            <table v-else class="bd-rtable">
              <thead>
                <tr><th>资源</th><th>理由</th><th>期望时长</th><th>提交时间</th><th>状态</th></tr>
              </thead>
              <tbody>
                <tr v-for="r in requests" :key="r.id">
                  <td><b>{{ r.resourceName }}</b></td>
                  <td class="bd-rreason">{{ r.reason }}</td>
                  <td>{{ r.ttlMinutes }} 分钟</td>
                  <td class="bd-mono">{{ r.submittedAt }}</td>
                  <td><span class="bd-pill" :class="'s-' + r.status">{{ statusZh[r.status] }}</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </a-spin>
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { api, type MyRequestsResp, type AccessRequest, type JitGrant } from '@/lib/api';
import PortalBar from '@/components/PortalBar.vue';

const router = useRouter();
const loading = ref(false);
const live = ref(false);
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

const avatarText = computed(() => (displayName.value || '·').slice(0, 1).toUpperCase());
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
  } catch {
    // 降级：内置演示数据，页面完整可点
    requests.value = MOCK_REQUESTS;
    grants.value = MOCK_GRANTS;
    live.value = false;
  } finally {
    loading.value = false;
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
.bd-portal { min-height: 100vh; background: var(--bd-fill-1); display: flex; flex-direction: column; }
.bd-pacct { display: flex; align-items: center; gap: 9px; }
.bd-pacct__av {
  width: 30px; height: 30px; border-radius: 50%; flex: none; color: #fff; font-size: 13px; font-weight: 600;
  background: linear-gradient(135deg, var(--bd-purple), var(--bd-primary));
  display: flex; align-items: center; justify-content: center;
}
.bd-pacct__name { font-size: 13px; font-weight: 600; color: var(--bd-t1); }
.bd-pquit {
  display: inline-flex; align-items: center; gap: 6px; height: 32px; padding: 0 12px;
  border: 1px solid var(--bd-border); background: #fff; border-radius: 7px; cursor: pointer;
  font-size: 13px; color: var(--bd-t2); transition: all .15s;
}
.bd-pquit:hover { border-color: var(--bd-primary); color: var(--bd-primary); }

.bd-pmain { flex: 1; padding: 40px 24px 64px; }
.bd-pwrap { max-width: 1080px; margin: 0 auto; }
.bd-phead { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; margin-bottom: 28px; flex-wrap: wrap; }
.bd-phead__hi { margin: 0; font-size: 26px; font-weight: 700; color: var(--bd-t1); letter-spacing: .3px; }
.bd-phead__sub { margin: 8px 0 0; font-size: 14px; color: var(--bd-t3); }
.bd-phead__sub b { color: var(--bd-primary); font-weight: 700; font-size: 15px; }
.bd-phead__sub i { color: var(--bd-warning); font-style: normal; font-weight: 700; font-size: 15px; }
.bd-phead__sub .bd-dot { margin: 0 8px; color: var(--bd-t4); }

.bd-sec { margin-bottom: 30px; }
.bd-sec__t { display: flex; align-items: center; gap: 8px; font-size: 15px; font-weight: 600; color: var(--bd-t1); margin-bottom: 14px; }
.bd-sec__t em { font-style: normal; font-size: 12px; color: var(--bd-t3); font-weight: 400; }

/* 授予卡片 */
.bd-glist { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px; }
.bd-gcard {
  background: #fff; border: 1px solid var(--bd-border); border-left: 3px solid var(--bd-success);
  border-radius: var(--bd-radius); padding: 16px 18px; display: flex; align-items: center; justify-content: space-between; gap: 14px;
}
.bd-gcard__name { font-size: 15px; font-weight: 600; color: var(--bd-t1); }
.bd-gcard__meta { font-size: 12px; color: var(--bd-t3); margin-top: 5px; }
.bd-remain {
  display: inline-flex; align-items: center; gap: 5px; font-size: 12.5px; font-weight: 600;
  color: var(--bd-success); background: var(--bd-tag-green-bg); padding: 5px 10px; border-radius: 7px; white-space: nowrap;
}
.bd-remain.soon { color: var(--bd-warning); background: var(--bd-tag-gold-bg); }

/* 申请表 */
.bd-rtable { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid var(--bd-border); border-radius: var(--bd-radius); overflow: hidden; }
.bd-rtable th, .bd-rtable td { text-align: left; padding: 12px 16px; font-size: 13px; border-bottom: 1px solid var(--bd-fill-1); }
.bd-rtable th { font-size: 12px; font-weight: 600; color: var(--bd-t3); background: var(--bd-fill-1); }
.bd-rtable tbody tr:last-child td { border-bottom: none; }
.bd-rtable b { font-weight: 600; color: var(--bd-t1); }
.bd-rreason { color: var(--bd-t2); max-width: 320px; }
.bd-pill { display: inline-block; font-size: 11.5px; font-weight: 600; padding: 3px 10px; border-radius: 6px; }
.bd-pill.s-pending { color: var(--bd-warning); background: var(--bd-tag-gold-bg); }
.bd-pill.s-approved { color: var(--bd-success); background: var(--bd-tag-green-bg); }
.bd-pill.s-rejected { color: var(--bd-danger); background: color-mix(in srgb, var(--bd-danger) 12%, #fff); }

.bd-empty { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--bd-t3); padding: 32px 12px; justify-content: center; }
.bd-inline { color: var(--bd-primary); cursor: pointer; margin: 0 3px; }
.bd-mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
