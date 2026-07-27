<template>
  <div class="bd-portal">
    <!-- 顶部细 bar -->
    <PortalBar title="白帝 · 应用门户">
      <button class="bd-pquit" @click="router.push('/portal/requests')">
        <icon-history /><span>我的申请</span>
      </button>
      <button class="bd-pquit" @click="router.push('/portal/security')">
        <icon-safe /><span>我的安全</span>
      </button>
      <button class="bd-pquit" @click="router.push('/portal/downloads')">
        <icon-download /><span>下载客户端</span>
      </button>
      <div class="bd-pacct">
        <span class="bd-pacct__av">{{ avatarText }}</span>
        <span class="bd-pacct__name">{{ displayName }}</span>
      </div>
      <button class="bd-pquit" @click="logout"><icon-export /><span>退出</span></button>
    </PortalBar>

    <!-- 主体 -->
    <main class="bd-pmain">
      <div class="bd-pwrap">
        <!-- 欢迎语 + 搜索 -->
        <div class="bd-phead">
          <div class="bd-phead__l">
            <h1 class="bd-phead__hi">你好，{{ displayName }}</h1>
            <p class="bd-phead__sub">
              可访问 <b>{{ accessibleCount }}</b> 个应用
              <span class="bd-dot">·</span>
              <i>{{ pendingCount }}</i> 个待申请
            </p>
          </div>
          <a-input
            v-model="keyword"
            class="bd-psearch"
            placeholder="搜索应用名称或地址…"
            allow-clear
          >
            <template #prefix><icon-search /></template>
          </a-input>
        </div>

        <!-- 应用磁贴网格 -->
        <a-spin :loading="loading" style="display:block">
          <div v-if="filtered.length" class="bd-grid">
            <div v-for="app in filtered" :key="app.id" class="bd-tile">
              <div class="bd-tile__top">
                <span class="bd-tile__icon" :class="'m-' + app.mode">
                  <component :is="modeMeta[app.mode].icon" />
                </span>
                <span
                  v-if="!app.accessible"
                  class="bd-tile__gold"
                ><icon-lock />高敏 · 需申请</span>
              </div>
              <div class="bd-tile__name">{{ app.name }}</div>
              <div class="bd-tile__addr bd-mono">{{ app.addr }}</div>
              <div class="bd-tile__meta">
                <span class="bd-mtag" :class="'mt-' + app.mode">{{ modeMeta[app.mode].label }}</span>
              </div>
              <button
                v-if="app.accessible"
                class="bd-tile__btn"
                @click="openApp(app)"
              ><icon-link />访问</button>
              <button
                v-else
                class="bd-tile__btn bd-tile__btn--ghost"
                @click="requestAccess(app)"
              ><icon-safe />申请权限</button>
            </div>
          </div>

          <!-- 空态 -->
          <div v-else-if="!loading" class="bd-empty">
            <icon-apps class="bd-empty__icon" />
            <div class="bd-empty__t">{{ keyword ? '没有匹配的应用' : '暂无可用应用' }}</div>
            <div class="bd-empty__s">{{ keyword ? '换个关键词试试' : '请联系管理员为你授权应用访问' }}</div>
          </div>
        </a-spin>
      </div>
    </main>

    <!-- JIT 访问申请 -->
    <a-modal v-model:visible="reqOpen" :title="`申请访问「${reqApp?.name ?? ''}」`" :width="480"
      :ok-loading="submitting" @ok="submitRequest" ok-text="提交申请" cancel-text="取消">
      <div class="bd-reqtip">
        <icon-safe class="bd-reqtip__ic" />
        <div>该应用为<b>高敏资源</b>，需管理员审批。批准后你将获得<b>限时访问授予</b>，到期自动回收。</div>
      </div>
      <div class="bd-reqfield">
        <label>期望时长（分钟）</label>
        <a-input-number v-model="reqTtl" :min="15" :max="480" :step="15" style="width: 160px" />
        <span class="bd-reqfield__hint">15–480 分钟</span>
      </div>
      <div class="bd-reqfield">
        <label>申请理由</label>
        <a-textarea v-model="reqReason" placeholder="例如：季度财务对账，需临时访问财务核算系统"
          :max-length="200" allow-clear :auto-size="{ minRows: 3, maxRows: 5 }" />
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { api, clearToken, type PortalAppsResp, type PortalTile } from '@/lib/api';
import PortalBar from '@/components/PortalBar.vue';

const router = useRouter();

const loading = ref(false);
const keyword = ref('');
const apps = ref<PortalTile[]>([]);
const displayName = ref('');

/* JIT 访问申请弹窗 */
const reqOpen = ref(false);
const reqApp = ref<PortalTile | null>(null);
const reqReason = ref('');
const reqTtl = ref(60);
const submitting = ref(false);

const modeMeta: Record<PortalTile['mode'], { label: string; icon: string }> = {
  tunnel: { label: '隧道代理', icon: 'icon-swap' },
  web:    { label: 'Web 应用', icon: 'icon-common' },
  global: { label: '全局加速', icon: 'icon-public' }
};

const avatarText = computed(() => (displayName.value || '·').slice(0, 1).toUpperCase());
const accessibleCount = computed(() => apps.value.filter(a => a.accessible).length);
const pendingCount = computed(() => apps.value.filter(a => !a.accessible).length);

const filtered = computed(() => {
  const k = keyword.value.trim().toLowerCase();
  if (!k) return apps.value;
  return apps.value.filter(
    a => a.name.toLowerCase().includes(k) || a.addr.toLowerCase().includes(k)
  );
});

function logout() {
  clearToken();
  sessionStorage.removeItem('baidi_portal');
  router.push('/portal/login');
}

function openApp(app: PortalTile) {
  Message.success(`正在通过安全隧道打开 ${app.name}…`);
}

function requestAccess(app: PortalTile) {
  reqApp.value = app;
  reqReason.value = '';
  reqTtl.value = 60;
  reqOpen.value = true;
}

async function submitRequest() {
  const app = reqApp.value;
  if (!app) return;
  if (!reqReason.value.trim()) { Message.warning('请填写申请理由'); return; }
  submitting.value = true;
  try {
    await api('/portal/access-requests', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ appId: app.id, reason: reqReason.value.trim(), ttlMinutes: reqTtl.value })
    });
    reqOpen.value = false;
    Message.success(`「${app.name}」访问申请已提交，等待管理员审批`);
  } catch (e) {
    // 无后端 / 重复申请等：不白屏，提示即可（HTTP 409 = 已有待审批或有效授予）
    const msg = String((e as Error)?.message ?? '');
    Message.error(msg.startsWith('409') ? '你已有待审批的申请或有效授予，请勿重复提交' : '申请提交失败，请稍后再试');
  } finally {
    submitting.value = false;
  }
}

async function load() {
  loading.value = true;
  try {
    const resp = await api<PortalAppsResp>('/portal/apps');
    apps.value = resp.apps ?? [];
  } catch {
    Message.error('应用列表加载失败');
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  const raw = sessionStorage.getItem('baidi_portal');
  if (!raw) {
    router.replace('/portal/login');
    return;
  }
  try {
    const s = JSON.parse(raw) as { displayName?: string };
    if (!s.displayName) {
      router.replace('/portal/login');
      return;
    }
    displayName.value = s.displayName;
  } catch {
    router.replace('/portal/login');
    return;
  }
  load();
});
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

/* 主体 */
.bd-pmain { flex: 1; padding: 40px 24px 64px; }
.bd-pwrap { max-width: 1080px; margin: 0 auto; }

/* 欢迎语 + 搜索 */
.bd-phead {
  display: flex; align-items: flex-end; justify-content: space-between; gap: 20px;
  margin-bottom: 28px; flex-wrap: wrap;
}
.bd-phead__hi { margin: 0; font-size: 26px; font-weight: 700; color: var(--bd-t1); letter-spacing: .3px; }
.bd-phead__sub { margin: 8px 0 0; font-size: 14px; color: var(--bd-t3); }
.bd-phead__sub b { color: var(--bd-primary); font-weight: 700; font-size: 15px; }
.bd-phead__sub i { color: var(--bd-warning); font-style: normal; font-weight: 700; font-size: 15px; }
.bd-phead__sub .bd-dot { margin: 0 8px; color: var(--bd-t4); }
.bd-psearch { width: 300px; max-width: 100%; }

/* 磁贴网格 */
.bd-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 18px;
}
.bd-tile {
  background: #fff; border: 1px solid var(--bd-border); border-radius: var(--bd-radius);
  padding: 20px; display: flex; flex-direction: column; transition: box-shadow .15s, border-color .15s, transform .15s;
}
.bd-tile:hover {
  border-color: var(--bd-primary-b); box-shadow: 0 8px 24px rgba(22, 93, 255, .1); transform: translateY(-2px);
}
.bd-tile__top { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; margin-bottom: 14px; }
.bd-tile__icon {
  width: 46px; height: 46px; border-radius: 12px; flex: none;
  display: flex; align-items: center; justify-content: center; font-size: 22px;
}
.bd-tile__icon.m-tunnel { background: var(--bd-tag-purple-bg); color: var(--bd-purple); }
.bd-tile__icon.m-web    { background: var(--bd-tag-blue-bg);   color: var(--bd-primary); }
.bd-tile__icon.m-global { background: var(--bd-tag-green-bg);  color: var(--bd-success); }
.bd-tile__gold {
  display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 600;
  color: var(--bd-warning); background: var(--bd-tag-gold-bg); padding: 3px 8px; border-radius: 6px; white-space: nowrap;
}
.bd-tile__name { font-size: 16px; font-weight: 600; color: var(--bd-t1); line-height: 1.3; }
.bd-tile__addr { font-size: 12px; color: var(--bd-t3); margin-top: 6px; word-break: break-all; }
.bd-tile__meta { margin-top: 12px; }
.bd-mtag {
  display: inline-block; font-size: 11.5px; font-weight: 500; padding: 2px 9px; border-radius: 5px;
}
.bd-mtag.mt-tunnel { background: var(--bd-tag-purple-bg); color: var(--bd-purple); }
.bd-mtag.mt-web    { background: var(--bd-tag-blue-bg);   color: var(--bd-primary); }
.bd-mtag.mt-global { background: var(--bd-tag-green-bg);  color: var(--bd-success); }
.bd-tile__btn {
  margin-top: 18px; height: 38px; width: 100%; border: none; border-radius: 8px;
  background: var(--bd-primary); color: #fff; font-size: 13px; font-weight: 500;
  display: inline-flex; align-items: center; justify-content: center; gap: 7px; cursor: pointer;
  box-shadow: 0 2px 6px rgba(22, 93, 255, .25); transition: background .15s;
}
.bd-tile__btn:hover { background: var(--bd-primary-h); }
.bd-tile__btn--ghost {
  background: #fff; color: var(--bd-t2); border: 1px solid var(--bd-border); box-shadow: none;
}
.bd-tile__btn--ghost:hover { border-color: var(--bd-warning); color: var(--bd-warning); background: #fff; }

/* 空态 */
.bd-empty { text-align: center; padding: 80px 20px; }
.bd-empty__icon { font-size: 56px; color: var(--bd-t4); }
.bd-empty__t { margin-top: 16px; font-size: 16px; font-weight: 600; color: var(--bd-t2); }
.bd-empty__s { margin-top: 6px; font-size: 13px; color: var(--bd-t3); }

/* 申请弹窗 */
.bd-reqtip { display: flex; gap: 10px; font-size: 13px; line-height: 1.7; color: var(--bd-t2); margin-bottom: 16px; }
.bd-reqtip__ic { color: var(--bd-primary); font-size: 18px; flex: none; margin-top: 2px; }
.bd-reqtip b { color: var(--bd-t1); font-weight: 600; }
.bd-reqfield { margin-bottom: 14px; }
.bd-reqfield label { display: block; font-size: 13px; font-weight: 500; color: var(--bd-t1); margin-bottom: 8px; }
.bd-reqfield__hint { font-size: 12px; color: var(--bd-t3); margin-left: 10px; }
</style>
