<template>
  <div class="bd-portal">
    <!-- 顶部细 bar -->
    <header class="bd-pbar">
      <div class="bd-plogo">
        <span class="bd-plogo__mark">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
            <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </span>
        <span class="bd-plogo__txt">白帝 · 应用门户</span>
      </div>
      <div class="bd-pbar__spacer" />
      <div class="bd-pacct">
        <span class="bd-pacct__av">{{ avatarText }}</span>
        <span class="bd-pacct__name">{{ displayName }}</span>
      </div>
      <button class="bd-pquit" @click="logout"><icon-export /><span>退出</span></button>
    </header>

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
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { api, type PortalAppsResp, type PortalTile } from '@/lib/api';

const router = useRouter();

const loading = ref(false);
const keyword = ref('');
const apps = ref<PortalTile[]>([]);
const displayName = ref('');

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
  sessionStorage.removeItem('baidi_portal');
  router.push('/portal/login');
}

function openApp(app: PortalTile) {
  Message.success(`正在通过安全隧道打开 ${app.name}…`);
}

function requestAccess(app: PortalTile) {
  Message.info(`「${app.name}」权限申请已提交，待审批`);
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

/* 顶部细 bar */
.bd-pbar {
  height: 56px; flex: none; background: #fff; border-bottom: 1px solid var(--bd-border);
  display: flex; align-items: center; padding: 0 24px; gap: 14px; position: sticky; top: 0; z-index: 10;
}
.bd-plogo { display: flex; align-items: center; gap: 10px; }
.bd-plogo__mark {
  width: 30px; height: 30px; border-radius: 7px; flex: none;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d));
  display: flex; align-items: center; justify-content: center; box-shadow: 0 2px 6px rgba(22, 93, 255, .35);
}
.bd-plogo__txt { font-size: 15px; font-weight: 700; letter-spacing: .3px; color: var(--bd-t1); }
.bd-pbar__spacer { flex: 1; }
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
</style>
