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
                <!-- 三种"不可访问"必须分开说，因为用户的下一步动作完全不同：
                     降权 → 先修终端（申请也没用，降权否决压过 JIT 授予）；
                     未关联资源 → 配置缺口，找管理员（申请会被后端以「不支持自助申请」拒掉）；
                     未授权 → 可以走自助申请。
                     ★徽标文案不再写死「高敏」：不可访问与敏感度是两件事，普通资源没授权同样进不去，
                     而已授权的高敏资源是能直接访问的（服务端判定见 appAccessState）。 -->
                <span
                  v-if="app.degraded"
                  class="bd-tile__gold bd-tile__gold--deg"
                ><icon-exclamation-circle-fill />终端降级 · 暂停访问</span>
                <span
                  v-else-if="app.unavailable"
                  class="bd-tile__gold bd-tile__gold--deg"
                  :title="app.unavailableReason"
                ><icon-exclamation-circle-fill />配置缺口 · 不可用</span>
                <span
                  v-else-if="!app.accessible"
                  class="bd-tile__gold"
                >
                  <icon-lock />{{ app.sensitivity === 'high' ? '高敏 · 需申请' : '未授权 · 可申请' }}
                </span>
              </div>
              <div class="bd-tile__name">{{ app.name }}</div>
              <div class="bd-tile__addr bd-mono">{{ app.addr }}</div>
              <div class="bd-tile__meta">
                <span class="bd-mtag" :class="'mt-' + app.mode">{{ modeMeta[app.mode].label }}</span>
              </div>
              <!-- ★这一串 v-if/v-else-if 必须**连续**（中间不许插任何别的元素）：
                   Vue 的 v-else-if 只认紧邻的上一个兄弟节点，此前那条「七层入口不可用」的
                   <div v-if> 插在中间，把链从这里截断了——于是 v-else-if 挂到了那个 div 上，
                   一个**可访问**的隧道类应用会同时画出「接入地址」和「申请权限」两个按钮
                   （给已经有权限的人一个申请入口，点下去后端还会以「无需申请」400 顶回来）。
                   告警文案改挂在整条链之后，它本来也只是补充说明、不参与状态分支。 -->
              <button
                v-if="app.accessible"
                class="bd-tile__btn"
                :disabled="opening === app.id || (browserOpenable(app) && !webProxy.ready)"
                :title="browserOpenable(app) && !webProxy.ready ? webProxy.note : ''"
                @click="openApp(app)"
              ><icon-link />{{ opening === app.id ? '正在打开…' : (browserOpenable(app) ? '访问' : '接入地址') }}</button>
              <button
                v-else-if="app.degraded"
                class="bd-tile__btn bd-tile__btn--ghost"
                disabled
                title="终端环境不合规，已暂停高敏资源访问。修复后重新上报即自动恢复（申请审批在此状态下无效）"
              ><icon-exclamation-circle-fill />请先修复终端</button>
              <!-- 结构性不可用：按钮必须点不动。给它一个「申请权限」会把人送进死路——
                   后端 JIT 闸会以「该应用不支持自助申请」400 拒掉，而用户无从知道为什么。
                   原因由服务端下发（两种成因文案不同，管理员要去改的栏也不同）。 -->
              <button
                v-else-if="app.unavailable"
                class="bd-tile__btn bd-tile__btn--ghost"
                disabled
                :title="app.unavailableReason"
              ><icon-exclamation-circle-fill />请联系管理员</button>
              <button
                v-else
                class="bd-tile__btn bd-tile__btn--ghost"
                @click="requestAccess(app)"
              ><icon-safe />申请权限</button>
              <!-- 七层入口不可用时当面说清原因：磁贴还在、按钮点不动，而不是点下去什么也没发生 -->
              <div v-if="app.accessible && browserOpenable(app) && !webProxy.ready" class="bd-tile__warn">
                <icon-exclamation-circle-fill />{{ webProxy.note }}
              </div>
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
        <!-- 不再一律写「高敏」：走到这个抽屉只说明「你当前没有这个资源的访问权」，
             它可能是高敏资源，也可能只是一条你不在授权名单里的普通资源。 -->
        <div>
          你当前<b>未获授权</b>访问<b>{{ reqApp?.sensitivity === 'high' ? '该高敏资源' : '该资源' }}</b>，
          需管理员审批。批准后你将获得<b>限时访问授予</b>，到期自动回收。
        </div>
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
import { api, clearToken, type PortalAppsResp, type PortalTile, type WebProxyStatus, type WebTicketResp } from '@/lib/api';
import PortalBar from '@/components/PortalBar.vue';

const router = useRouter();

const loading = ref(false);
const keyword = ref('');
const apps = ref<PortalTile[]>([]);
const displayName = ref('');
/** 七层 Web 代理入口状态（后端下发）。ready=false 时 Web 磁贴的「访问」按钮置灰并说明原因，
 *  而不是让人点下去才拿到一个一闪而过的错误提示。 */
const webProxy = ref<WebProxyStatus>({ ready: true, note: '' });
/** 正在取票的应用 id（避免连点重复签票）。 */
const opening = ref('');

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
// 「待申请」只数**真的能去申请**的那些：被降权的申请必然被否（降权否决压过 JIT 授予），
// 未关联受控资源的会被后端以「该应用不支持自助申请」拒掉。把这两类算进来，
// 这个数字就在替一批点不动的磁贴承诺「你还有 N 件事可做」——与磁贴上写的字自相矛盾。
const pendingCount = computed(() => apps.value.filter(a => !a.accessible && !a.degraded && !a.unavailable).length);

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

/** 该磁贴能不能在浏览器里直接打开：只有 Web 发布模式经七层代理，
 *  隧道 / 全网资源两种模式浏览器没有载体（前者要桌面客户端隧道）。 */
function browserOpenable(app: PortalTile) { return app.mode === 'web'; }

/**
 * 真正打开一个受保护业务。
 *
 * ★这里此前整个函数体就是一句 Message.success——磁贴点得动、什么也不会发生，
 * 是本项目"页面存在≠功能存在"最典型的一例。现在的流程是：
 *   控制面按资源鉴权 → 签一张 60s 一次性访问票据（use=web，绑定资源 id）
 *   → 浏览器跳到网关七层入口 → 网关验票换会话 Cookie → 逐请求重新鉴权后反代。
 *
 * 用 window.open 新开标签而不是当前页跳转：门户本身是这条链路的入口，
 * 被业务系统顶掉之后用户再打开第二个应用就得重新登录门户。
 */
async function openApp(app: PortalTile) {
  if (!browserOpenable(app)) {
    Message.info(`「${app.name}」是 ${modeMeta[app.mode].label}，浏览器无法直达，请用桌面客户端接入后访问 ${app.addr}`);
    return;
  }
  if (!webProxy.value.ready) { Message.warning(webProxy.value.note || '七层 Web 代理入口不可用'); return; }
  opening.value = app.id;
  try {
    const t = await api<WebTicketResp>('/portal/web-ticket', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ appId: app.id })
    });
    // 票据只有 60s 且一次性：拿到就立刻跳，不缓存、不放进任何可分享的地方。
    window.open(t.url, '_blank', 'noopener');
  } catch (e) {
    // 后端的拒绝理由（无授权 / 终端降级 / 网关没开七层）都写在 message 里，原样呈现——
    // 换成一句"打开失败"就等于把唯一的线索丢掉。
    Message.error(reason(e, '打开失败，请稍后再试'));
  } finally {
    opening.value = '';
  }
}

/** 从 api() 抛出的错误里取后端那句中文说明（形如 "403 终端环境不合规：…"）。 */
function reason(e: unknown, fallback: string) {
  const msg = String((e as Error)?.message ?? '').trim();
  const m = msg.match(/^\d{3}\s+(.+)$/s);
  return m ? m[1] : (msg || fallback);
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
    // 旧后端不下发 webProxy：按"可用"处理，点开时若真不可用会拿到后端的 503 原文。
    if (resp.webProxy) webProxy.value = resp.webProxy;
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
/* 终端降级：红而非金——它与"高敏需申请"是两回事，申请审批在这个状态下无效 */
.bd-tile__gold--deg { color: var(--bd-danger); background: var(--bd-tag-red-bg, rgba(245, 63, 63, .08)); }
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
.bd-tile__btn:disabled { background: var(--bd-fill-2); color: var(--bd-t4); box-shadow: none; cursor: not-allowed; }
.bd-tile__warn {
  display: flex; gap: 6px; margin-top: 8px; font-size: 11.5px; line-height: 1.55; color: var(--bd-warning);
}
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
