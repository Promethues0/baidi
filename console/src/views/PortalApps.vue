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
                <!-- ★三种"不可访问"必须分开说，用户的下一步动作完全不同：降权 → 先修终端
                     （申请无效，降权否决压过 JIT 授予）；未关联资源 → 找管理员（申请会被后端以
                     「不支持自助申请」拒掉）；未授权 → 走自助申请。徽标不许写死「高敏」：
                     普通资源没授权同样进不去，已授权的高敏资源则能直接访问。 -->
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
              <!-- ★这一串 v-if/v-else-if 必须连续，中间不许插任何元素：v-else-if 只认紧邻的
                   上一个兄弟节点，链一断就会让已授权的应用同时画出「访问」和「申请权限」
                   两个按钮。补充说明性的提示一律挂在整条链之后。 -->
              <button
                v-if="app.accessible"
                class="bd-tile__btn"
                :disabled="opening === app.id || webBlocked(app)"
                :title="webBlocked(app) ? webBlockNote(app) : ''"
                @click="openApp(app)"
              ><icon-link />{{ opening === app.id ? '正在打开…' : openLabel(app) }}</button>
              <!-- 续期（PRD FR-AUTH-03/04）。★只在服务端说可以续时出现：renewable 的判据与
                   store.CreateAccessRequest 的放行条件同源（剩余 ≤ RenewWindowMinutes），
                   早于窗口点它必然 409。 -->
              <button
                v-if="app.accessible && app.renewable"
                class="bd-tile__btn bd-tile__btn--ghost"
                @click="requestAccess(app, true)"
              ><icon-history />续期</button>
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
              <div v-if="app.accessible && app.grantExpiresAt" class="bd-tile__exp" :class="{ soon: app.renewable }">
                <icon-clock-circle />临时授权剩余 {{ remainText(app.grantExpiresAt) }}
              </div>
              <!-- 七层入口不可用时当面说清原因：磁贴还在、按钮点不动，而不是点下去什么也没发生 -->
              <div v-if="app.accessible && webBlocked(app)" class="bd-tile__warn">
                <icon-exclamation-circle-fill />{{ webBlockNote(app) }}
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
    <a-modal v-model:visible="reqOpen" :title="`${reqRenew ? '续期' : '申请访问'}「${reqApp?.name ?? ''}」`" :width="480"
      :ok-loading="submitting" @ok="submitRequest" ok-text="提交申请" cancel-text="取消">
      <div class="bd-reqtip">
        <icon-safe class="bd-reqtip__ic" />
        <!-- 文案按 sensitivity 分档，不许一律写「高敏」：走到这个抽屉只说明当前没有该资源的
             访问权，它可能只是一条你不在授权名单里的普通资源。 -->
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
import { api, clearToken, type PortalAppsResp, type PortalTile, type WebProxyStatus, type WebTicketResp, failReason, failStatus } from '@/lib/api';
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
  // ★「直连书签」的名字在向导 / 门户 / 移动端三处必须一致：这类应用不经网关、不进隧道
  // 路由、不做鉴权，剖面与门户直接给 accessible: true，任何叫得像"受控"的名字都是误导。
  global: { label: '直连书签', icon: 'icon-public' }
};

const avatarText = computed(() => (displayName.value || '·').slice(0, 1).toUpperCase());
const accessibleCount = computed(() => apps.value.filter(a => a.accessible).length);
// ★「待申请」只数真的能去申请的：被降权的必然被否（降权否决压过 JIT 授予），未关联受控
// 资源的会被后端以「不支持自助申请」拒掉——算进来就是替点不动的磁贴承诺「还有 N 件事可做」。
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

/** 该磁贴能不能在浏览器里直接打开。
 *
 *  - web：经七层代理（换票 → 跳网关入口）；
 *  - global：**直连书签**，地址是完整 URL 时直接开新标签（它本来就不经白帝任何通道）；
 *  - tunnel：浏览器没有载体，要桌面客户端。 */
function browserOpenable(app: PortalTile) { return app.mode === 'web'; }
/** 这个磁贴的七层入口此刻能不能点。
 *  ★必须逐磁贴判：资源级 webEntry 只对它自己生效，而服务端那份全局结论是用空资源算的，
 *  拿它判会把已配好 webEntry 的应用一起置灰——票其实签得出，用户照做了却点不动。
 *  旧后端不下发 app.web 时回落到全局字段。 */
function webBlocked(app: PortalTile) {
  if (!browserOpenable(app)) return false;
  return app.web ? !app.web.ready : !webProxy.value.ready;
}
/** 点不动的原因：逐磁贴那句优先（它才是这个应用真正会撞上的那句）。 */
function webBlockNote(app: PortalTile) {
  return (app.web ? app.web.note : webProxy.value.note) || '七层 Web 代理入口不可用';
}
/** 按钮文案要与点下去真正会发生的事一致：
 *  web=经七层代理访问 / global=直接开新标签（或只显示地址）/ tunnel=要客户端。 */
function openLabel(app: PortalTile) {
  if (app.mode === 'global') return bookmarkURL(app) ? '打开链接' : '查看地址';
  return browserOpenable(app) ? '访问' : '接入地址';
}
/** 直连书签的地址是不是一个能直接打开的 URL（泛域名 *.x.com 不是）。 */
function bookmarkURL(app: PortalTile): string {
  const a = (app.addr || '').trim();
  if (app.mode !== 'global' || !a || a.includes('*')) return '';
  return /^https?:\/\//i.test(a) ? a : 'https://' + a;
}

/**
 * 真正打开一个受保护业务：控制面按资源鉴权 → 签一张 60s 一次性访问票据（use=web，绑定
 * 资源 id）→ 浏览器跳网关七层入口 → 网关验票换会话 Cookie → 逐请求重新鉴权后反代。
 *
 * ★用 window.open 新开标签而不是当前页跳转：门户本身是这条链路的入口，被业务系统顶掉
 * 之后用户再开第二个应用就得重新登录门户。
 */
async function openApp(app: PortalTile) {
  // ★直连书签不经白帝任何通道，能拼出 URL 就直接开——绝不能提示「请用客户端接入后访问」，
  // 它不走隧道，接入了也帮不上忙，等于把用户指去一条不存在的路。
  if (app.mode === 'global') {
    const u = bookmarkURL(app);
    if (u) { window.open(u, '_blank', 'noopener'); return; }
    Message.info(`「${app.name}」是直连书签（不经白帝通道，也不受访问控制），请直接访问：${app.addr}`);
    return;
  }
  if (!browserOpenable(app)) {
    Message.info(`「${app.name}」是 ${modeMeta[app.mode].label}，浏览器无法直达，请用桌面客户端接入后访问 ${app.addr}`);
    return;
  }
  if (webBlocked(app)) { Message.warning(webBlockNote(app)); return; }
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
    Message.error(`打开失败：${failReason(e)}`);
  } finally {
    opening.value = '';
  }
}

/** 从 api() 抛出的错误里取后端那句中文说明（形如 "403 终端环境不合规：…"）。 */
/** 剩余时长的人话（服务端下发的是 Unix 秒）。 */
function remainText(exp: number): string {
  const s = Math.max(0, exp - Math.floor(Date.now() / 1000));
  if (s < 60) return `${s} 秒`;
  const m = Math.floor(s / 60);
  return m < 60 ? `${m} 分钟` : `${Math.floor(m / 60)} 小时 ${m % 60} 分钟`;
}

const reqRenew = ref(false);
function requestAccess(app: PortalTile, renew = false) {
  reqApp.value = app;
  reqRenew.value = renew;
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
    Message.success(reqRenew.value
      ? `「${app.name}」续期申请已提交，等待管理员审批；批准后在现有授权上延长，访问不会中断`
      : `「${app.name}」访问申请已提交，等待管理员审批`);
  } catch (e) {
    // 无后端 / 重复申请等：不白屏，提示即可（HTTP 409 = 已有待审批或有效授予）
    Message.error(failStatus(e) === 409 ? '你已有待审批的申请或有效授予，请勿重复提交' : `申请提交失败：${failReason(e)}`);
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
  } catch (e) {
    Message.error(`应用列表加载失败：${failReason(e)}`);
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
.bd-tile__exp { display: flex; align-items: center; gap: 4px; margin-top: 7px;
  font-size: 11.5px; color: var(--bd-t3); }
.bd-tile__exp.soon { color: var(--bd-warning); }
</style>
