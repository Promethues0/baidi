<template>
  <div class="bd-portal">
    <!-- 顶部细 bar：账号徽章由 PortalBar 画，「退出」放它右边 -->
    <PortalBar title="白帝 · 应用门户" :user="displayName">
      <button class="bd-pquit" @click="router.push('/portal/requests')">
        <icon-history /><span>我的申请</span>
      </button>
      <button class="bd-pquit" @click="router.push('/portal/security')">
        <icon-safe /><span>我的安全</span>
      </button>
      <button class="bd-pquit" @click="router.push('/portal/downloads')">
        <icon-download /><span>下载客户端</span>
      </button>
      <template #after>
        <button class="bd-pquit" @click="logout"><icon-export /><span>退出</span></button>
      </template>
    </PortalBar>

    <!-- 主体 -->
    <main class="bd-pmain">
      <div class="bd-pwrap">
        <!-- 欢迎语 + 搜索 -->
        <div class="bd-phead">
          <div class="bd-phead__l">
            <h1 class="bd-phead__hi">你好，{{ displayName }}</h1>
            <!-- ★两个计数是三态的：列表还没回来 / 读取失败时它们是「不可判定」，画成 0 就是在断言
                 「你一个应用都没有权限」——而那正是读取失败时用户最不该被告知的事。不可判定时
                 加全局 .bd-unknown（灰、细），不让「—」穿着主色粗体长得像一个数。 -->
            <p class="bd-phead__sub">
              可访问 <b :class="{ 'bd-unknown': !countsKnown }">{{ accessibleText }}</b> 个应用
              <span class="bd-dot">·</span>
              <i :class="{ 'bd-unknown': !countsKnown }">{{ pendingText }}</i> 个待申请
            </p>
          </div>
          <!-- ★从 a-input allow-clear 换成裸 <input> 时丢了一键清空——这里补回一个真 <button>：
               有关键词才出现（空框上一个"清空"是装饰）、可 Tab、有 aria-label（图标按钮没有可读文本），
               点它清词并把焦点还给输入框（键盘用户清完通常要接着输）。 -->
          <div class="bd-searchbox bd-psearch">
            <icon-search />
            <input ref="searchInput" v-model="keyword" class="bd-searchbox__in" placeholder="搜索应用名称或地址…" />
            <button
              v-if="keyword"
              type="button"
              class="bd-psearch__clear"
              aria-label="清空搜索"
              title="清空搜索"
              @click="clearKeyword"
            ><icon-close /></button>
          </div>
        </div>

        <!-- 首屏骨架：第一次 load() 回来之前不画空态（「暂无可用应用」在这一刻是一句没有依据的断言） -->
        <div v-if="!loaded" class="bd-grid">
          <div v-for="i in 6" :key="i" class="bd-card"><SkeletonBlock kind="card" :rows="3" /></div>
        </div>

        <!-- 应用磁贴网格 -->
        <a-spin v-else :loading="loading" class="bd-pspin">
          <!-- ★读取失败必须排在一切空态之前，且是常驻的：此前失败只弹一条 3 秒就消失的 toast，
               屏幕上留下的常驻状态却是「暂无可用应用 / 请联系管理员为你授权应用访问」——控制面
               5xx 时终端用户会照着去找管理员要授权，而不是等控制面恢复。这里转述后端原话
               （failReason），并给一个真能重新拉列表的「重试」。 -->
          <div v-if="loadErr" class="bd-card">
            <EmptyState
              size="lg"
              tone="danger"
              title="应用列表未读取"
              :desc="`${loadErr}——这里显示的不是「没有可用应用」，你的授权情况尚未读到；请稍后重试`"
            >
              <template #action>
                <button class="bd-btn bd-btn--ghost" :disabled="loading" @click="load"><icon-refresh />重试</button>
              </template>
            </EmptyState>
          </div>
          <div v-else-if="filtered.length" class="bd-grid">
            <div v-for="app in filtered" :key="app.id" class="bd-card bd-card--hover bd-tile">
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
                  class="bd-tg bd-tg--red bd-tile__flag"
                ><icon-exclamation-circle-fill />终端降级 · 暂停访问</span>
                <span
                  v-else-if="app.unavailable"
                  class="bd-tg bd-tg--red bd-tile__flag"
                  :title="app.unavailableReason"
                ><icon-exclamation-circle-fill />配置缺口 · 不可用</span>
                <span
                  v-else-if="!app.accessible"
                  class="bd-tg bd-tg--gold bd-tile__flag"
                >
                  <icon-lock />{{ app.sensitivity === 'high' ? '高敏 · 需申请' : '未授权 · 可申请' }}
                </span>
              </div>
              <div class="bd-tile__name">{{ app.name }}</div>
              <div class="bd-tile__addr bd-mono">{{ app.addr }}</div>
              <div class="bd-tile__meta">
                <span class="bd-tg" :class="'bd-tg--' + modeMeta[app.mode].tag">{{ modeMeta[app.mode].label }}</span>
              </div>
              <!-- ★这一串 v-if/v-else-if 必须是**一条**链，中间不许插任何元素、也不许另起
                   一个 v-if：v-else-if 只认紧邻的上一个兄弟节点。此前「续期」写成了独立的
                   `v-if="accessible && renewable"`，等于在「访问」后面开了第二条链——它的
                   v-else 对「已授权但不可续期」照样命中，于是 OA / Git / 直连书签这几张
                   已授权磁贴同时画出「访问」和「申请权限」（后者点下去会被后端以「无需申请」
                   顶回来）。现在「访问 + 续期」收进同一个 <template v-if> 分支里。
                   补充说明性的提示一律挂在整条链之后。

                   ★四个分支互斥有后端保证（control/internal/api/subjects.go appAccessState）：
                   Accessible = accessibleFor(…, degraded)，而 accessibleFor 在
                   `degraded && HighSensitivity()` 时直接回 false；Degraded 恰好也等于
                   `degraded && HighSensitivity()`——所以 degraded ⇒ !accessible。
                   Unavailable 只在两条提前 return 的分支里置 true，那两处 Accessible 是零值
                   false——所以 unavailable ⇒ !accessible。因此「accessible 排最前」不会
                   压掉任何降权 / 不可用磁贴。 -->
              <template v-if="app.accessible">
                <button
                  class="bd-btn bd-tile__btn"
                  :disabled="opening === app.id || webBlocked(app)"
                  :title="webBlocked(app) ? webBlockNote(app) : ''"
                  @click="openApp(app)"
                ><icon-link />{{ opening === app.id ? '正在打开…' : openLabel(app) }}</button>
                <!-- 续期（PRD FR-AUTH-03/04）。★只在服务端说可以续时出现：renewable 的判据与
                     store.CreateAccessRequest 的放行条件同源（剩余 ≤ RenewWindowMinutes），
                     早于窗口点它必然 409。 -->
                <button
                  v-if="app.renewable"
                  class="bd-btn bd-btn--ghost bd-tile__btn"
                  @click="requestAccess(app, true)"
                ><icon-history />续期</button>
              </template>
              <!-- ★禁用按钮的解释不能只放 title：disabled 的 <button> 键盘聚焦不到、触屏没有 hover，
                   两类用户都读不到那句话。解释另画成下面那行可见的 .bd-tile__warn（与 webBlocked 同款），
                   title 保留给鼠标用户，并用 aria-describedby 把两者接起来。文案只有一份（DEGRADED_NOTE）。 -->
              <button
                v-else-if="app.degraded"
                class="bd-btn bd-btn--ghost bd-tile__btn"
                disabled
                :title="DEGRADED_NOTE"
                :aria-describedby="noteId(app)"
              ><icon-exclamation-circle-fill />请先修复终端</button>
              <!-- 结构性不可用：按钮必须点不动。给它一个「申请权限」会把人送进死路——
                   后端 JIT 闸会以「该应用不支持自助申请」400 拒掉，而用户无从知道为什么。
                   原因由服务端下发（两种成因文案不同，管理员要去改的栏也不同）。 -->
              <button
                v-else-if="app.unavailable"
                class="bd-btn bd-btn--ghost bd-tile__btn"
                disabled
                :title="unavailableNote(app)"
                :aria-describedby="noteId(app)"
              ><icon-exclamation-circle-fill />请联系管理员</button>
              <button
                v-else
                class="bd-btn bd-btn--ghost bd-tile__btn"
                @click="requestAccess(app)"
              ><icon-safe />申请权限</button>
              <div v-if="app.accessible && app.grantExpiresAt" class="bd-tile__exp" :class="{ soon: app.renewable }">
                <icon-clock-circle />临时授权剩余 {{ remainText(app.grantExpiresAt) }}
              </div>
              <!-- 按钮点不动的原因当面写出来（三种处境互斥，一条链）：
                   七层入口不可用 → 磁贴还在、按钮点不动，而不是点下去什么也没发生；
                   终端降级 → 该做的是修终端，不是去申请（申请在此状态下无效）；
                   配置缺口 → 拿着后端那句原因去找管理员（两种成因要改的栏不同）。
                   后两条是 disabled 按钮 title 里那句的可见版，id 供按钮 aria-describedby 引用。 -->
              <div v-if="app.accessible && webBlocked(app)" class="bd-tile__warn">
                <icon-exclamation-circle-fill />{{ webBlockNote(app) }}
              </div>
              <div v-else-if="app.degraded" :id="noteId(app)" class="bd-tile__warn bd-tile__warn--danger">
                <icon-exclamation-circle-fill />{{ DEGRADED_NOTE }}
              </div>
              <div v-else-if="app.unavailable" :id="noteId(app)" class="bd-tile__warn bd-tile__warn--danger">
                <icon-exclamation-circle-fill />{{ unavailableNote(app) }}
              </div>
            </div>
          </div>

          <!-- 空态：搜索无命中 / 确实没有可用应用，两者下一步动作不同 -->
          <div v-else-if="!loading" class="bd-card">
            <EmptyState v-if="keyword" size="lg" title="没有匹配的应用" desc="换个关键词试试" />
            <EmptyState v-else size="lg" title="暂无可用应用" desc="请联系管理员为你授权应用访问">
              <template #icon><icon-apps /></template>
            </EmptyState>
          </div>
        </a-spin>
      </div>
    </main>

    <!-- JIT 访问申请 -->
    <a-modal v-model:visible="reqOpen" :title="`${reqRenew ? '续期' : '申请访问'}「${reqApp?.name ?? ''}」`" :width="480"
      :ok-loading="submitting" @ok="submitRequest" ok-text="提交申请" cancel-text="取消">
      <div class="bd-notice">
        <icon-safe />
        <!-- 文案按 sensitivity 分档，不许一律写「高敏」：走到这个抽屉只说明当前没有该资源的
             访问权，它可能只是一条你不在授权名单里的普通资源。 -->
        <span>
          你当前<b>未获授权</b>访问<b>{{ reqApp?.sensitivity === 'high' ? '该高敏资源' : '该资源' }}</b>，
          需管理员审批。批准后你将获得<b>限时访问授予</b>，到期自动回收。
        </span>
      </div>
      <div class="bd-fld">
        <label>期望时长（分钟）</label>
        <div class="bd-req__ttl">
          <a-input-number v-model="reqTtl" :min="15" :max="480" :step="15" />
          <span class="bd-fld__d">15–480 分钟</span>
        </div>
      </div>
      <div class="bd-fld">
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
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

const router = useRouter();

const loading = ref(false);
/** 首屏是否已完成第一次 load()：只决定骨架屏何时让位（成功 / 失败都算完成），不改任何数据流。 */
const loaded = ref(false);
/** 最近一次 load() 失败的后端原话（failReason）；空串 = 上一次读取成功。
 *  ★它是常驻状态，不是 toast：失败时磁贴区画 tone=danger 的空态并转述这句话，
 *  头部两个计数退成「—」。成功那次必须清空（Apps.vue 同款）。 */
const loadErr = ref('');
const keyword = ref('');
const searchInput = ref<HTMLInputElement | null>(null);
/** 一键清空搜索词，并把焦点还给输入框（清空按钮随词消失，焦点若留在它上面会掉到 body）。 */
function clearKeyword() {
  keyword.value = '';
  searchInput.value?.focus();
}
const apps = ref<PortalTile[]>([]);

/** 终端降级磁贴的解释——按钮 title 与可见说明行共用这一句，别写成两份会漂移的文案。
 *  语义与后端一致：degraded = 风险引擎判 degrade，只摘掉高敏资源、不断连（CLAUDE.md「风险四档」），
 *  下一次 posture 上报判回 allow 即恢复，期间的 JIT 审批被 DenyUsers 否决压过。 */
const DEGRADED_NOTE = '终端环境不合规，已暂停高敏资源访问。修复后重新上报即自动恢复（申请审批在此状态下无效）';
/** 结构性不可用的解释：优先用服务端下发的那句原因（用户要拿它去找管理员）。
 *  ★字段缺席（旧后端 / 字段没带）时不许替后端编一个原因——如实说"原因未下发"，
 *  让人去找管理员核对，而不是照着一句猜的话去改错的栏。 */
function unavailableNote(app: PortalTile) {
  return app.unavailableReason || '该应用当前不可用，服务端未下发具体原因；请联系管理员核对它的资源关联与后端地址';
}
/** 说明行的 DOM id（供禁用按钮 aria-describedby 引用）。app.id 在一页里唯一。 */
function noteId(app: PortalTile) { return `bd-tile-note-${app.id}`; }
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

/* tag 是 .bd-tg 的颜色变体名（隧道紫 / Web 蓝 / 直连书签绿），与磁贴图标底色同一族。 */
const modeMeta: Record<PortalTile['mode'], { label: string; icon: string; tag: 'purple' | 'blue' | 'green' }> = {
  tunnel: { label: '隧道代理', icon: 'icon-swap', tag: 'purple' },
  web:    { label: 'Web 应用', icon: 'icon-common', tag: 'blue' },
  // ★「直连书签」的名字在向导 / 门户 / 移动端三处必须一致：这类应用不经网关、不进隧道
  // 路由、不做鉴权，剖面与门户直接给 accessible: true，任何叫得像"受控"的名字都是误导。
  global: { label: '直连书签', icon: 'icon-public', tag: 'green' }
};
const accessibleCount = computed(() => apps.value.filter(a => a.accessible).length);
// ★「待申请」只数真的能去申请的：被降权的必然被否（降权否决压过 JIT 授予），未关联受控
// 资源的会被后端以「不支持自助申请」拒掉——算进来就是替点不动的磁贴承诺「还有 N 件事可做」。
const pendingCount = computed(() => apps.value.filter(a => !a.accessible && !a.degraded && !a.unavailable).length);
/** 头部计数的三态渲染：首屏未回 / 读取失败 → 「—」（不可判定），否则才是真实计数。
 *  apps 在这两种情形下都是 []，直接渲染 accessibleCount 会画出一个言之凿凿的 0。 */
const countsKnown = computed(() => loaded.value && !loadErr.value);
const accessibleText = computed(() => (countsKnown.value ? String(accessibleCount.value) : '—'));
const pendingText = computed(() => (countsKnown.value ? String(pendingCount.value) : '—'));

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
    // 成功必须清掉上一次的失败原话：「重试」会再次走到这里，留着的话磁贴区仍是 danger 空态。
    loadErr.value = '';
  } catch (e) {
    // 常驻态 + toast 同源同句：toast 负责当下引起注意，loadErr 负责 3 秒后屏幕上留下的仍是真话。
    loadErr.value = failReason(e);
    Message.error(`应用列表加载失败：${failReason(e)}`);
  } finally {
    loading.value = false;
    loaded.value = true;
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
/* 本页独有：磁贴网格与磁贴内部。门户壳（.bd-portal / .bd-pmain / .bd-pwrap / .bd-phead / .bd-pquit）在 PortalBar.vue。 */
.bd-psearch { width: 300px; max-width: 100%; }
/* 搜索框里的清空按钮：与搜索图标同色同号，hover 提亮；焦点环走全局 :focus-visible。
   尺寸取 --bd-sp-5（20）：比 32 高的框留出上下各 6px，不把框撑高。 */
.bd-psearch__clear {
  flex: none; display: inline-flex; align-items: center; justify-content: center;
  width: var(--bd-sp-5); height: var(--bd-sp-5); padding: 0; border: 0; border-radius: var(--bd-radius-xs);
  background: transparent; color: var(--bd-t3); cursor: pointer; font: inherit;
  transition: color var(--bd-dur-fast) var(--bd-ease), background var(--bd-dur-fast) var(--bd-ease);
}
.bd-psearch__clear:hover { color: var(--bd-t2); background: var(--bd-fill-2); }
.bd-pspin { display: block; }

/* 磁贴网格 */
.bd-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: var(--bd-sp-4); }
.bd-tile { padding: var(--bd-sp-5); display: flex; flex-direction: column; }
.bd-tile__top { display: flex; align-items: flex-start; justify-content: space-between; gap: var(--bd-sp-2); margin-bottom: var(--bd-sp-4); }
.bd-tile__icon {
  width: 46px; height: 46px; border-radius: var(--bd-radius); flex: none;
  display: flex; align-items: center; justify-content: center; font-size: 22px;
}
.bd-tile__icon.m-tunnel { background: var(--bd-tag-purple-bg); color: var(--bd-purple); }
.bd-tile__icon.m-web    { background: var(--bd-tag-blue-bg);   color: var(--bd-primary); }
.bd-tile__icon.m-global { background: var(--bd-tag-green-bg);  color: var(--bd-success); }
/* 右上角状态徽标：复用 .bd-tg 的色族，只加图标间距 */
.bd-tile__flag { display: inline-flex; align-items: center; gap: 4px; font-weight: 600; padding: 3px 8px; }
.bd-tile__name { font-size: var(--bd-fs-lg); font-weight: 600; color: var(--bd-t1); line-height: var(--bd-lh-tight); }
.bd-tile__addr { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin-top: 6px; word-break: break-all; }
.bd-tile__meta { margin-top: var(--bd-sp-3); }
/* 磁贴主按钮：全局 .bd-btn 的整宽变体 */
.bd-tile__btn { margin-top: var(--bd-sp-4); width: 100%; }
.bd-tile__btn + .bd-tile__btn { margin-top: var(--bd-sp-2); }
.bd-tile__warn { display: flex; gap: 6px; margin-top: var(--bd-sp-2); font-size: var(--bd-fs-xs); line-height: var(--bd-lh); color: var(--bd-warning-t); }
/* 降级 / 配置缺口那两行跟随磁贴右上角红色徽标的语义色（同族 danger-t），与七层入口的 warning 分得开 */
.bd-tile__warn--danger { color: var(--bd-danger-t); }
.bd-tile__exp { display: flex; align-items: center; gap: 4px; margin-top: 7px; font-size: var(--bd-fs-xs); color: var(--bd-t3); }
.bd-tile__exp.soon { color: var(--bd-warning); }

/* 申请弹窗 */
.bd-req__ttl { display: flex; align-items: center; gap: 10px; }
.bd-req__ttl :deep(.arco-input-number) { width: 160px; }
.bd-req__ttl .bd-fld__d { margin-top: 0; }
</style>
