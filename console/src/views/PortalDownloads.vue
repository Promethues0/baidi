<template>
  <div class="bd-portal">
    <!-- 顶部细 bar（与应用门户同构） -->
    <PortalBar title="白帝 · 客户端下载">
      <button class="bd-pquit" @click="goBack"><icon-left /><span>返回</span></button>
    </PortalBar>

    <main class="bd-pmain bd-pmain--dl">
      <div class="bd-pwrap">
        <!-- 加载态：骨架而不是一句「正在获取」——首屏不闪白 -->
        <template v-if="loading">
          <div class="bd-hero bd-hero--sk"><SkeletonBlock kind="stat" /></div>
          <div class="bd-section-title">全部平台</div>
          <div class="bd-grid">
            <div v-for="i in 6" :key="i" class="bd-card"><SkeletonBlock kind="card" :rows="3" /></div>
          </div>
        </template>

        <!-- 错误态（持久，非一次性 toast；可重试）。说明栏转述后端原话，与 toast 同源。 -->
        <div v-else-if="failed" class="bd-card">
          <EmptyState size="lg" tone="danger" title="下载清单获取失败，请稍后重试" :desc="failMsg">
            <template #action><button class="bd-btn bd-btn--ghost" @click="load"><icon-refresh /> 重试</button></template>
          </EmptyState>
        </div>

        <template v-else>
          <!-- 推荐下载（按访问端识别） -->
          <section v-if="recommended" class="bd-hero">
            <div class="bd-hero__txt">
              <p class="bd-hero__kicker">为你推荐 · 已识别当前设备</p>
              <h1 class="bd-hero__title">{{ recommended.label }}</h1>
              <p class="bd-hero__meta">
                <template v-if="recommended.available">
                  版本 {{ recommended.version }}
                  <template v-if="recommended.arch"> · {{ recommended.arch }}</template>
                  · {{ fmtSize(recommended.size) }}
                </template>
                <!-- ★兜底文案刻意不许诺任何"正在构建 / 即将到来"：没有包时该说什么由后端
                     placeholderManifest / build-artifacts.sh 两处逐字一致的 note 决定（它说的是
                     此刻的真实缺口与下一步找谁）。前端拿不到 note 时并不知道原因，不该替它编一个。 -->
                <template v-else>{{ recommended.note || '暂无安装包，请联系管理员' }}</template>
              </p>
              <button v-if="recommended.available" class="bd-btn bd-hero__btn" @click="download(recommended)">
                <icon-download /> 立即下载
              </button>
            </div>
          </section>

          <!-- 全平台栅格 -->
          <h2 class="bd-section-title">全部平台</h2>
          <div class="bd-grid">
            <article v-for="c in clients" :key="c.platform" class="bd-card bd-dtile" :class="{ 'bd-dtile--off': !c.available }">
              <header class="bd-dtile__head">
                <span class="bd-dtile__icon"><component :is="platformIcon(c.platform)" /></span>
                <div>
                  <h3 class="bd-dtile__name">{{ c.label }}</h3>
                  <!-- 同上：note 缺席时不替后端许诺一个可能不会到来的版本 -->
                  <p class="bd-dtile__arch">{{ c.available ? (c.arch || '') : (c.note || '暂无安装包，请联系管理员') }}</p>
                </div>
              </header>
              <template v-if="c.available">
                <dl class="bd-dtile__meta">
                  <div><dt>版本</dt><dd>{{ c.version }}</dd></div>
                  <div><dt>大小</dt><dd>{{ fmtSize(c.size) }}</dd></div>
                  <div class="bd-dtile__sha">
                    <dt>SHA256</dt>
                    <dd class="bd-mono" :title="c.sha256">{{ shortSha(c.sha256) }}
                      <button class="bd-copybtn" title="复制完整校验值" aria-label="复制完整 SHA256 校验值" @click="copySha(c.sha256)"><icon-copy /></button>
                    </dd>
                  </div>
                </dl>
                <p v-if="c.note" class="bd-dtile__note">{{ c.note }}</p>
                <!-- 构建溯源：包比源码旧 / 无法判断新旧都必须当面说，不说的话用户拿到的是一个
                     看起来正常的旧包。★两种状态颜色分开：过期是确定的坏消息（红），不可判定
                     是「我们不知道」（黄），混成一句话两个方向都会被读错。 -->
                <p v-if="c.stale" class="bd-notice bd-notice--danger bd-dtile__prov">
                  <icon-exclamation-circle-fill /><span>{{ c.staleReason }}</span>
                </p>
                <p v-else-if="c.provenanceUnknown" class="bd-notice bd-notice--warn bd-dtile__prov">
                  <icon-question-circle-fill /><span>{{ c.staleReason }}</span>
                </p>
                <p v-if="c.builtAt" class="bd-dtile__built bd-mono">
                  构建于 {{ fmtBuilt(c.builtAt) }}<template v-if="c.sourceCommit"> · 源码 {{ c.sourceCommit }}</template>
                </p>
                <div class="bd-dtile__act">
                  <button class="bd-btn" @click="download(c)"><icon-download /> 下载</button>
                  <div v-if="c.platform === 'android'" class="bd-qr">
                    <img v-if="qr" :src="qr" alt="扫码下载 Android 客户端" width="84" height="84" />
                    <span v-else class="bd-mono bd-qr__fallback">{{ fileUrl(c) }}</span>
                    <span class="bd-qr__cap">手机扫码直接下载</span>
                  </div>
                </div>
              </template>
              <template v-else>
                <div class="bd-dtile__act">
                  <button class="bd-btn bd-btn--ghost" disabled>暂未提供</button>
                </div>
              </template>
            </article>
          </div>

          <p class="bd-foot">
            安装包由控制中心统一分发，下载后请核对 SHA256 校验值。iOS / 鸿蒙分发请联系管理员。
          </p>
        </template>
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import QRCode from 'qrcode';
import { Message } from '@arco-design/web-vue';
import { api, getToken, type ClientDownload, type DownloadsResp, failReason } from '@/lib/api';
import { IconDesktop, IconMobile } from '@arco-design/web-vue/es/icon';
import PortalBar from '@/components/PortalBar.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

const router = useRouter();
const clients = ref<ClientDownload[]>([]);
const qr = ref('');
const loading = ref(true);
const failed = ref(false);
/** 读取失败时后端那句原话：与 toast 同源，持久显示在错误态里（toast 三秒就没了）。 */
const failMsg = ref('');

function detectPlatform(): string {
  const ua = navigator.userAgent;
  if (/HarmonyOS|OpenHarmony/i.test(ua)) return 'harmony';
  if (/Android/i.test(ua)) return 'android';
  if (/iPhone|iPad|iPod/.test(ua)) return 'ios';
  if (/Windows/i.test(ua)) return 'windows';
  if (/Macintosh|Mac OS X/.test(ua)) return 'macos';
  if (/Linux/i.test(ua)) return 'linux';
  return 'macos';
}

const recommended = computed(() => clients.value.find((c) => c.platform === detectPlatform()));

function platformIcon(p: string) {
  return p === 'android' || p === 'ios' || p === 'harmony' ? IconMobile : IconDesktop;
}

function fileUrl(c: ClientDownload): string {
  return `${location.origin}/downloads/${encodeURIComponent(c.file || '')}`;
}

function download(c: ClientDownload) {
  if (!c.file) return;
  window.location.href = `/downloads/${encodeURIComponent(c.file)}`;
}

function fmtSize(n?: number): string {
  if (!n) return '—';
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(1)} GB`;
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(n / 1024))} KB`;
}

/** 构建时间按本地时区显示；解析不了就原样回显（绝不显示一个编造的时间）。 */
function fmtBuilt(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString('zh-CN', { hour12: false });
}

function shortSha(s?: string): string {
  return s ? `${s.slice(0, 8)}…${s.slice(-8)}` : '—';
}

async function copySha(s?: string) {
  if (!s) return;
  try {
    await navigator.clipboard.writeText(s);
    Message.success('SHA256 已复制');
  } catch {
    Message.error('复制失败，请手动复制完整校验值');
  }
}

function goBack() {
  router.push(getToken() ? '/portal/apps' : '/portal/login');
}

async function load() {
  loading.value = true;
  failed.value = false;
  try {
    const resp = await api<DownloadsResp>('/portal/downloads');
    clients.value = resp.clients;
    qr.value = '';
    const android = resp.clients.find((c) => c.platform === 'android' && c.available && c.file);
    if (android) {
      try {
        qr.value = await QRCode.toDataURL(fileUrl(android), { width: 168, margin: 1 });
      } catch {
        qr.value = ''; // 降级显示纯 URL 文本
      }
    }
  } catch (e) {
    failed.value = true;
    failMsg.value = failReason(e);
    Message.error(`下载清单获取失败：${failReason(e)}`);
  } finally {
    loading.value = false;
  }
}

onMounted(load);
</script>

<style scoped>
/* 本页独有：推荐横幅（品牌深色）与平台磁贴内部。门户壳在 PortalBar.vue；卡片 / 按钮 / 提示条 / 空态 / 骨架是全局或共享件。 */
.bd-pmain--dl { padding-top: var(--bd-sp-6); }
.bd-hero {
  background: linear-gradient(135deg, var(--bd-dark-1), var(--bd-dark-2));
  /* 深色渐变底上的文字用 --bd-on-color（"实底上的字"），不是 --bd-bg-1（那是白底本身）。 */
  border-radius: var(--bd-radius); padding: var(--bd-sp-7) var(--bd-sp-7); color: var(--bd-on-color); margin-bottom: var(--bd-sp-7);
}
.bd-hero--sk { padding: var(--bd-sp-3); }
.bd-hero__kicker { font-size: var(--bd-fs-sm); color: var(--bd-dark-txt); margin: 0 0 var(--bd-sp-2); }
.bd-hero__title { font-size: 24px; font-weight: 700; margin: 0 0 var(--bd-sp-2); line-height: var(--bd-lh-tight); }
.bd-hero__meta { font-size: var(--bd-fs-md); color: var(--bd-dark-txt); margin: 0 0 var(--bd-sp-4); line-height: var(--bd-lh); }
.bd-hero__btn { height: 38px; padding: 0 var(--bd-sp-5); font-size: var(--bd-fs-base); }

.bd-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: var(--bd-sp-4); }
.bd-dtile { padding: var(--bd-sp-4) var(--bd-sp-5); display: flex; flex-direction: column; gap: var(--bd-sp-4); }
.bd-dtile--off { opacity: .62; }
.bd-dtile__head { display: flex; align-items: center; gap: var(--bd-sp-3); }
.bd-dtile__icon {
  width: 40px; height: 40px; border-radius: var(--bd-radius); display: inline-flex; align-items: center; justify-content: center;
  background: var(--bd-primary-1); color: var(--bd-primary); font-size: 20px; flex: none;
}
.bd-dtile__name { font-size: var(--bd-fs-base); font-weight: 600; color: var(--bd-t1); margin: 0; }
.bd-dtile__arch { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin: 2px 0 0; line-height: var(--bd-lh); }
.bd-dtile__meta { display: flex; flex-wrap: wrap; gap: 6px var(--bd-sp-5); margin: 0; font-size: var(--bd-fs-sm); }
.bd-dtile__meta div { display: flex; gap: var(--bd-sp-2); }
.bd-dtile__meta dt { color: var(--bd-t3); }
.bd-dtile__meta dd { color: var(--bd-t2); margin: 0; display: inline-flex; align-items: center; gap: var(--bd-sp-1); }
.bd-dtile__sha { flex-basis: 100%; }
.bd-copybtn {
  border: none; background: none; color: var(--bd-t3); cursor: pointer; padding: 0 2px; font-size: var(--bd-fs-sm);
  transition: color var(--bd-dur-fast) var(--bd-ease);
}
.bd-copybtn:hover { color: var(--bd-primary); }
.bd-dtile__note { font-size: var(--bd-fs-sm); color: var(--bd-warning-t); margin: 0; }
/* 溯源提示复用 .bd-notice 的两档语义色，只收掉它在卡片里的外边距 */
.bd-dtile__prov { margin: 0; }
.bd-dtile__built { font-size: var(--bd-fs-xs); color: var(--bd-t3); margin: 0; }
.bd-dtile__act { margin-top: auto; display: flex; align-items: flex-end; justify-content: space-between; gap: var(--bd-sp-3); }
.bd-qr { display: flex; flex-direction: column; align-items: center; gap: var(--bd-sp-1); }
.bd-qr img { border: 1px solid var(--bd-border); border-radius: var(--bd-radius-xs); }
.bd-qr__cap { font-size: var(--bd-fs-xs); color: var(--bd-t3); }
.bd-qr__fallback { font-size: 10px; color: var(--bd-t3); max-width: 160px; word-break: break-all; }
.bd-foot { margin-top: var(--bd-sp-6); font-size: var(--bd-fs-sm); color: var(--bd-t4); }
</style>
