<template>
  <div class="bd-portal">
    <!-- 顶部细 bar（与应用门户同构） -->
    <header class="bd-pbar">
      <div class="bd-plogo">
        <span class="bd-plogo__mark">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
            <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </span>
        <span class="bd-plogo__txt">白帝 · 客户端下载</span>
      </div>
      <div class="bd-pbar__spacer" />
      <button class="bd-pquit" @click="goBack"><icon-left /><span>返回</span></button>
    </header>

    <main class="bd-pmain">
      <div class="bd-pwrap">
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
              <template v-else>{{ recommended.note || '构建中，敬请期待' }}</template>
            </p>
            <button v-if="recommended.available" class="bd-hero__btn" @click="download(recommended)">
              <icon-download /> 立即下载
            </button>
          </div>
        </section>

        <!-- 全平台栅格 -->
        <h2 class="bd-sect">全部平台</h2>
        <div class="bd-grid">
          <article v-for="c in clients" :key="c.platform" class="bd-dtile" :class="{ 'bd-dtile--off': !c.available }">
            <header class="bd-dtile__head">
              <span class="bd-dtile__icon"><component :is="platformIcon(c.platform)" /></span>
              <div>
                <h3 class="bd-dtile__name">{{ c.label }}</h3>
                <p class="bd-dtile__arch">{{ c.available ? (c.arch || '') : (c.note || '构建中，敬请期待') }}</p>
              </div>
            </header>
            <template v-if="c.available">
              <dl class="bd-dtile__meta">
                <div><dt>版本</dt><dd>{{ c.version }}</dd></div>
                <div><dt>大小</dt><dd>{{ fmtSize(c.size) }}</dd></div>
                <div class="bd-dtile__sha">
                  <dt>SHA256</dt>
                  <dd class="bd-mono" :title="c.sha256">{{ shortSha(c.sha256) }}
                    <button class="bd-copybtn" title="复制完整校验值" @click="copySha(c.sha256)"><icon-copy /></button>
                  </dd>
                </div>
              </dl>
              <p v-if="c.note" class="bd-dtile__note">{{ c.note }}</p>
              <div class="bd-dtile__act">
                <button class="bd-dtile__btn" @click="download(c)"><icon-download /> 下载</button>
                <div v-if="c.platform === 'android'" class="bd-qr">
                  <img v-if="qr" :src="qr" alt="扫码下载 Android 客户端" width="84" height="84" />
                  <span v-else class="bd-mono bd-qr__fallback">{{ fileUrl(c) }}</span>
                  <span class="bd-qr__cap">手机扫码直接下载</span>
                </div>
              </div>
            </template>
            <template v-else>
              <div class="bd-dtile__act">
                <button class="bd-dtile__btn bd-dtile__btn--ghost" disabled>暂未提供</button>
              </div>
            </template>
          </article>
        </div>

        <p class="bd-foot">
          安装包由控制中心统一分发，下载后请核对 SHA256 校验值。iOS / 鸿蒙分发请联系管理员。
        </p>
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import QRCode from 'qrcode';
import { Message } from '@arco-design/web-vue';
import { api, getToken, type ClientDownload, type DownloadsResp } from '@/lib/api';
import { IconDesktop, IconMobile } from '@arco-design/web-vue/es/icon';

const router = useRouter();
const clients = ref<ClientDownload[]>([]);
const qr = ref('');

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

function shortSha(s?: string): string {
  return s ? `${s.slice(0, 8)}…${s.slice(-8)}` : '—';
}

async function copySha(s?: string) {
  if (!s) return;
  await navigator.clipboard.writeText(s);
  Message.success('SHA256 已复制');
}

function goBack() {
  router.push(getToken() ? '/portal/apps' : '/portal/login');
}

onMounted(async () => {
  try {
    const resp = await api<DownloadsResp>('/portal/downloads');
    clients.value = resp.clients;
    const android = resp.clients.find((c) => c.platform === 'android' && c.available && c.file);
    if (android) {
      try {
        qr.value = await QRCode.toDataURL(fileUrl(android), { width: 168, margin: 1 });
      } catch {
        qr.value = ''; // 降级显示纯 URL 文本
      }
    }
  } catch {
    Message.error('下载清单获取失败，请稍后重试');
  }
});
</script>

<style scoped>
.bd-portal { min-height: 100vh; display: flex; flex-direction: column; background: var(--bd-fill-1); }
.bd-pbar {
  height: 56px; background: #fff; border-bottom: 1px solid var(--bd-border);
  display: flex; align-items: center; padding: 0 24px; gap: 14px; position: sticky; top: 0; z-index: 10;
}
.bd-plogo { display: inline-flex; align-items: center; gap: 10px; }
.bd-plogo__mark {
  width: 30px; height: 30px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d));
}
.bd-plogo__txt { font-size: 14.5px; font-weight: 600; color: var(--bd-t1); }
.bd-pbar__spacer { flex: 1; }
.bd-pquit {
  display: inline-flex; align-items: center; gap: 6px; height: 32px; padding: 0 12px;
  border: 1px solid var(--bd-border); background: #fff; border-radius: 7px; cursor: pointer;
  font-size: 13px; color: var(--bd-t2); transition: all .15s;
}
.bd-pquit:hover { border-color: var(--bd-primary); color: var(--bd-primary); }
.bd-pmain { flex: 1; padding: 28px 24px 48px; }
.bd-pwrap { max-width: 1080px; margin: 0 auto; }
.bd-hero {
  background: linear-gradient(135deg, var(--bd-dark-1), var(--bd-dark-2));
  border-radius: var(--bd-radius); padding: 30px 34px; color: #fff; margin-bottom: 30px;
}
.bd-hero__kicker { font-size: 12px; color: var(--bd-dark-txt); margin-bottom: 8px; }
.bd-hero__title { font-size: 24px; font-weight: 700; margin: 0 0 8px; }
.bd-hero__meta { font-size: 13px; color: var(--bd-dark-txt); margin-bottom: 18px; }
.bd-hero__btn {
  display: inline-flex; align-items: center; gap: 8px; height: 38px; padding: 0 22px;
  background: var(--bd-primary); color: #fff; border: none; border-radius: 8px; font-size: 14px;
  cursor: pointer; box-shadow: 0 4px 14px rgba(22, 93, 255, .35); transition: background .15s;
}
.bd-hero__btn:hover { background: var(--bd-primary-h); }
.bd-sect { font-size: 15px; font-weight: 600; color: var(--bd-t1); margin: 0 0 14px; }
.bd-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
.bd-dtile {
  background: #fff; border: 1px solid var(--bd-border); border-radius: var(--bd-radius);
  padding: 18px 20px; display: flex; flex-direction: column; gap: 14px;
}
.bd-dtile--off { opacity: .62; }
.bd-dtile__head { display: flex; align-items: center; gap: 12px; }
.bd-dtile__icon {
  width: 40px; height: 40px; border-radius: 10px; display: inline-flex; align-items: center; justify-content: center;
  background: var(--bd-primary-1); color: var(--bd-primary); font-size: 20px; flex: none;
}
.bd-dtile__name { font-size: 14.5px; font-weight: 600; color: var(--bd-t1); margin: 0; }
.bd-dtile__arch { font-size: 12px; color: var(--bd-t3); margin: 2px 0 0; }
.bd-dtile__meta { display: flex; flex-wrap: wrap; gap: 6px 22px; margin: 0; font-size: 12.5px; }
.bd-dtile__meta div { display: flex; gap: 8px; }
.bd-dtile__meta dt { color: var(--bd-t3); }
.bd-dtile__meta dd { color: var(--bd-t2); margin: 0; display: inline-flex; align-items: center; gap: 4px; }
.bd-dtile__sha { flex-basis: 100%; }
.bd-copybtn {
  border: none; background: none; color: var(--bd-t3); cursor: pointer; padding: 0 2px; font-size: 12px;
}
.bd-copybtn:hover { color: var(--bd-primary); }
.bd-dtile__note { font-size: 12px; color: var(--bd-warning); margin: 0; }
.bd-dtile__act { margin-top: auto; display: flex; align-items: flex-end; justify-content: space-between; gap: 12px; }
.bd-dtile__btn {
  display: inline-flex; align-items: center; gap: 6px; height: 34px; padding: 0 18px;
  background: var(--bd-primary); color: #fff; border: none; border-radius: 7px; font-size: 13px;
  cursor: pointer; box-shadow: 0 2px 8px rgba(22, 93, 255, .25); transition: background .15s;
}
.bd-dtile__btn:hover { background: var(--bd-primary-h); }
.bd-dtile__btn--ghost {
  background: #fff; color: var(--bd-t3); border: 1px solid var(--bd-border); box-shadow: none; cursor: not-allowed;
}
.bd-qr { display: flex; flex-direction: column; align-items: center; gap: 4px; }
.bd-qr img { border: 1px solid var(--bd-border); border-radius: 6px; }
.bd-qr__cap { font-size: 11px; color: var(--bd-t3); }
.bd-qr__fallback { font-size: 10px; color: var(--bd-t3); max-width: 160px; word-break: break-all; }
.bd-foot { margin-top: 28px; font-size: 12px; color: var(--bd-t4); }
</style>
