<template>
  <!-- 触发器：顶栏那个框。★它此前是 `<div class="bd-search">` + 一个图标 + 一句
       静态中文「搜索用户、应用、策略…」，没有 input、没有 handler——与 Users /
       Resources / Apps 三页曾经的假搜索框是同一个缺陷，那三页已经修过一轮，
       而这个**全局**的、最显眼的一个漏在了外面（scripts/check-dead-ui.mjs 的
       规则一只认 class="bd-searchbox"，这里叫 bd-search，正好从守卫底下溜过去）。 -->
  <button class="bd-search" @click="openPanel" :title="`全局搜索（${hotkeyLabel}）`">
    <icon-search />
    <span class="bd-search__ph">{{ PLACEHOLDER }}</span>
    <kbd class="bd-search__kbd">{{ hotkeyLabel }}</kbd>
  </button>

  <a-modal v-model:visible="open" :footer="false" :width="620" :closable="false"
           title-align="start" modal-class="bd-gs__modal" @close="onClose">
    <template #title><span class="bd-gs__title"><icon-search /> 全局搜索</span></template>

    <div class="bd-gs">
      <div class="bd-searchbox bd-gs__box">
        <icon-search />
        <input
          ref="inputEl" v-model="kw" class="bd-searchbox__in"
          :placeholder="PLACEHOLDER" autocomplete="off" spellcheck="false"
          @keydown.down.prevent="move(1)" @keydown.up.prevent="move(-1)"
          @keydown.enter.prevent="hit(active)" @keydown.esc.prevent="open = false"
        />
        <span v-if="loading" class="bd-gs__loading">加载中…</span>
      </div>

      <!-- ★取数失败必须当面说，且要点名**哪一类**搜不到。
           一个悄悄少搜了一类的搜索框比没有搜索框更坏：管理员搜不到某个用户，
           得到的结论会是"系统里没有这个人"，而不是"用户目录没拉下来"。 -->
      <div v-if="failed.length" class="bd-gs__warn">
        <icon-exclamation-circle-fill />
        <span>{{ failed.map((f) => f.label).join('、') }} 没有取到，下面的结果**不含**这些类别（{{ failed[0].err }}）</span>
        <button class="bd-gs__retry" @click="load(true)">重试</button>
      </div>

      <div v-if="!kw.trim()" class="bd-gs__hint">
        输入关键字搜索：{{ SOURCES.map((s) => s.label).join(' / ') }}。
        <span class="bd-gs__hint2">↑↓ 选择 · Enter 打开 · Esc 关闭</span>
      </div>
      <div v-else-if="!results.length" class="bd-gs__hint">
        没有匹配「{{ kw.trim() }}」的条目<span v-if="failed.length">（且有 {{ failed.length }} 类未取到，见上）</span>。
      </div>

      <ul v-else class="bd-gs__list" ref="listEl">
        <template v-for="(grp, gi) in grouped" :key="grp.kind">
          <li class="bd-gs__grp">{{ grp.label }}<i>{{ grp.items.length }}</i></li>
          <li
            v-for="it in grp.items" :key="it.key"
            class="bd-gs__it" :class="{ on: it.idx === active }"
            :data-idx="it.idx"
            @click="hit(it.idx)" @mouseenter="active = it.idx"
          >
            <component :is="grp.icon" class="bd-gs__icon" />
            <div class="bd-gs__body">
              <div class="bd-gs__t" v-html="mark(it.title)" />
              <div class="bd-gs__s" v-html="mark(it.sub)" />
            </div>
            <span class="bd-gs__go">{{ it.action }}</span>
          </li>
          <li v-if="grp.truncated" :key="grp.kind + '-more'" class="bd-gs__more">
            {{ grp.label }}还有 {{ grp.truncated }} 条匹配未列出，请补充关键字
          </li>
          <li v-if="gi < grouped.length - 1" :key="grp.kind + '-hr'" class="bd-gs__hr" />
        </template>
      </ul>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
/**
 * 全局搜索（顶栏 + Cmd/Ctrl-K）。
 *
 * 两条纪律，都是这个项目反复吃过亏的地方：
 *
 *  1. **占位文案与真实过滤字段逐字对应**。原来那句「搜索用户、应用、策略…」
 *     一个字都没兑现。现在 PLACEHOLDER 由 SOURCES 生成，加一类搜索就必然改一次文案，
 *     不会出现"说能搜、其实搜不到"。
 *
 *  2. **搜不到与没搜过必须分得开**。四个数据源里任何一个取数失败，都在结果区
 *     顶部点名说明；绝不静默地少给一类结果。
 *
 * 数据量：控制台的用户/应用/资源/网关都是**管理规模**（几十到几千），一次性拉全量
 * 在前端过滤是合适的；进入面板才拉、拉一次缓存 60s。刻意不做后端全文检索——
 * 那需要一个新端点与一套新的权限判定，而这四个读端点任意管理员本就可读。
 */
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import { api } from '@/lib/api';
import type { AppBundle, GatewayBundle, ResourcesResp, UserDirBundle } from '@/lib/api';
import { NAV } from '@/nav';

type Kind = 'page' | 'user' | 'app' | 'res' | 'gw';
interface Hit { kind: Kind; key: string; title: string; sub: string; path: string; action: string }

/** 每类最多列几条（其余用 truncated 明说）。 */
const PER_KIND = 5;
/** 缓存有效期：过了就重拉（管理台数据变动不频繁，但不能永久不刷）。 */
const TTL_MS = 60_000;

/** 搜索类别声明。★PLACEHOLDER 由它生成——这是"文案与实现同源"的执行方。 */
const SOURCES = [
  { kind: 'page' as const, label: '页面', icon: 'IconApps' },
  { kind: 'user' as const, label: '用户', icon: 'IconUser' },
  { kind: 'app' as const, label: '应用', icon: 'IconAppstore' },
  { kind: 'res' as const, label: '资源', icon: 'IconRelation' },
  { kind: 'gw' as const, label: '网关', icon: 'IconStorage' }
];
const PLACEHOLDER = `搜索${SOURCES.map((s) => s.label).join(' / ')}…`;

const router = useRouter();
const open = ref(false);
const kw = ref('');
const active = ref(0);
const loading = ref(false);
const inputEl = ref<HTMLInputElement>();
const listEl = ref<HTMLElement>();

const hotkeyLabel = navigator.platform.toLowerCase().includes('mac') ? '⌘K' : 'Ctrl K';

/** 拉到的原始条目（不含页面——页面来自 NAV，永远可用）。 */
const remote = ref<Hit[]>([]);
/** 取数失败的类别：{ label, err }。必须原样显示，见上面第 2 条纪律。 */
const failed = ref<{ label: string; err: string }[]>([]);
let loadedAt = 0;

/** 页面条目：始终可用，不依赖任何接口。 */
const pages = computed<Hit[]>(() =>
  NAV.flatMap((g) => g.children.map((c) => ({
    kind: 'page' as const, key: 'p:' + c.path,
    title: c.title, sub: `${g.label} · ${c.path}`, path: c.path, action: '打开'
  })))
);

const all = computed<Hit[]>(() => [...pages.value, ...remote.value]);

const results = computed<Hit[]>(() => {
  const q = kw.value.trim().toLowerCase();
  if (!q) return [];
  return all.value.filter((h) => (h.title + ' ' + h.sub).toLowerCase().includes(q));
});

/** 按类别分组 + 每类截断，并把全局序号 idx 写进条目（键盘上下移动用）。 */
const grouped = computed(() => {
  let idx = 0;
  const out: { kind: Kind; label: string; icon: string; items: (Hit & { idx: number })[]; truncated: number }[] = [];
  for (const src of SOURCES) {
    const hits = results.value.filter((h) => h.kind === src.kind);
    if (!hits.length) continue;
    const shown = hits.slice(0, PER_KIND).map((h) => ({ ...h, idx: idx++ }));
    out.push({ kind: src.kind, label: src.label, icon: src.icon, items: shown, truncated: hits.length - shown.length });
  }
  return out;
});
/** 当前可选中的条目（与 grouped 展开顺序一致）。 */
const flat = computed(() => grouped.value.flatMap((g) => g.items));

function openPanel() {
  open.value = true;
  active.value = 0;
  void nextTick(() => inputEl.value?.focus());
  void load(false);
}
function onClose() { kw.value = ''; active.value = 0; }

async function load(force: boolean) {
  if (!force && loadedAt && Date.now() - loadedAt < TTL_MS) return;
  loading.value = true;
  const fails: { label: string; err: string }[] = [];
  const hits: Hit[] = [];
  const pull = async (label: string, fn: () => Promise<Hit[]>) => {
    try { hits.push(...(await fn())); }
    catch (e) { fails.push({ label, err: e instanceof Error ? e.message : '未知错误' }); }
  };
  await Promise.all([
    pull('用户', async () => (await api<UserDirBundle>('/users')).users.map((u) => ({
      kind: 'user', key: 'u:' + u.id, title: u.name,
      sub: `${u.account}${u.org ? ' · ' + u.org : ''}${u.ip ? ' · ' + u.ip : ''}`,
      path: '/business/users', action: '用户与角色'
    }))),
    pull('应用', async () => (await api<AppBundle>('/apps')).apps.map((a) => ({
      kind: 'app', key: 'a:' + a.id, title: a.name, sub: `${a.id} · ${a.addr}`,
      path: '/business/apps', action: '应用管理'
    }))),
    pull('资源', async () => (await api<ResourcesResp>('/resources')).resources.map((r) => ({
      kind: 'res', key: 'r:' + r.id, title: r.name, sub: `${r.id} · ${r.backend}`,
      path: '/security/resources', action: '资源策略'
    }))),
    pull('网关', async () => (await api<GatewayBundle>('/gateway')).nodes.map((n) => ({
      kind: 'gw', key: 'g:' + n.id, title: n.id,
      sub: `${n.online ? '在线' : '离线'} · SPA ${n.spa} · 隧道 ${n.proxy}`,
      path: '/security/gateway', action: '网关与隐身'
    })))
  ]);
  remote.value = hits;
  failed.value = fails;
  // 只有全都成功才算"缓存有效"，否则下次打开还应再试一次。
  loadedAt = fails.length ? 0 : Date.now();
  loading.value = false;
}

function move(d: number) {
  const n = flat.value.length;
  if (!n) return;
  active.value = (active.value + d + n) % n;
  void nextTick(() => {
    listEl.value?.querySelector<HTMLElement>(`[data-idx="${active.value}"]`)
      ?.scrollIntoView({ block: 'nearest' });
  });
}

function hit(i: number) {
  const target = flat.value[i];
  if (!target) return;
  open.value = false;
  // 目标页没有"定位到某一行"的深链，所以只导航到页面，并把关键字留在剪贴板式的
  // 页面内搜索里做不到——刻意**不**假装能定位：action 那一列写的就是落地页名字。
  if (router.currentRoute.value.path !== target.path) router.push(target.path);
}

/** 高亮命中片段。转义在前、插标签在后，避免把用户/资源名里的尖括号当标签渲染。 */
function mark(text: string): string {
  const esc = (s: string) => s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
  const q = kw.value.trim();
  const safe = esc(text);
  if (!q) return safe;
  const i = safe.toLowerCase().indexOf(esc(q).toLowerCase());
  if (i < 0) return safe;
  return safe.slice(0, i) + '<em>' + safe.slice(i, i + q.length) + '</em>' + safe.slice(i + q.length);
}

/** Cmd/Ctrl-K 唤起。绑在 window 上，任何页面都能用。 */
function onKey(e: KeyboardEvent) {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openPanel(); }
}
onMounted(() => window.addEventListener('keydown', onKey));
onUnmounted(() => window.removeEventListener('keydown', onKey));
</script>

<style scoped>
.bd-search {
  display: flex; align-items: center; height: 32px; background: var(--bd-fill-2); border: none;
  border-radius: 6px; padding: 0 8px 0 10px; gap: 8px; width: 240px; color: var(--bd-t3);
  font-size: 13px; cursor: pointer; text-align: left;
}
.bd-search:hover { background: var(--bd-fill-1); box-shadow: inset 0 0 0 1px var(--bd-border); }
.bd-search:focus-visible { outline: 2px solid var(--bd-primary); outline-offset: 1px; }
.bd-search__ph { flex: 1; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
.bd-search__kbd {
  font-size: 10.5px; color: var(--bd-t3); background: #fff; border: 1px solid var(--bd-border);
  border-radius: 4px; padding: 1px 5px; font-family: inherit; flex: none;
}

.bd-gs__title { display: flex; align-items: center; gap: 8px; font-size: 14px; }
.bd-gs__box { margin-bottom: 12px; }
.bd-searchbox {
  display: flex; align-items: center; gap: 8px; height: 38px; padding: 0 12px;
  background: var(--bd-fill-2); border-radius: 8px; color: var(--bd-t3);
}
.bd-searchbox__in { border: none; outline: none; background: transparent; flex: 1; min-width: 0; font-size: 14px; color: var(--bd-t1); }
.bd-searchbox__in::placeholder { color: var(--bd-t3); }
.bd-gs__loading { font-size: 11.5px; color: var(--bd-t3); flex: none; }

.bd-gs__warn {
  display: flex; align-items: center; gap: 8px; padding: 9px 12px; margin-bottom: 10px;
  background: var(--bd-tag-gold-bg); border-radius: 8px; font-size: 12px; color: var(--bd-t2); line-height: 1.6;
}
.bd-gs__warn > span { flex: 1; }
.bd-gs__retry { border: none; background: transparent; color: var(--bd-primary); cursor: pointer; font-size: 12px; flex: none; }

.bd-gs__hint { padding: 26px 6px; text-align: center; font-size: 12.5px; color: var(--bd-t3); line-height: 1.9; }
.bd-gs__hint2 { display: block; font-size: 11.5px; color: var(--bd-t4); }

.bd-gs__list { list-style: none; margin: 0; padding: 0; max-height: 420px; overflow-y: auto; }
.bd-gs__grp {
  display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--bd-t3);
  font-weight: 600; padding: 8px 6px 5px; letter-spacing: .4px;
}
.bd-gs__grp i { font-style: normal; color: var(--bd-t4); font-weight: 400; }
.bd-gs__it {
  display: flex; align-items: center; gap: 10px; padding: 8px 10px; border-radius: 7px; cursor: pointer;
}
.bd-gs__it.on { background: var(--bd-primary-1); }
.bd-gs__icon { font-size: 16px; color: var(--bd-t3); flex: none; }
.bd-gs__it.on .bd-gs__icon { color: var(--bd-primary); }
.bd-gs__body { flex: 1; min-width: 0; }
.bd-gs__t { font-size: 13px; color: var(--bd-t1); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bd-gs__s { font-size: 11.5px; color: var(--bd-t3); margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bd-gs__t :deep(em), .bd-gs__s :deep(em) { font-style: normal; color: var(--bd-primary); font-weight: 600; }
.bd-gs__go { font-size: 11px; color: var(--bd-t4); flex: none; }
.bd-gs__it.on .bd-gs__go { color: var(--bd-primary); }
.bd-gs__more { font-size: 11px; color: var(--bd-t3); padding: 3px 10px 6px 36px; }
.bd-gs__hr { height: 1px; background: var(--bd-border); margin: 6px 4px; }
</style>
