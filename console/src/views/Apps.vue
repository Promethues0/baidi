<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">应用管理</div>
        <div class="bd-page__sub">把内网业务注册为受控资源 · 隧道应用与 WEB 应用 · 以资源为最小授权单元</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <button class="bd-btn" @click="openWizard"><icon-plus />新增应用</button>
      </div>
    </div>

    <div class="bd-two">
      <!-- 分类 -->
      <div class="bd-card bd-cats">
        <div class="bd-cats__h">
          <span>应用分类</span>
          <!-- 真 button 而非 <span @click>：裸 span 不进 Tab 焦点序列、读屏也报不出它是可操作的，
               键盘用户根本到不了分类维护这唯一的入口（Users.vue 的组织树同批已改）。 -->
          <button type="button" class="bd-link bd-cats__mgr" @click="openCatMgr"><icon-settings />管理分类</button>
        </div>
        <button v-for="c in categories" :key="c.key" class="bd-cat" :class="{ on: cat === c.key }" @click="cat = c.key">
          <icon-folder class="bd-cat__ic" />
          <span class="bd-cat__t">{{ c.label }}</span>
          <span class="bd-cat__n">{{ c.count }}</span>
        </button>
      </div>

      <!-- 应用表 -->
      <div class="bd-tablecard" style="flex: 1; min-width: 0">
        <div class="bd-toolbar">
          <span class="bd-toolbar__c">共 {{ filtered.length }} 个应用</span>
          <div style="flex: 1" />
          <div class="bd-searchbox" style="width: 240px"><icon-search />按名称 / 地址搜索</div>
        </div>
        <table class="bd-table">
          <thead>
            <tr>
              <th>应用名称</th><th>发布模式</th><th>所属区域</th><th>已授权</th><th>状态</th><th class="r">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in filtered" :key="a.id">
              <td>
                <div class="bd-cellname">
                  <span class="bd-appic" :style="{ background: modeMeta(a.mode).bg }">
                    <component :is="modeMeta(a.mode).icon" :style="{ color: modeMeta(a.mode).color }" />
                  </span>
                  <span><b>{{ a.name }}</b><i class="bd-mono">{{ a.addr }}</i></span>
                </div>
              </td>
              <td><span class="bd-tg" :style="tagStyle(modeMeta(a.mode).color)">{{ modeMeta(a.mode).label }}</span></td>
              <td>{{ a.node }}</td>
              <td><span :class="{ 'bd-auth--none': a.authScope === 'unlinked' }" :title="authTitle(a)">{{ authText(a) }}</span></td>
              <td>
                <span class="bd-st"><span class="d" :style="{ background: a.status === 'running' ? 'var(--bd-success)' : 'var(--bd-t4)' }" />{{ a.status === 'running' ? '运行中' : '已停用' }}</span>
              </td>
              <td class="r"><span class="bd-link" @click="openWizard">编辑</span> <span class="bd-link bd-link--grey" style="margin-left: 12px">详情</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ============ 分类维护（增删改 + 排序）============ -->
    <a-modal v-model:visible="mgr.open" :width="680" title="管理应用分类" :footer="false" unmount-on-close>
      <div class="bd-catmgr">
        <div class="bd-catmgr__hint">
          <icon-info-circle />分类只影响管理台上的归类与筛选，不参与任何访问授权判定——授权在「安全防护 → 资源策略」按资源配置。
        </div>
        <div v-if="mgr.err" class="bd-catmgr__err">{{ mgr.err }}</div>

        <table class="bd-table bd-catmgr__t">
          <thead>
            <tr><th style="width: 76px">排序</th><th>名称</th><th style="width: 150px">分类 key</th><th style="width: 80px">应用数</th><th class="r" style="width: 64px">操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="(c, i) in mgr.list" :key="c.key">
              <td>
                <button type="button" class="bd-link bd-catmgr__mv" :disabled="mgr.busy || i === 0"
                  :title="`把「${c.label}」上移一位`" :aria-label="`把分类「${c.label}」上移一位`"
                  @click="move(i, -1)"><icon-arrow-up /></button>
                <button type="button" class="bd-link bd-catmgr__mv" :disabled="mgr.busy || i === mgr.list.length - 1"
                  :title="`把「${c.label}」下移一位`" :aria-label="`把分类「${c.label}」下移一位`"
                  @click="move(i, 1)"><icon-arrow-down /></button>
              </td>
              <td>
                <a-input v-model="c.label" :max-length="64" size="small" :disabled="mgr.busy"
                  @blur="rename(c)" @press-enter="rename(c)" />
              </td>
              <td>
                <i class="bd-mono">{{ c.key }}</i>
                <span v-if="c.builtin" class="bd-tg bd-catmgr__bi">内置</span>
              </td>
              <td>{{ c.count }}</td>
              <td class="r">
                <span v-if="c.builtin" class="bd-catmgr__no" title="内置分类不可删除（key 被既有应用引用），可改名与调整排序">—</span>
                <button v-else type="button" class="bd-link bd-link--danger" :disabled="mgr.busy"
                  :title="`删除分类「${c.label}」`" :aria-label="`删除分类「${c.label}」`"
                  @click="askRemove(c)"><icon-delete /></button>
              </td>
            </tr>
            <tr v-if="!mgr.list.length && mgr.loaded">
              <td colspan="5" class="bd-catmgr__empty">分类字典为空——新增一个后才能发布应用。</td>
            </tr>
          </tbody>
        </table>

        <div class="bd-catmgr__add">
          <a-input v-model="mgr.newKey" placeholder="key（小写字母/数字/连字符）" class="bd-mono" :max-length="32" :disabled="mgr.busy" />
          <a-input v-model="mgr.newLabel" placeholder="显示名称" :max-length="64" :disabled="mgr.busy" @press-enter="create" />
          <button class="bd-btn" :disabled="mgr.busy || !mgr.newKey || !mgr.newLabel"
            :style="{ opacity: mgr.busy || !mgr.newKey || !mgr.newLabel ? 0.5 : 1 }" @click="create"><icon-plus />新增</button>
        </div>
        <div class="bd-catmgr__foot">key 落库后不可更改（既有应用按 key 引用分类）；名称随时可改，应用页与发布向导立即跟随。</div>
      </div>
    </a-modal>

    <!-- ============ 发布向导（P1 分步 + 分支）============ -->
    <a-drawer v-model:visible="wz.open" :width="720" title="应用发布向导" :footer="false" unmount-on-close>
      <div class="bd-wz">
        <a-steps :current="wz.step + 1" small class="bd-wz__steps">
          <a-step v-for="(t, i) in STEPS" :key="i" :title="t" />
        </a-steps>

        <!-- Step 1: 发布模式（分支点） -->
        <div v-if="wz.step === 0" class="bd-wz__body">
          <div class="bd-wz__hint">选择业务的发布模式 —— 不同模式决定后续的配置项与可用安全能力。</div>
          <button v-for="m in MODES" :key="m.key" class="bd-mode-card" :class="{ on: wz.mode === m.key }" @click="wz.mode = m.key">
            <span class="bd-mode-card__ic" :style="{ background: m.bg }"><component :is="m.icon" :style="{ color: m.color }" /></span>
            <span class="bd-mode-card__txt"><b>{{ m.label }}</b><i>{{ m.desc }}</i></span>
            <icon-check-circle-fill v-if="wz.mode === m.key" class="bd-mode-card__chk" />
          </button>
        </div>

        <!-- Step 2: 基础配置（按模式分支） -->
        <div v-else-if="wz.step === 1" class="bd-wz__body">
          <div class="bd-fld"><label>应用名称</label><a-input v-model="wz.f.name" placeholder="例如：OA 协同办公" /></div>
          <div class="bd-fld"><label>所属分类</label>
            <a-select v-model="wz.f.cat" placeholder="选择分类">
              <a-option v-for="c in pickableCats" :key="c.key" :value="c.key">{{ c.label }}</a-option>
            </a-select>
            <span v-if="!pickableCats.length" class="bd-fld__d">分类字典为空，请先用左侧「管理分类」新增一个——后端会拒收字典外的分类。</span>
          </div>
          <div v-if="wz.mode === 'tunnel'" class="bd-fld"><label>内网地址</label><a-input v-model="wz.f.addr" placeholder="10.30.5.8:22" class="bd-mono" /></div>
          <div v-else-if="wz.mode === 'web'" class="bd-fld"><label>内网 URL</label><a-input v-model="wz.f.addr" placeholder="http://10.20.1.10:8080" class="bd-mono" /></div>
          <div v-else class="bd-fld"><label>泛域名</label><a-input v-model="wz.f.addr" placeholder="*.cnki.net" class="bd-mono" /></div>
          <div class="bd-fld"><label>关联受控资源</label>
            <a-select v-model="wz.f.resourceId" placeholder="选择资源（决定客户端路由与 JIT 申请）" allow-clear>
              <a-option v-for="r in resources" :key="r.id" :value="r.id">{{ r.name }}（{{ r.backend }}）</a-option>
            </a-select>
            <span v-if="!wz.f.resourceId" class="bd-fld__d">不关联资源的应用无法经隧道访问、也无法被 JIT 申请——客户端剖面会对此显式告警。</span>
          </div>
        </div>

        <!-- Step 3: 确认发布 -->
        <div v-else class="bd-wz__body">
          <div class="bd-wz__summary">
            <b>发布摘要</b>
            <div>{{ modeMeta(wz.mode || 'web').label }} · {{ wz.f.name || '未命名' }} · {{ wz.f.addr || '—' }} · {{ wz.f.resourceId ? `关联资源 ${wz.f.resourceId}` : '未关联资源' }}</div>
          </div>
          <div class="bd-wz__note"><icon-info-circle />访问授权在「安全防护 → 资源策略」按资源配置（角色/用户白名单），时限授予走「JIT 即时访问」审批流。</div>
        </div>

        <div class="bd-wz__foot">
          <button v-if="wz.step > 0" class="bd-btn bd-btn--ghost" @click="wz.step--">上一步</button>
          <div style="flex: 1" />
          <button class="bd-btn bd-btn--ghost" @click="wz.open = false">取消</button>
          <button class="bd-btn" :disabled="!canNext" :style="{ opacity: canNext ? 1 : 0.5 }" @click="next">
            {{ wz.step < 2 ? '下一步' : '发布应用' }}
          </button>
        </div>
      </div>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, watch, onMounted } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { api, type AppBundle, type App, type AppCategory, type AppCategoryDef, type AppCategoriesResp, type Resource, type ResourcesResp } from '@/lib/api';

const live = ref(false);
const categories = ref<AppCategory[]>([{ key: 'all', label: '全部应用', count: 0 }]);
const apps = ref<App[]>([]);
const cat = ref('all');
const filtered = computed(() => (cat.value === 'all' ? apps.value : apps.value.filter((a) => a.category === cat.value)));

const MODES = [
  { key: 'tunnel', label: '隧道应用（C/S）', desc: 'SSH / RDP / 数据库等 C/S 业务，走 SSL 访问隧道', icon: 'IconCode', bg: '#F5E8FF', color: '#722ED1' },
  { key: 'web', label: 'WEB 应用（B/S）', desc: '浏览器直达的 B/S 业务，免客户端，走 HTTPS 代理', icon: 'IconCommon', bg: '#F2F7FF', color: '#165DFF' },
  { key: 'global', label: 'WEB 全网资源', desc: '知网 / 图书馆等泛域名公网资源，门户内访问', icon: 'IconPublic', bg: '#E8FFEA', color: '#00B42A' }
] as const;
function modeMeta(m: string) { return MODES.find((x) => x.key === m) ?? MODES[1]; }

/* 「已授权」列：授权面由后端按关联资源的真实 ACL 现算，三种性质要分开呈现——
   都渲染成一个数字的话，「没关联资源所以谁也进不去」会长得跟「授权了 0 个人」一样。 */
function authText(a: App) {
  if (a.authScope === 'unlinked') return '未关联资源';
  if (a.authScope === 'unlimited') return `全部用户（${a.authedUsers}）`;
  return `${a.authedUsers} 用户`;
}
function authTitle(a: App) {
  if (a.authScope === 'unlinked') return '该应用未关联受控资源，无法经隧道访问——在发布向导里关联一个资源';
  if (a.authScope === 'unlimited') return '关联资源未设置任何访问控制，对全部登录用户开放';
  return '按资源 ACL（用户 / 角色 / 组织 / 用户组展开）统计，不含有时限的 JIT 临时授予';
}
function tagStyle(color: string) { return { color, background: color + '14' }; }

// 向导只收集会真正提交后端的字段——收集了却静默丢弃的控件比没有更糟（见 CLAUDE.md 静默失效缺陷族）。
// DLP / 水印 / 浏览器管控 / XFF / 负载均衡等依赖七层代理，网关当前是 L4 隧道，暂无执行方，故不提供入口。
const STEPS = ['发布模式', '基础配置', '确认发布'];
const wz = reactive({
  open: false, step: 0, mode: '' as '' | 'tunnel' | 'web' | 'global',
  f: { name: '', cat: '', addr: '', resourceId: '' }
});
/** 发布向导可选的分类 = 筛选条去掉合成项 all（它不是真实分类）。 */
const pickableCats = computed(() => categories.value.filter((c) => c.key !== 'all'));
function openWizard() {
  wz.open = true; wz.step = 0; wz.mode = '';
  wz.f.name = ''; wz.f.addr = ''; wz.f.resourceId = '';
  // 默认选第一个真实分类。★不再写死 'office'：分类可增删之后，写死一个 key 意味着
  // 管理员删掉它以后每次发布都会 400，而错误来自一个界面上根本没显示的默认值。
  wz.f.cat = pickableCats.value[0]?.key ?? '';
}
const canNext = computed(() => {
  if (wz.step === 0) return !!wz.mode;
  // 分类是必选：后端会拒收字典外的 key，前端放行只会把校验推迟到最后一步。
  if (wz.step === 1) return !!wz.f.name && !!wz.f.addr && !!wz.f.cat;
  return true;
});
const publishing = ref(false);
const resources = ref<Resource[]>([]);
async function load() {
  try {
    const b = await api<AppBundle>('/apps');
    categories.value = b.categories; apps.value = b.apps; live.value = true;
    // 当前筛选的分类可能刚被删掉（自己删的，或另一个管理员删的）：不重置的话左栏一项都不高亮、
    // 右侧列表恒空，看起来像"这个分类下没有应用"，而实际是筛选卡在了一个不存在的 key 上。
    if (cat.value !== 'all' && !b.categories.some((c) => c.key === cat.value)) cat.value = 'all';
  } catch { live.value = false; }
  try {
    const r = await api<ResourcesResp>('/resources');
    resources.value = r.resources ?? [];
  } catch { resources.value = []; }
}
async function next() {
  if (!canNext.value) return;
  if (wz.step < 2) { wz.step++; return; }
  publishing.value = true;
  try {
    await api('/apps', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: wz.f.name, addr: wz.f.addr, mode: wz.mode, category: wz.f.cat, resourceId: wz.f.resourceId })
    });
    wz.open = false;
    Message.success(`应用「${wz.f.name}」已发布并落库`);
    cat.value = 'all';
    await load();
  } catch (e) {
    Message.error(reason(e, '发布失败，请检查后端连接'));
  } finally {
    publishing.value = false;
  }
}

/* ── 分类维护（增删改 + 排序）──
   分类此前是编译进后端二进制的两个常量，管理员既加不了也改不了；这里是唯一维护入口。
   每次操作立刻落库（不做本地暂存 + 批量保存）：批量提交要维护一份差异集，
   而任何一条失败都会让页面上的状态与库里分家，那种分家在这一屏上看不出来。 */
const mgr = reactive({
  open: false, loaded: false, busy: false, err: '',
  list: [] as AppCategoryDef[],
  newKey: '', newLabel: ''
});

async function loadCats() {
  try {
    mgr.list = (await api<AppCategoriesResp>('/app-categories')).categories ?? [];
  } catch (e) {
    mgr.list = [];
    mgr.err = reason(e, '读取分类字典失败');
  } finally {
    mgr.loaded = true;
  }
}
function openCatMgr() { mgr.open = true; mgr.loaded = false; mgr.err = ''; mgr.newKey = ''; mgr.newLabel = ''; void loadCats(); }

/** 一次分类写操作：统一置忙、统一刷新字典与应用页（计数与筛选条都要跟着变）。 */
async function catOp(run: () => Promise<unknown>, okMsg: string, failMsg: string): Promise<boolean> {
  if (mgr.busy) return false;
  mgr.busy = true;
  try {
    await run();
    mgr.err = '';
    await loadCats();
    await load();
    Message.success(okMsg);
    return true;
  } catch (e) {
    // 后端守卫的原话就是下一步该做什么（"分类下仍有 N 个应用…"），原样呈现。
    const msg = reason(e, failMsg);
    Message.error(msg);
    // ★先刷新再写 err：loadCats 成功时不动 err，但它是异步的，
    // 顺序反过来的话弹窗里的红条会被这次刷新的时序吃掉，只剩一条转瞬即逝的 toast。
    await loadCats(); // 回到库里的真实状态，别把本地改了一半的输入留在表格里
    mgr.err = msg;
    return false;
  } finally {
    mgr.busy = false;
  }
}

function create() {
  const key = mgr.newKey.trim(), label = mgr.newLabel.trim();
  if (!key || !label) return;
  void catOp(
    () => api('/app-categories', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key, label }) }),
    `分类「${label}」已新增`, '新增分类失败'
  ).then((ok) => { if (ok) { mgr.newKey = ''; mgr.newLabel = ''; } });
}

function putCat(c: AppCategoryDef, label: string, sort: number) {
  return api(`/app-categories/${encodeURIComponent(c.key)}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label, sort })
  });
}

function rename(c: AppCategoryDef) {
  const label = c.label.trim();
  const was = prevLabel.get(c.key) ?? '';
  // 名字清空或没改动都不提交：前者后端本就会拒（400），后者每次失焦都会落一条
  // 「改名 X→X」的审计——审计只该记真的发生过的事。两种情况都把输入框还原成库里那份。
  if (!label || label === was) { c.label = was; return; }
  void catOp(() => putCat(c, label, c.sort), `分类已改名为「${label}」`, '改名失败');
}

/** 上移/下移：与相邻行交换 sort 后各提交一次（sort 是库里的真实列，不是前端排布）。 */
function move(i: number, dir: -1 | 1) {
  const j = i + dir;
  if (mgr.busy || j < 0 || j >= mgr.list.length) return;
  const a = mgr.list[i], b = mgr.list[j];
  // 两行 sort 相同时（历史数据可能如此）交换不会改变顺序，先拉开一档再交换。
  const sa = a.sort, sb = a.sort === b.sort ? b.sort + dir : b.sort;
  void catOp(async () => { await putCat(a, a.label, sb); await putCat(b, b.label, sa); }, '排序已更新', '调整排序失败');
}

/** 删除前先确认：这个图标常驻可见（不依赖 hover），点中即删的代价是一次不可撤销的字典变更。 */
function askRemove(c: AppCategoryDef) {
  Modal.confirm({
    title: '删除分类',
    content: `确认删除分类「${c.label}」（${c.key}）？分类下若仍有应用，后端会拒绝删除并说明还剩几个。`,
    okText: '删除', cancelText: '取消', okButtonProps: { status: 'danger' },
    onOk: () => remove(c)
  });
}

// 删掉的正好是当前筛选项时，筛选由 load() 里那道守卫统一拨回「全部应用」——
// 只写在这里的话，另一个管理员删掉同一个分类时本页仍会卡在空列表上。
async function remove(c: AppCategoryDef) {
  await catOp(
    () => api(`/app-categories/${encodeURIComponent(c.key)}`, { method: 'DELETE' }),
    `分类「${c.label}」已删除`, '删除失败'
  );
}

/** prevLabel 记住每行改动前的名称：用于「没变就不提交」与失败回滚显示。 */
const prevLabel = new Map<string, string>();
watch(() => mgr.list, (l) => { prevLabel.clear(); l.forEach((c) => prevLabel.set(c.key, c.label)); }, { deep: false });

function reason(e: unknown, fallback: string) {
  const msg = e instanceof Error ? e.message : '';
  return msg ? `${fallback}（${msg}）` : fallback;
}

onMounted(load);
</script>

<style scoped>
.bd-two { display: flex; gap: 16px; align-items: flex-start; }
.bd-cats { width: 210px; flex: none; padding: 12px; }
.bd-cats__h { font-size: 12px; font-weight: 600; color: var(--bd-t3); padding: 4px 8px 10px; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.bd-cats__mgr { display: inline-flex; align-items: center; gap: 3px; font-weight: 500; }
.bd-cat { width: 100%; display: flex; align-items: center; gap: 9px; height: 36px; padding: 0 12px; border: none; background: transparent; border-radius: 7px; cursor: pointer; font-size: 13px; color: var(--bd-t2); }
.bd-cat:hover { background: var(--bd-fill-2); }
.bd-cat.on { background: var(--bd-primary-1); color: var(--bd-primary); font-weight: 500; }
.bd-cat__ic { font-size: 15px; }
.bd-cat__t { flex: 1; text-align: left; }
.bd-cat__n { font-size: 11px; color: var(--bd-t3); }
/* 未关联资源不是「授权了 0 人」而是「根本进不去」，用弱化色与虚线下划线区分开。 */
.bd-auth--none { color: var(--bd-t3); border-bottom: 1px dashed var(--bd-line); cursor: help; }
.bd-toolbar__c { font-size: 12.5px; color: var(--bd-t3); }
.bd-appic { width: 34px; height: 34px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; font-size: 17px; flex: none; }

/* 链接样式的 <button>：外观沿用 .bd-link，但可聚焦、可回车触发、有禁用态。 */
button.bd-link { border: none; background: transparent; padding: 0; font: inherit; line-height: inherit; }
button.bd-link[disabled] { color: var(--bd-t4); cursor: not-allowed; text-decoration: none; }
button.bd-link[disabled]:hover { text-decoration: none; }
button.bd-link:focus-visible { outline: 2px solid var(--bd-primary); outline-offset: 2px; border-radius: 3px; }

/* 分类维护弹窗 */
.bd-catmgr__hint { display: flex; align-items: flex-start; gap: 8px; font-size: 12.5px; color: var(--bd-t3); background: var(--bd-fill-1); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
.bd-catmgr__err { font-size: 12.5px; color: var(--bd-danger); background: var(--bd-danger-1, rgba(245, 63, 63, .08)); border-radius: 8px; padding: 9px 12px; margin-bottom: 12px; }
.bd-catmgr__t td { vertical-align: middle; }
.bd-catmgr__mv { display: inline-flex; margin-right: 8px; font-size: 13px; }
.bd-catmgr__bi { margin-left: 8px; color: var(--bd-t3); background: var(--bd-fill-2); }
.bd-catmgr__no { color: var(--bd-t4); }
.bd-catmgr__empty { color: var(--bd-t3); text-align: center; padding: 22px 0; }
.bd-catmgr__add { display: flex; gap: 10px; align-items: center; margin-top: 14px; }
.bd-catmgr__add :deep(.arco-input-wrapper) { flex: 1; }
.bd-catmgr__foot { font-size: 12px; color: var(--bd-t3); margin-top: 10px; }

/* 向导 */
.bd-wz { display: flex; flex-direction: column; height: 100%; }
.bd-wz__steps { padding: 6px 0 18px; }
.bd-wz__body { flex: 1; overflow-y: auto; padding-right: 2px; }
.bd-wz__hint { font-size: 13px; color: var(--bd-t3); margin-bottom: 14px; }
.bd-wz__note { display: flex; align-items: center; gap: 8px; font-size: 12.5px; color: var(--bd-t3); background: var(--bd-fill-1); border-radius: 8px; padding: 12px 14px; }
.bd-mode-card { width: 100%; display: flex; align-items: center; gap: 14px; padding: 16px; margin-bottom: 12px; border: 1.5px solid var(--bd-border); border-radius: 10px; background: #fff; cursor: pointer; text-align: left; transition: all .15s; }
.bd-mode-card:hover { border-color: var(--bd-primary-b); }
.bd-mode-card.on { border-color: var(--bd-primary); background: var(--bd-primary-1); }
.bd-mode-card__ic { width: 44px; height: 44px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 22px; flex: none; }
.bd-mode-card__txt b { font-size: 14px; display: block; color: var(--bd-t1); }
.bd-mode-card__txt i { font-style: normal; font-size: 12px; color: var(--bd-t3); }
.bd-mode-card__chk { margin-left: auto; color: var(--bd-primary); font-size: 20px; }

.bd-fld { margin-bottom: 16px; }
.bd-fld > label { display: block; font-size: 13px; font-weight: 500; color: var(--bd-t1); margin-bottom: 7px; }
.bd-fld :deep(.arco-input-wrapper), .bd-fld :deep(.arco-select-view), .bd-fld :deep(.arco-input-number) { width: 100%; }
.bd-fld--row { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.bd-fld--row label { margin-bottom: 2px; }
.bd-fld__d { font-size: 12px; color: var(--bd-t3); }
.bd-sec2 { font-size: 13px; font-weight: 600; margin: 18px 0 12px; }
.bd-chk-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.bd-wz__sub { font-size: 12px; color: var(--bd-t3); margin: -6px 0 14px; }
.bd-wm { background: var(--bd-fill-2); padding: 2px 8px; border-radius: 4px; color: var(--bd-t2); }
.bd-wz__summary { margin-top: 8px; background: var(--bd-primary-1); border: 1px solid var(--bd-primary-b); border-radius: 8px; padding: 12px 14px; font-size: 13px; }
.bd-wz__summary b { display: block; margin-bottom: 6px; }
.bd-wz__summary div { color: var(--bd-t2); font-size: 12.5px; }
.bd-wz__foot { display: flex; align-items: center; gap: 10px; padding-top: 16px; border-top: 1px solid var(--bd-fill-2); }
</style>
