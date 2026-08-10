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
        <div class="bd-cats__h">应用分类</div>
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
              <td>{{ a.authedUsers }} 用户</td>
              <td>
                <span class="bd-st"><span class="d" :style="{ background: a.status === 'running' ? 'var(--bd-success)' : 'var(--bd-t4)' }" />{{ a.status === 'running' ? '运行中' : '已停用' }}</span>
              </td>
              <td class="r"><span class="bd-link" @click="openWizard">编辑</span> <span class="bd-link bd-link--grey" style="margin-left: 12px">详情</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

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
              <a-option v-for="c in categories.filter(x => x.key !== 'all')" :key="c.key" :value="c.key">{{ c.label }}</a-option>
            </a-select>
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
import { ref, reactive, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type AppBundle, type App, type AppCategory, type Resource, type ResourcesResp } from '@/lib/api';

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
function tagStyle(color: string) { return { color, background: color + '14' }; }

// 向导只收集会真正提交后端的字段——收集了却静默丢弃的控件比没有更糟（见 CLAUDE.md 静默失效缺陷族）。
// DLP / 水印 / 浏览器管控 / XFF / 负载均衡等依赖七层代理，网关当前是 L4 隧道，暂无执行方，故不提供入口。
const STEPS = ['发布模式', '基础配置', '确认发布'];
const wz = reactive({
  open: false, step: 0, mode: '' as '' | 'tunnel' | 'web' | 'global',
  f: { name: '', cat: '', addr: '', resourceId: '' }
});
function openWizard() { wz.open = true; wz.step = 0; wz.mode = ''; wz.f.name = ''; wz.f.cat = ''; wz.f.addr = ''; wz.f.resourceId = ''; }
const canNext = computed(() => {
  if (wz.step === 0) return !!wz.mode;
  if (wz.step === 1) return !!wz.f.name && !!wz.f.addr;
  return true;
});
const publishing = ref(false);
const resources = ref<Resource[]>([]);
async function load() {
  try {
    const b = await api<AppBundle>('/apps');
    categories.value = b.categories; apps.value = b.apps; live.value = true;
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
      body: JSON.stringify({ name: wz.f.name, addr: wz.f.addr, mode: wz.mode, category: wz.f.cat || 'office', resourceId: wz.f.resourceId })
    });
    wz.open = false;
    Message.success(`应用「${wz.f.name}」已发布并落库`);
    cat.value = 'all';
    await load();
  } catch {
    Message.error('发布失败，请检查后端连接');
  } finally {
    publishing.value = false;
  }
}

onMounted(load);
</script>

<style scoped>
.bd-two { display: flex; gap: 16px; align-items: flex-start; }
.bd-cats { width: 210px; flex: none; padding: 12px; }
.bd-cats__h { font-size: 12px; font-weight: 600; color: var(--bd-t3); padding: 4px 8px 10px; }
.bd-cat { width: 100%; display: flex; align-items: center; gap: 9px; height: 36px; padding: 0 12px; border: none; background: transparent; border-radius: 7px; cursor: pointer; font-size: 13px; color: var(--bd-t2); }
.bd-cat:hover { background: var(--bd-fill-2); }
.bd-cat.on { background: var(--bd-primary-1); color: var(--bd-primary); font-weight: 500; }
.bd-cat__ic { font-size: 15px; }
.bd-cat__t { flex: 1; text-align: left; }
.bd-cat__n { font-size: 11px; color: var(--bd-t3); }
.bd-toolbar__c { font-size: 12.5px; color: var(--bd-t3); }
.bd-appic { width: 34px; height: 34px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; font-size: 17px; flex: none; }

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
