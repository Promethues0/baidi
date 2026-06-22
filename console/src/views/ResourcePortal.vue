<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">应用门户编排<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">门户入口 = 被授权资源的用户可见投影（ZL-FR-103/603）· 可见性由策略推导，此处只编排呈现</div>
      </div>
      <a-button type="primary" @click="show = true"><template #icon><icon-plus /></template>新建门户分组</a-button>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1.5fr 1fr;">
      <!-- 分组编排 -->
      <div style="display:flex;flex-direction:column;gap:14px;min-width:0">
        <div v-for="g in portal" :key="g.name" class="zl-card zl-card__pad">
          <div class="pt-group__head">
            <span class="pt-group__name">{{ g.name }}</span>
            <div style="display:flex;align-items:center;gap:10px">
              <span class="pt-group__meta">{{ g.items.length }} 项 · 可见范围：{{ g.audience }}</span>
              <a-button size="mini" type="text" @click="openAdd(g)"><template #icon><icon-plus /></template>加应用</a-button>
              <a-popconfirm content="删除该分组及其全部门户项？" @ok="delGroup(g)">
                <a-button size="mini" type="text" status="danger"><icon-delete /></a-button>
              </a-popconfirm>
            </div>
          </div>
          <div class="pt-items">
            <div v-for="(it, i) in g.items" :key="it.name" class="pt-item">
              <span class="pt-tile" :data-proto="it.proto">{{ it.proto }}</span>
              <div class="pt-item__main">
                <div class="pt-item__name">{{ it.name }} <icon-lock v-if="it.stepup" style="color:var(--warn);font-size:12px" /></div>
                <div class="pt-item__addr data">{{ it.addr }}</div>
              </div>
              <a-space size="mini">
                <a-button size="mini" type="text" :disabled="i===0" @click="move(g, i, -1)"><icon-up /></a-button>
                <a-button size="mini" type="text" :disabled="i===g.items.length-1" @click="move(g, i, 1)"><icon-down /></a-button>
                <a-switch v-model="it.visible" size="small" @change="vis(it)" />
                <a-button size="mini" type="text" status="danger" @click="delItem(g, i)"><icon-close /></a-button>
              </a-space>
            </div>
            <div v-if="!g.items.length" class="pt-empty">空分组 · 点「加应用」从资源对象挑选</div>
          </div>
        </div>
      </div>

      <!-- 客户端预览 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title" style="margin-bottom:4px">客户端门户预览</div>
        <div class="zl-page__sub" style="margin-bottom:12px">以 张伟（研发-动态）视角 · 隐藏项与未授权项不出现</div>
        <div class="pt-phone">
          <div class="pt-phone__head data">白帝 · 应用门户</div>
          <template v-for="g in portal" :key="g.name">
            <div v-if="g.items.some(i=>i.visible)" class="pt-phone__group">{{ g.name }}</div>
            <div v-for="it in g.items.filter(i=>i.visible)" :key="it.name" class="pt-phone__item">
              <span class="pt-tile sm" :data-proto="it.proto">{{ it.proto }}</span>
              <span class="pt-phone__name">{{ it.name }}</span>
              <span v-if="it.stepup" style="font-size:10px">🔒</span>
            </div>
          </template>
        </div>
      </div>
    </div>

    <a-modal v-model:visible="show" title="新建门户分组" @ok="add" ok-text="创建">
      <a-form :model="form" layout="vertical">
        <a-form-item label="分组名称" required><a-input v-model="form.name" placeholder="例如：数据与报表" /></a-form-item>
        <a-form-item label="可见范围（展示层过滤，不替代策略授权）">
          <a-select v-model="form.audience">
            <a-option>全体员工</a-option><a-option>研发-动态</a-option><a-option>财务</a-option><a-option>运维</a-option>
          </a-select>
        </a-form-item>
      </a-form>
    </a-modal>

    <a-modal v-model:visible="addShow" :title="`向「${addGroup?.name}」添加应用`" @ok="doAdd" ok-text="添加">
      <a-form :model="addForm" layout="vertical">
        <a-form-item label="选择资源对象">
          <a-select v-model="addForm.res" placeholder="从已定义资源对象挑选" allow-search>
            <a-option v-for="r in resourceOpts" :key="r.name" :value="r.name" :disabled="inGroup(r.name)">
              {{ r.name }} · {{ r.addr }}{{ inGroup(r.name) ? '（已在本组）' : '' }}
            </a-option>
          </a-select>
        </a-form-item>
        <div style="font-size:11.5px;color:var(--ink-3);line-height:1.6">门户入口仅为呈现投影；用户能否真正访问由策略授权决定（未授权项即便加入也不会出现在其门户）。</div>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message } from '@arco-design/web-vue';
import { resources } from '@/mock';

interface PItem { name: string; proto: string; addr: string; stepup: boolean; visible: boolean; }
interface PGroup { name: string; audience: string; items: PItem[]; }

// 资源对象 → 门户协议标记
const protoOf = (r: any) => {
  if (r.type === 'app') return /^https?:/.test(r.addr) ? 'WEB' : 'WEB';
  if (r.type === 'service') return /:22$/.test(r.addr) ? 'SSH' : 'TCP';
  if (r.type === 'site') return 'WEB';
  return 'NET';
};

const mockPortal: PGroup[] = [
  { name: '办公协同', audience: '全体员工', items: [
    { name: 'OA 办公系统', proto: 'WEB', addr: 'oa.corp', stepup: false, visible: true },
    { name: '财务系统', proto: 'WEB', addr: 'finance.corp', stepup: true, visible: true }
  ] },
  { name: '研发工具', audience: '研发-动态', items: [
    { name: 'GitLab', proto: 'WEB', addr: 'gitlab.corp', stepup: false, visible: true },
    { name: '核心数据库', proto: 'TCP', addr: 'db.corp:5432', stepup: true, visible: true },
    { name: '堡垒机', proto: 'SSH', addr: 'bastion.corp:22', stepup: true, visible: false }
  ] },
  { name: '分支业务', audience: '上海分支', items: [{ name: '上海分支 ERP', proto: 'WEB', addr: 'erp.sh.corp', stepup: false, visible: true }] }
];

/* 门户编排整份布局存控制面 /ctl/api/coll?kind=portal（key=layout）；编排改动后
   保存整份布局（排序/可见/分组持久化），控制面不可达时降级 mock。 */
const portal = ref<PGroup[]>([...mockPortal]);
const live = ref(false);
async function loadPortal() {
  try {
    const r = await fetch('/ctl/api/coll?kind=portal');
    if (!r.ok) return;
    const docs = await r.json();
    if (docs.length) portal.value = docs[0]; // layout doc 即整份布局数组
    live.value = true;
  } catch { live.value = false; }
}
onMounted(loadPortal);

async function savePortal() {
  if (!live.value) return;
  try {
    await fetch('/ctl/api/coll?kind=portal', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key: 'layout', doc: portal.value }) });
  } catch { /* 忽略保存失败 */ }
}

const move = (g: PGroup, i: number, d: number) => {
  const [it] = g.items.splice(i, 1);
  g.items.splice(i + d, 0, it);
  savePortal();
};
const vis = (it: PItem) => {
  Message.info(`「${it.name}」已${it.visible ? '在门户展示' : '从门户隐藏'}（不影响策略授权）${live.value ? ' · 已持久化' : ''}`);
  savePortal();
};
const delItem = (g: PGroup, i: number) => {
  const [it] = g.items.splice(i, 1);
  savePortal();
  Message.info(`已从「${g.name}」移除「${it.name}」`);
};
const delGroup = (g: PGroup) => {
  portal.value = portal.value.filter((x) => x !== g);
  savePortal();
  Message.success(`分组「${g.name}」已删除`);
};

/* —— 向分组加应用（从资源对象挑选）—— */
const addShow = ref(false);
const addGroup = ref<PGroup | null>(null);
const addForm = reactive({ res: '' });
const resourceOpts = computed(() => resources);
const inGroup = (name: string) => !!addGroup.value?.items.some((i) => i.name === name);
const openAdd = (g: PGroup) => { addGroup.value = g; addForm.res = ''; addShow.value = true; };
const doAdd = () => {
  if (!addForm.res || !addGroup.value) return Message.warning('请选择资源对象');
  const r = resources.find((x: any) => x.name === addForm.res)!;
  addGroup.value.items.push({ name: r.name, proto: protoOf(r), addr: r.addr, stepup: !!r.stepup, visible: true });
  savePortal();
  Message.success(`「${r.name}」已加入「${addGroup.value.name}」· 高敏项仍受二次鉴权约束`);
  addShow.value = false;
};

const show = ref(false);
const form = reactive({ name: '', audience: '全体员工' });
async function add() {
  if (!form.name) return Message.warning('请填写分组名称');
  portal.value.push({ name: form.name, audience: form.audience, items: [] });
  await savePortal();
  Message.success(`分组「${form.name}」已创建${live.value ? ' · 已持久化' : ''}`);
  form.name = '';
}
</script>

<style scoped>
.pt-group__head { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 10px; }
.pt-group__name { font-size: 14px; font-weight: 700; color: var(--ink); }
.pt-group__meta { font-size: 11.5px; color: var(--ink-3); }
.pt-items { display: flex; flex-direction: column; }
.pt-item { display: flex; align-items: center; gap: 12px; padding: 9px 0; }
.pt-item + .pt-item { border-top: 1px solid var(--line); }
.pt-tile {
  width: 38px; height: 38px; border-radius: 11px; flex: none; display: grid; place-items: center;
  font-size: 10px; font-weight: 800; font-family: var(--font-data);
  background: var(--accent-soft); color: var(--accent-2);
}
.pt-tile.sm { width: 28px; height: 28px; border-radius: 8px; font-size: 8.5px; }
.pt-tile[data-proto='TCP'] { background: var(--ok-soft); color: var(--ok); }
.pt-tile[data-proto='SSH'] { background: var(--warn-soft); color: var(--warn); }
.pt-item__main { flex: 1; min-width: 0; }
.pt-item__name { font-size: 13px; font-weight: 650; color: var(--ink); display: flex; align-items: center; gap: 5px; }
.pt-item__addr { font-size: 11px; color: var(--ink-3); }
.pt-phone { border: 1px solid var(--line-2); border-radius: 18px; padding: 14px; background: var(--surface-2); }
.pt-phone__head { font-size: 11px; color: var(--ink-3); text-align: center; margin-bottom: 10px; letter-spacing: .05em; }
.pt-phone__group { font-size: 10.5px; font-weight: 700; color: var(--ink-3); margin: 10px 2px 5px; }
.pt-phone__item { display: flex; align-items: center; gap: 9px; background: var(--surface); border-radius: 10px; padding: 7px 10px; margin-bottom: 6px; box-shadow: var(--shadow-sm); }
.pt-phone__name { font-size: 12px; font-weight: 600; color: var(--ink); flex: 1; }
</style>
