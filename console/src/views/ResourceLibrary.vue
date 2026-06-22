<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">对象库<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">对象先定义、策略只引用（ZL-FR-601，习自在用防火墙走查）· 对象变更自动传播到全部引用方</div>
      </div>
      <a-button type="primary" @click="show = true"><template #icon><icon-plus /></template>新建对象</a-button>
    </div>

    <div class="zl-card">
      <a-tabs v-model:active-key="tab" type="rounded" style="padding: 12px 16px 0;">
        <a-tab-pane v-for="(g, k) in lib" :key="k" :title="`${g.title}（${g.items.length}）`" />
      </a-tabs>
      <a-table :data="lib[tab].items" :pagination="false" :bordered="false" row-key="name">
        <template #columns>
          <a-table-column title="对象" data-index="name" :width="180">
            <template #cell="{ record }"><span style="font-weight:600;color:var(--ink)">{{ record.name }}</span></template>
          </a-table-column>
          <a-table-column title="定义">
            <template #cell="{ record }"><span class="data" style="font-size:12px;color:var(--ink-2)">{{ record.def }}</span></template>
          </a-table-column>
          <a-table-column title="说明">
            <template #cell="{ record }"><span style="font-size:12px;color:var(--ink-3)">{{ record.note }}</span></template>
          </a-table-column>
          <a-table-column title="被引用" align="center" :width="100">
            <template #cell="{ record }">
              <a-tooltip :content="record.refs.length ? '被引用：' + record.refs.join('、') : '未被引用'">
                <span class="zl-badge" :class="record.refs.length ? 'zl-badge--accent' : 'zl-badge--idle'">{{ record.refs.length }} 处</span>
              </a-tooltip>
            </template>
          </a-table-column>
          <a-table-column title="" align="center" :width="80">
            <template #cell="{ record }">
              <a-popconfirm :content="record.refs.length ? `仍被 ${record.refs.length} 处引用，不可删除` : '删除该对象？'"
                            :ok-button-props="{ disabled: !!record.refs.length }" @ok="del(record)">
                <a-button size="mini" type="text" status="danger">删除</a-button>
              </a-popconfirm>
            </template>
          </a-table-column>
        </template>
      </a-table>
    </div>

    <a-modal v-model:visible="show" :title="`新建${lib[tab].title}对象`" @ok="add" ok-text="创建">
      <a-form :model="form" layout="vertical">
        <a-form-item label="对象名称" required><a-input v-model="form.name" :placeholder="lib[tab].egName" /></a-form-item>
        <a-form-item :label="lib[tab].defLabel" required><a-input v-model="form.def" :placeholder="lib[tab].egDef" /></a-form-item>
        <a-form-item label="说明"><a-input v-model="form.note" /></a-form-item>
      </a-form>
      <div style="font-size:11.5px;color:var(--ink-3);line-height:1.6">策略引用对象 ID 而非字面量；对象变更后引用它的策略自动重编译下发（≤60s）。</div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { Message } from '@arco-design/web-vue';

interface LibItem { name: string; def: string; note: string; refs: string[]; }
const live = ref(false);
const lib = reactive<Record<string, { title: string; defLabel: string; egName: string; egDef: string; items: LibItem[] }>>({
  addr: {
    title: '地址', defLabel: 'IP / CIDR / 范围', egName: '总部办公网', egDef: '10.8.0.0/16',
    items: [
      { name: '总部办公网', def: '10.8.0.0/16', note: '连接器 conn-hq-01 发布', refs: ['pol-branch-erp', 'conn-hq-01'] },
      { name: '上海分支网段', def: '10.20.0.0/16', note: 'IPSec selector 引用', refs: ['pol-branch-erp', 'tun-hq-sh'] },
      { name: 'DMZ 段', def: '192.168.1.0/24', note: '', refs: ['conn-hq-01'] },
      { name: '合作方放行段', def: '192.168.77.0/24', note: '仅 tun-sh-partner 使用', refs: ['tun-sh-partner'] }
    ]
  },
  svc: {
    title: '服务', defLabel: '主机:端口（支持通配）', egName: '核心数据库', egDef: 'db.corp:5432',
    items: [
      { name: '核心数据库', def: 'db.corp:5432', note: '高敏 · 强制二次鉴权', refs: ['pol-rd-database'] },
      { name: '全网 SSH', def: '*.corp:22', note: '通配服务对象', refs: ['pol-ops-ssh'] },
      { name: 'Git 服务', def: 'gitlab.corp:443', note: '', refs: ['pol-rd-database'] }
    ]
  },
  time: {
    title: '时间', defLabel: '时间表达式', egName: '工作时间', egDef: '周一至周五 09:00–19:00',
    items: [
      { name: '工作时间', def: '周一至周五 09:00–19:00', note: 'time: workhours 谓词来源', refs: ['pol-ops-ssh'] },
      { name: '运维窗口', def: '每日 22:00–02:00', note: '变更窗口', refs: [] }
    ]
  },
  url: {
    title: 'URL', defLabel: 'URL 模式', egName: 'OA 入口', egDef: 'https://oa.corp/*',
    items: [
      { name: 'OA 入口', def: 'https://oa.corp/*', note: '门户应用入口', refs: ['pol-oa-all'] },
      { name: '财务报销路径', def: 'https://finance.corp/expense/*', note: '页面级授权（ZL-FR-603 分层）', refs: ['pol-finance-fin'] }
    ]
  }
});
const tab = ref('addr');

/* 对象库来自控制面 /ctl/api/coll?kind=lib（持久化，doc 带 cat 分类），不可达时降级 mock */
async function loadLib() {
  try {
    const r = await fetch('/ctl/api/coll?kind=lib');
    if (!r.ok) return;
    const docs = await r.json();
    for (const k in lib) lib[k].items = [];
    for (const d of docs) {
      if (lib[d.cat]) lib[d.cat].items.push({ name: d.name, def: d.def, note: d.note || '', refs: d.refs || [] });
    }
    live.value = true;
  } catch { live.value = false; }
}
onMounted(loadLib);

const show = ref(false);
const form = reactive({ name: '', def: '', note: '' });
async function add() {
  if (!form.name || !form.def) return Message.warning('名称与定义为必填');
  const cat = tab.value;
  const doc = { cat, name: form.name, def: form.def, note: form.note, refs: [] as string[] };
  if (live.value) {
    try {
      const r = await fetch('/ctl/api/coll?kind=lib', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key: cat + '/' + form.name, doc }) });
      if (!r.ok) return Message.error('创建失败');
      await loadLib();
    } catch { return Message.error('控制面不可达'); }
  } else {
    lib[cat].items.unshift({ name: doc.name, def: doc.def, note: doc.note, refs: [] });
  }
  Message.success(`${lib[cat].title}对象「${form.name}」已创建${live.value ? ' · 已持久化' : ''}`);
  Object.assign(form, { name: '', def: '', note: '' });
}
async function del(r: LibItem) {
  if (r.refs.length) return;
  const cat = tab.value;
  if (live.value) {
    try {
      const res = await fetch(`/ctl/api/coll?kind=lib&key=${encodeURIComponent(cat + '/' + r.name)}`, { method: 'DELETE' });
      if (!res.ok) return Message.error('删除失败');
      await loadLib();
    } catch { return Message.error('控制面不可达'); }
  } else {
    const items = lib[cat].items;
    const i = items.findIndex((x) => x.name === r.name);
    if (i >= 0) items.splice(i, 1);
  }
  Message.success(`已删除「${r.name}」`);
}
</script>
