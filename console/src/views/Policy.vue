<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">统一策略</h1>
        <div class="zl-page__sub">一份策略，三个执行点 · 编译器翻译到 Mesh / SSL / IPSec 数据面（ZL-FR-104）· 求值序：deny &gt; allow &gt; 默认拒绝</div>
      </div>
      <a-space>
        <a-radio-group v-model="viewMode" type="button" size="small">
          <a-radio value="policy">按策略</a-radio>
          <a-radio value="resource">按资源</a-radio>
        </a-radio-group>
        <a-button type="primary" @click="openCreate"><template #icon><icon-plus /></template>新建策略</a-button>
      </a-space>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1.6fr 1fr;">
      <!-- 策略表 -->
      <div class="zl-card">
        <a-table v-if="viewMode==='policy'" :data="rows" :pagination="false" :bordered="false" row-key="id"
                 :row-class="(r:any)=> r.id===sel?.id ? 'row-on':''" @row-click="(r:any)=>sel=r">
          <template #columns>
            <a-table-column title="策略 ID" data-index="id">
              <template #cell="{ record }">
                <span class="data" style="font-size:12.5px;font-weight:600;color:var(--ink)">{{ record.id }}</span>
                <div class="pol-sub data">{{ record.subjects.join('，') }} → {{ record.resources.join('，') }}</div>
              </template>
            </a-table-column>
            <a-table-column title="动作" align="center" :width="70">
              <template #cell="{ record }">
                <span class="zl-badge" :class="record.action==='allow'?'zl-badge--ok':'zl-badge--danger'">{{ record.action === 'allow' ? '允许' : '拒绝' }}</span>
              </template>
            </a-table-column>
            <a-table-column title="条件" align="center" :width="64">
              <template #cell="{ record }">
                <a-tooltip v-if="condStrings(record).length" :content="condStrings(record).join('；')">
                  <span class="zl-badge zl-badge--accent">{{ condStrings(record).length }}</span>
                </a-tooltip>
                <span v-else style="color:var(--ink-3)">—</span>
              </template>
            </a-table-column>
            <a-table-column title="模式" align="center" :width="74">
              <template #cell="{ record }"><span class="zl-mode-pill" :class="modeClass(record.modes)">{{ record.modes }}</span></template>
            </a-table-column>
            <a-table-column title="命中" align="right" :width="72">
              <template #cell="{ record }"><span class="data">{{ record.hits.toLocaleString() }}</span></template>
            </a-table-column>
            <a-table-column title="启用" align="center" :width="56">
              <template #cell="{ record }"><a-switch v-model="record.enabled" size="small" @click.stop /></template>
            </a-table-column>
            <a-table-column title="" align="center" :width="92">
              <template #cell="{ record }">
                <a-button size="mini" type="text" @click.stop="openEdit(record)">编辑</a-button>
                <a-button size="mini" type="text" status="danger" @click.stop="del(record)">删除</a-button>
              </template>
            </a-table-column>
          </template>
        </a-table>

        <!-- 按资源视图：原「资源授权」已并入此处，按资源反查命中策略 -->
        <div v-else class="res-view">
          <div class="res-view__note">「资源授权」已并入统一策略：下面按资源维度查看每个资源被哪些策略放行 / 拒绝（含条件）。授权的唯一事实来源是策略本身（policy-store 求值，deny &gt; allow &gt; 默认拒绝），不再有平行的第二套授权表。</div>
          <div v-for="g in byResource" :key="g.resource" class="res-grp">
            <div class="res-grp__head">
              <span class="data res-grp__name">{{ g.resource }}</span>
              <span class="res-grp__count">{{ g.pols.length }} 条策略</span>
            </div>
            <div v-for="p in g.pols" :key="p.id" class="res-pol" :class="{ on: sel?.id===p.id }" @click="sel=p">
              <span class="zl-badge" :class="p.action==='allow'?'zl-badge--ok':'zl-badge--danger'">{{ p.action==='allow'?'允许':'拒绝' }}</span>
              <span class="res-pol__id data">{{ p.id }}</span>
              <span class="res-pol__subj data">{{ p.subjects.join('，') }}</span>
              <span v-if="p.cond?.notAfter" class="zl-badge zl-badge--idle" title="限时授权有效期">限时 · 至 {{ p.cond.notAfter }}</span>
              <a-tooltip v-if="condStrings(p).length" :content="condStrings(p).join('；')">
                <span class="zl-badge zl-badge--accent">{{ condStrings(p).length }} 条件</span>
              </a-tooltip>
              <a-switch v-model="p.enabled" size="small" @click.stop />
            </div>
          </div>
          <div v-if="!byResource.length" class="zl-soon" style="min-height:200px">
            <icon-select-all style="font-size:24px" /><span>暂无资源授权 · 新建一条 allow 策略即可</span>
          </div>
        </div>
      </div>

      <!-- 三执行点编译预览 -->
      <div class="zl-card zl-card__pad" v-if="sel">
        <div class="zl-card__title">编译预览 · <span class="data" style="color:var(--accent-2)">{{ sel.id }}</span></div>
        <div class="pol-src">
          <div class="pol-src__row"><b>主体</b><span>{{ sel.subjects.join('，') }}</span></div>
          <div class="pol-src__row"><b>客体</b><span>{{ sel.resources.join('，') }}</span></div>
          <div class="pol-src__row"><b>条件</b><span>{{ condStrings(sel).length ? condStrings(sel).join('；') : '无' }}</span></div>
        </div>
        <!-- CEL 表达式 -->
        <div class="pol-cel">
          <span class="pol-cel__tag data">CEL</span>
          <pre class="pol-cel__code data">{{ cel(sel) }}</pre>
        </div>

        <div class="pol-arrow">↓ 编译器 · 默认拒绝优先</div>

        <div class="pol-exec" v-for="ep in execPoints" :key="ep.key">
          <div class="pol-exec__head">
            <span class="zl-mode-pill" :class="`zl-mode--${ep.key}`">{{ ep.key }}</span>
            <span class="pol-exec__name">{{ ep.name }}</span>
            <span class="pol-exec__v" :class="ep.active(sel) ? 'on':''">{{ ep.active(sel) ? '已下发' : '不适用' }}</span>
          </div>
          <pre class="pol-exec__code data">{{ ep.compile(sel) }}</pre>
        </div>
      </div>
      <div class="zl-card zl-soon" v-else>
        <icon-select-all style="font-size: 28px;" />
        <span>选择左侧一条策略，查看它编译到三执行点的结果</span>
      </div>
    </div>

    <!-- 新建 / 编辑 -->
    <a-modal v-model:visible="show" :title="editing ? `编辑策略 · ${form.id}` : '新建策略'" width="600px" @ok="save" :ok-text="editing ? '保存并重编译' : '创建并下发'">
      <a-form :model="form" layout="vertical">
        <a-form-item label="策略 ID" required>
          <a-input v-model="form.id" placeholder="pol-xxx（小写中划线）" :disabled="editing" />
        </a-form-item>
        <a-form-item label="动作">
          <a-radio-group v-model="form.action" type="button">
            <a-radio value="allow">允许 allow</a-radio>
            <a-radio value="deny">拒绝 deny（优先于一切 allow）</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item label="主体（可多选 · group/tag/user/site）">
          <a-select v-model="form.subjects" multiple allow-create placeholder="group:/tag:/user:/site:">
            <a-option v-for="s in subjectOpts" :key="s" :value="s">{{ s }}</a-option>
          </a-select>
        </a-form-item>
        <a-form-item label="资源（可多选，引用统一资源对象）">
          <a-select v-model="form.resources" multiple allow-create>
            <a-option v-for="r in resourceOpts" :key="r" :value="r">{{ r }}</a-option>
          </a-select>
        </a-form-item>

        <!-- 条件谓词 -->
        <a-form-item label="访问条件（CEL 条件谓词 · 全部满足才放行）">
          <div class="cond-list">
            <div v-for="c in condDefs" :key="c.k" class="cond-item" :class="{ on: form.conditions.includes(c.k) }" @click="toggleCond(c.k)">
              <a-checkbox :model-value="form.conditions.includes(c.k)" @click.stop="toggleCond(c.k)" />
              <div class="cond-item__main">
                <div class="cond-item__name">{{ c.name }} <code class="data">{{ c.cel }}</code></div>
                <div class="cond-item__desc">{{ c.desc }}</div>
                <router-link v-if="c.link" :to="c.link" class="cond-item__src" @click.stop>{{ c.note }} →</router-link>
              </div>
            </div>
          </div>
        </a-form-item>

        <a-form-item label="模式约束 access_modes">
          <a-radio-group v-model="form.modes" type="button">
            <a-radio value="auto">auto</a-radio><a-radio value="ssl">ssl</a-radio>
            <a-radio value="mesh">mesh</a-radio><a-radio value="ipsec">ipsec</a-radio>
          </a-radio-group>
        </a-form-item>

        <!-- 实时 CEL 预览 -->
        <div class="cond-cel">
          <span class="pol-cel__tag data">编译预览 CEL</span>
          <pre class="pol-cel__code data">{{ celFromForm() }}</pre>
        </div>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, ref } from 'vue';
import { useRoute } from 'vue-router';
import { Message, Modal } from '@arco-design/web-vue';
import { policyStore, condStrings, netmapState, type Pol as PolicyRow } from '@/policy-store';

const rows = policyStore;
const sel = ref<PolicyRow | null>(rows[0]);

// 视图维度：按策略（默认）/ 按资源（原「资源授权」并入此处，?view=resource 直达）
const route = useRoute();
const viewMode = ref<'policy' | 'resource'>(route.query.view === 'resource' ? 'resource' : 'policy');
const byResource = computed(() => {
  const map = new Map<string, PolicyRow[]>();
  for (const p of rows) for (const r of p.resources) {
    const arr = map.get(r) ?? [];
    arr.push(p);
    map.set(r, arr);
  }
  return [...map.entries()]
    .map(([resource, pols]) => ({ resource, pols }))
    .sort((a, b) => a.resource.localeCompare(b.resource));
});

const subjectOpts = ['group:研发-动态', 'group:全体员工', 'group:BYOD', 'group:运维', 'group:财务', 'tag:ci-runner', 'site:上海分支'];
const resourceOpts = ['app:oa.corp', 'app:gitlab', 'app:finance', 'service:db.corp:5432', 'service:*.corp:22', 'subnet:10.20.0.0/16'];

// 条件谓词定义（仅含求值引擎真实支持的三项，CEL 为编译形态）
const condDefs: { k: string; name: string; cel: string; desc: string; note?: string; link?: string }[] = [
  { k: 'auth: mfa', name: 'MFA 强认证', cel: 'auth.strength >= mfa', desc: '本次会话已完成二次认证（auth_strength）', note: '强度阈值由身份中心〈认证策略〉签发，访问门仅消费', link: '/identity/auth-policy' },
  { k: 'posture: disk_encrypted', name: '终端基线', cel: 'device.posture.compliant', desc: '设备通过 posture 最小集（盘加密 / 未越狱 / 版本合规）' },
  { k: 'time: workhours', name: '工作时间', cel: 'request.time in time:workhours', desc: '请求落在工作时间对象窗口内（引用时间对象）' }
];

const show = ref(false);
const editing = ref(false);
const form = reactive({ id: '', action: 'allow', subjects: [] as string[], resources: [] as string[], conditions: [] as string[], modes: 'auto' });

function toggleCond(k: string) {
  const i = form.conditions.indexOf(k);
  if (i >= 0) form.conditions.splice(i, 1); else form.conditions.push(k);
}

function openCreate() {
  editing.value = false;
  Object.assign(form, { id: '', action: 'allow', subjects: [], resources: [], conditions: [], modes: 'auto' });
  show.value = true;
}
function openEdit(p: PolicyRow) {
  editing.value = true;
  Object.assign(form, {
    id: p.id, action: p.action, subjects: [...p.subjects], resources: [...p.resources], modes: p.modes,
    conditions: [...(p.cond.mfa ? ['auth: mfa'] : []), ...(p.cond.posture ? ['posture: disk_encrypted'] : []), ...(p.cond.workhours ? ['time: workhours'] : [])]
  });
  show.value = true;
}

function formCond() {
  return { mfa: form.conditions.includes('auth: mfa'), posture: form.conditions.includes('posture: disk_encrypted'), workhours: form.conditions.includes('time: workhours') };
}

function save() {
  if (!form.id || !form.subjects.length || !form.resources.length) return Message.warning('策略 ID / 主体 / 资源为必填');
  if (editing.value) {
    const p = rows.find((x) => x.id === form.id);
    if (!p) return;
    p.action = form.action as any; p.subjects = [...form.subjects]; p.resources = [...form.resources]; p.modes = form.modes; p.cond = formCond();
    Message.success(`策略 ${form.id} 已更新 · netmap v${netmapState.version + 1} 重编译下发（引用方 ≤60s 生效）`);
  } else {
    if (rows.some((x) => x.id === form.id)) return Message.error(`策略 ${form.id} 已存在`);
    const row: PolicyRow = { id: form.id, subjects: [...form.subjects], resources: [...form.resources], action: form.action as any, cond: formCond(), modes: form.modes, hits: 0, enabled: true };
    rows.unshift(row); sel.value = row;
    Message.success(`策略 ${form.id} 已创建 · netmap v${netmapState.version + 1} 编译下发中（客户端 ≤2s 拉取）`);
  }
  show.value = false;
}

function del(p: PolicyRow) {
  Modal.warning({
    title: `删除策略「${p.id}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: `删除后，依赖此策略放行的主体将落入默认拒绝（零信任缺省）。netmap 立即重编译下发，进入审计链。`,
    onOk: () => {
      const i = rows.findIndex((x) => x.id === p.id);
      if (i >= 0) rows.splice(i, 1);
      if (sel.value?.id === p.id) sel.value = rows[0] ?? null;
      Message.success(`策略「${p.id}」已删除 · netmap 重编译`);
    }
  });
}

/* —— CEL 表达式合成 —— */
function celOf(action: string, subjects: string[], resources: string[], cond: { mfa?: boolean; posture?: boolean; workhours?: boolean }) {
  const subj = subjects.length ? subjects.map((s) => `"${s}"`).join(', ') : '∅';
  const res = resources.length ? resources.map((r) => `"${r}"`).join(', ') : '∅';
  const preds = [
    ...(cond.mfa ? ['auth.strength >= mfa'] : []),
    ...(cond.posture ? ['device.posture.compliant'] : []),
    ...(cond.workhours ? ['request.time in time:workhours'] : [])
  ];
  const when = preds.length ? `\n  when ${preds.join(' &&\n       ')}` : '';
  return `${action} if subject in [${subj}]\n  access resource in [${res}]${when}`;
}
const cel = (p: PolicyRow) => celOf(p.action, p.subjects, p.resources, p.cond);
const celFromForm = () => celOf(form.action, form.subjects, form.resources, formCond());

function modeClass(m: string) { return m === 'auto' ? '' : `zl-mode--${m}`; }
function applies(p: PolicyRow, mode: string) { return p.modes === 'auto' || p.modes === mode; }

const execPoints = [
  {
    key: 'mesh', name: 'Mesh 执行点 · netmap + 包过滤', active: (p: PolicyRow) => applies(p, 'mesh'),
    compile: (p: PolicyRow) => applies(p, 'mesh') ? `# netmap ACL (端侧执行)\n${p.action} ${p.subjects.join(',')}\n  -> ${p.resources.join(',')}` : '（该策略锁定为 ' + p.modes + ' 模式，Mesh 不下发）'
  },
  {
    key: 'ssl', name: 'SSL 执行点 · 代理授权表 + SPA', active: (p: PolicyRow) => applies(p, 'ssl'),
    compile: (p: PolicyRow) => applies(p, 'ssl') ? `# proxy_acl + spa_allow\nrule { ${p.action}\n  who: ${p.subjects.join(', ')}\n  res: ${p.resources.join(', ')} }` : '（锁定为 ' + p.modes + '，SSL 不下发）'
  },
  {
    key: 'ipsec', name: 'IPSec 执行点 · selector / SA（站点粒度）', active: (p: PolicyRow) => applies(p, 'ipsec') && p.resources.some((r) => r.startsWith('subnet:')),
    compile: (p: PolicyRow) => {
      const subnets = p.resources.filter((r) => r.startsWith('subnet:'));
      if (!applies(p, 'ipsec')) return '（锁定为 ' + p.modes + '，IPSec 不下发）';
      if (!subnets.length) return '（无 subnet 客体，IPSec 站点粒度不适用 · 取交集后为空）';
      return `# traffic selector / child SA\nleft=site  right=${subnets.join(',')}\naction=${p.action}`;
    }
  }
];
</script>

<style scoped>
:deep(.row-on) { background: var(--accent-soft) !important; }
:deep(.arco-table-tr) { cursor: pointer; }
.pol-sub { font-size: 11px; color: var(--ink-3); margin-top: 2px; }
.pol-src { margin-top: 12px; background: var(--surface-2); border-radius: var(--r-md); padding: 12px 14px; }
.pol-src__row { display: flex; gap: 10px; font-size: 12.5px; padding: 3px 0; }
.pol-src__row b { color: var(--ink-3); font-weight: 600; min-width: 34px; flex: none; }
.pol-src__row span { color: var(--ink); }
.pol-cel { margin-top: 10px; display: flex; gap: 8px; align-items: flex-start; }
.cond-cel { margin-top: 14px; display: flex; gap: 8px; align-items: flex-start; }
.pol-cel__tag { font-size: 10px; font-weight: 700; color: var(--accent-2); background: var(--accent-soft); border-radius: 5px; padding: 3px 7px; flex: none; margin-top: 2px; }
.pol-cel__code { margin: 0; padding: 8px 10px; font-size: 11px; line-height: 1.55; color: var(--ink-2); white-space: pre-wrap; background: var(--surface-2); border-radius: var(--r-md); flex: 1; min-width: 0; }
.pol-arrow { text-align: center; font-size: 12px; color: var(--ink-3); margin: 12px 0; }
.pol-exec { border: 1px solid var(--line); border-radius: var(--r-md); margin-bottom: 10px; overflow: hidden; }
.pol-exec__head { display: flex; align-items: center; gap: 8px; padding: 9px 12px; background: var(--surface-2); }
.pol-exec__name { flex: 1; font-size: 12.5px; font-weight: 600; color: var(--ink); }
.pol-exec__v { font-size: 11px; color: var(--ink-3); }
.pol-exec__v.on { color: var(--ok); font-weight: 600; }
.pol-exec__code { margin: 0; padding: 10px 12px; font-size: 11.5px; line-height: 1.55; color: var(--ink-2); white-space: pre-wrap; }
.cond-list { display: flex; flex-direction: column; gap: 8px; width: 100%; }
.cond-item { display: flex; align-items: flex-start; gap: 10px; padding: 10px 12px; border: 1px solid var(--line); border-radius: var(--r-md); cursor: pointer; transition: all .15s; }
.cond-item:hover { border-color: var(--accent-line); }
.cond-item.on { border-color: var(--accent-2); background: var(--accent-soft); }
.cond-item__main { flex: 1; min-width: 0; }
.cond-item__name { font-size: 12.5px; font-weight: 650; color: var(--ink); display: flex; align-items: center; gap: 8px; }
.cond-item__name code { font-size: 10.5px; color: var(--accent-2); background: var(--surface); padding: 1px 6px; border-radius: 4px; }
.cond-item__desc { font-size: 11px; color: var(--ink-3); margin-top: 2px; }
.cond-item__src { display: inline-block; margin-top: 4px; font-size: 11px; color: var(--accent-2); text-decoration: none; }
.cond-item__src:hover { text-decoration: underline; }

/* 按资源视图（原资源授权并入） */
.res-view { padding: 12px 14px; display: flex; flex-direction: column; gap: 14px; }
.res-view__note { font-size: 11.5px; color: var(--ink-3); line-height: 1.6; background: var(--surface-2); border-radius: var(--r-md); padding: 10px 12px; }
.res-grp { border: 1px solid var(--line); border-radius: var(--r-md); overflow: hidden; }
.res-grp__head { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 9px 12px; background: var(--surface-2); border-bottom: 1px solid var(--line); }
.res-grp__name { font-size: 12.5px; font-weight: 650; color: var(--ink); }
.res-grp__count { font-size: 11px; color: var(--ink-3); }
.res-pol { display: flex; align-items: center; gap: 10px; padding: 9px 12px; cursor: pointer; transition: background .12s; }
.res-pol + .res-pol { border-top: 1px solid var(--line); }
.res-pol:hover { background: var(--surface-2); }
.res-pol.on { background: var(--accent-soft); }
.res-pol__id { font-size: 12px; font-weight: 600; color: var(--ink); flex: none; }
.res-pol__subj { font-size: 11.5px; color: var(--ink-3); flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
