<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">资源策略 · 数据面授权</div>
        <div class="bd-page__sub">受 SPA 门控的后端资源（id→后端 + 角色/用户细粒度授权）· control 托管，网关注册后周期热拉取生效</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <button class="bd-btn" @click="openCreate"><icon-plus />新增资源</button>
      </div>
    </div>

    <!-- 在线数据面网关 -->
    <div class="bd-gws">
      <div class="bd-gws__h"><icon-storage /> 在线数据面网关 <em>{{ gateways.length }}</em></div>
      <div v-if="!gateways.length" class="bd-gws__empty">
        暂无网关注册 —— 启动 <span class="bd-mono">baidi-gateway -control http://…:8090</span> 即上线
      </div>
      <div v-else class="bd-gws__list">
        <div v-for="g in gateways" :key="g.id" class="bd-gw">
          <span class="bd-gw__dot" :class="{ stale: isStale(g) }" />
          <div class="bd-gw__main">
            <div class="bd-gw__id">{{ g.id }}</div>
            <div class="bd-gw__meta"><span class="bd-mono">proxy {{ g.proxy }}</span> · <span class="bd-mono">spa {{ g.spa }}</span></div>
            <div class="bd-gw__nums">已授权客户端 <b>{{ g.clients }}</b> · 活跃隧道 <b>{{ g.tunnels }}</b> · 运行 <b>{{ upt(g.uptime) }}</b></div>
          </div>
          <span class="bd-gw__seen">{{ seenAgo(g.lastSeen) }}</span>
        </div>
      </div>
    </div>

    <!-- 受控资源表 -->
    <div class="bd-tablecard">
      <div class="bd-toolbar">
        <span class="bd-toolbar__c">受控资源 · {{ resources.length }} 项</span>
        <div style="flex: 1" />
        <div class="bd-searchbox" style="width: 240px"><icon-search />按 id / 名称 / 后端搜索</div>
      </div>
      <table class="bd-table">
        <thead>
          <tr><th>资源 id</th><th>名称</th><th>后端</th><th>授权角色</th><th>授权用户</th><th class="r">操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="r in resources" :key="r.id">
            <td><span class="bd-mono bd-rid">{{ r.id }}</span></td>
            <td>{{ r.name || '—' }}</td>
            <td>
              <span class="bd-mono">{{ r.backend }}</span>
              <a-tooltip v-if="r.addrRef || r.svcRef" :content="refLabel(r)">
                <span class="bd-srctag"><icon-link />源自对象库</span>
              </a-tooltip>
            </td>
            <td>
              <template v-if="r.allowRoles && r.allowRoles.length">
                <span v-for="role in r.allowRoles" :key="role" class="bd-rtag" :style="tagStyle(roleColor(role))">{{ role }}</span>
              </template>
              <span v-else class="bd-anyt">不限</span>
            </td>
            <td>
              <template v-if="r.allowUsers && r.allowUsers.length">
                <span v-for="u in r.allowUsers" :key="u" class="bd-rtag" :style="tagStyle('#722ED1')">{{ u }}</span>
              </template>
              <span v-else class="bd-anyt">不限</span>
            </td>
            <td class="r">
              <span class="bd-link" @click="openEdit(r)">编辑</span>
              <span class="bd-link bd-link--danger" style="margin-left: 12px" @click="del(r)">删除</span>
            </td>
          </tr>
          <tr v-if="!resources.length"><td colspan="6" class="bd-empty">暂无资源，点右上「新增资源」创建</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 新增 / 编辑 资源 -->
    <a-modal v-model:visible="formOpen" :title="editing ? '编辑资源' : '新增资源'" :width="480" :footer="false" unmount-on-close>
      <div class="bd-uform">
        <div class="bd-uform__f"><label>资源 id<i class="req">*</i></label>
          <a-input v-model="form.id" :disabled="editing" placeholder="如 oa（隧道前导 CONNECT &lt;id&gt; 引用）" />
        </div>
        <div class="bd-uform__f"><label>名称</label><a-input v-model="form.name" placeholder="如 OA 协同办公" /></div>
        <div class="bd-uform__f"><label>后端 host:port<i class="req">*</i></label>
          <a-input v-model="form.backend" placeholder="如 10.20.1.10:8080（仅源自此处，绝不取客户端值＝防 SSRF）" />
          <div class="bd-uform__hint">backend 为权威拨号目标，选择对象仅自动回填、可手动覆盖（防 SSRF：数据面只认此值）</div>
        </div>
        <div class="bd-uform__f"><label>引用地址对象（可选）</label>
          <a-select v-model="form.addrRef" allow-clear placeholder="不引用（手填 backend host）" @change="onRefChange">
            <a-option v-for="a in addrs" :key="a.id" :value="a.id">{{ a.name }} · {{ a.value }}</a-option>
          </a-select>
        </div>
        <div class="bd-uform__f"><label>引用服务对象（可选）</label>
          <a-select v-model="form.svcRef" allow-clear placeholder="不引用（手填 backend port）" @change="onRefChange">
            <a-option v-for="s in services" :key="s.id" :value="s.id">{{ s.name }} · {{ s.proto }}/{{ s.ports }}</a-option>
          </a-select>
        </div>
        <div class="bd-uform__f"><label>授权角色（空＝不限）</label>
          <a-select v-model="form.allowRoles" multiple allow-clear placeholder="不限角色">
            <a-option value="admin">admin</a-option>
            <a-option value="user">user</a-option>
          </a-select>
        </div>
        <div class="bd-uform__f"><label>授权用户（逗号分隔，空＝不限）</label>
          <a-input v-model="usersText" placeholder="如 li.ming, zhang.wei" />
        </div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="formOpen = false">取消</button>
          <button class="bd-btn" :disabled="saving" @click="save">{{ editing ? '保存' : '创建' }}并落库</button>
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type Resource, type ResourcesResp, type GatewayReg, type GatewaysResp, type AddrObject, type ServiceObject, type ObjectBundle } from '@/lib/api';

const live = ref(false);
const resources = ref<Resource[]>([]);
const gateways = ref<GatewayReg[]>([]);
const addrs = ref<AddrObject[]>([]);
const services = ref<ServiceObject[]>([]);
const nowSec = ref(Math.floor(Date.now() / 1000));
let timer: ReturnType<typeof setInterval>;

function tagStyle(color: string) { return { color, background: color + '14' }; }
function roleColor(r: string) { return r === 'admin' ? '#F53F3F' : r === 'gateway' ? '#0FC6C2' : '#165DFF'; }
function isStale(g: GatewayReg) { return nowSec.value - g.lastSeen > 60; }
function upt(sec: number) {
  if (!sec || sec < 60) return `${sec || 0}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h`;
  return `${Math.floor(sec / 86400)}d`;
}
function seenAgo(ts: number) {
  const d = nowSec.value - ts;
  if (d < 5) return '刚刚';
  if (d < 60) return `${d}s 前`;
  if (d < 3600) return `${Math.floor(d / 60)} 分前`;
  return `${Math.floor(d / 3600)} 时前`;
}

async function load() {
  try {
    const r = await api<ResourcesResp>('/resources');
    resources.value = r.resources; live.value = true;
  } catch { live.value = false; }
  try {
    const g = await api<GatewaysResp>('/gateways');
    gateways.value = g.gateways || [];
  } catch { /* 网关列表失败不影响资源管理 */ }
  try {
    const o = await api<ObjectBundle>('/objects');
    addrs.value = o.addrs || []; services.value = o.services || [];
  } catch { /* 对象库失败不影响资源管理 */ }
}

function refLabel(r: Resource) {
  const parts: string[] = [];
  if (r.addrRef) { const a = addrs.value.find((x) => x.id === r.addrRef); parts.push(`地址：${a ? `${a.name}（${a.value}）` : r.addrRef}`); }
  if (r.svcRef) { const s = services.value.find((x) => x.id === r.svcRef); parts.push(`服务：${s ? `${s.name}（${s.proto}/${s.ports}）` : r.svcRef}`); }
  return parts.join(' · ');
}

const formOpen = ref(false);
const editing = ref(false);
const saving = ref(false);
const form = reactive<{ id: string; name: string; backend: string; allowRoles: string[]; addrRef: string; svcRef: string }>({ id: '', name: '', backend: '', allowRoles: [], addrRef: '', svcRef: '' });
const usersText = ref('');

// 选择对象时自动回填 backend（保持可手动覆盖，backend 始终权威）
function onRefChange() {
  const addr = form.addrRef ? addrs.value.find((a) => a.id === form.addrRef) : undefined;
  const svc = form.svcRef ? services.value.find((s) => s.id === form.svcRef) : undefined;
  if (addr && svc) {
    form.backend = `${addr.value}:${svc.ports}`;
  } else if (addr) {
    const port = form.backend.includes(':') ? form.backend.slice(form.backend.lastIndexOf(':') + 1) : '';
    form.backend = port ? `${addr.value}:${port}` : addr.value;
  }
  // 清空选择仅清 ref，不动 backend（权威值）—— 由 a-select allow-clear 把 ref 置空后走此分支无操作
}

function openCreate() {
  editing.value = false;
  form.id = ''; form.name = ''; form.backend = ''; form.allowRoles = []; form.addrRef = ''; form.svcRef = ''; usersText.value = '';
  formOpen.value = true;
}
function openEdit(r: Resource) {
  editing.value = true;
  form.id = r.id; form.name = r.name; form.backend = r.backend;
  form.allowRoles = [...(r.allowRoles || [])];
  form.addrRef = r.addrRef || ''; form.svcRef = r.svcRef || '';
  usersText.value = (r.allowUsers || []).join(', ');
  formOpen.value = true;
}

async function save() {
  if (!form.id || !form.backend) { Message.warning('资源 id 与后端必填'); return; }
  saving.value = true;
  const allowUsers = usersText.value.split(',').map((s) => s.trim()).filter(Boolean);
  try {
    await api('/resources', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: form.id, name: form.name, backend: form.backend, allowRoles: form.allowRoles, allowUsers, addrRef: form.addrRef || undefined, svcRef: form.svcRef || undefined })
    });
    Message.success(`资源「${form.id}」已落库，网关下次轮询即生效`);
    formOpen.value = false;
    await load();
  } catch { Message.error('保存失败，请检查管理员权限或后端连接'); } finally { saving.value = false; }
}

async function del(r: Resource) {
  try {
    await api(`/resources/${r.id}`, { method: 'DELETE' });
    Message.success(`资源「${r.id}」已删除`);
    await load();
  } catch { Message.error('删除失败，请检查权限或后端连接'); }
}

const _shown = computed(() => resources.value); // 预留搜索过滤位
void _shown;

onMounted(() => {
  load();
  timer = setInterval(() => { nowSec.value = Math.floor(Date.now() / 1000); load(); }, 5000);
});
onUnmounted(() => clearInterval(timer));
</script>

<style scoped>
.bd-gws { background: var(--bd-surface, #fff); border: 1px solid var(--bd-border, #e5e6eb); border-radius: 10px; padding: 14px 16px; margin-bottom: 14px; }
.bd-gws__h { display: flex; align-items: center; gap: 6px; font-weight: 600; color: var(--bd-t1, #1d2129); margin-bottom: 10px; }
.bd-gws__h em { font-style: normal; color: var(--bd-accent, #165DFF); font-weight: 700; }
.bd-gws__empty { font-size: 13px; color: var(--bd-t3, #86909c); }
.bd-gws__list { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 10px; }
.bd-gw { display: flex; align-items: center; gap: 10px; border: 1px solid var(--bd-border, #e5e6eb); border-radius: 8px; padding: 10px 12px; background: var(--bd-surface-2, #f7f8fa); }
.bd-gw__dot { width: 8px; height: 8px; border-radius: 50%; background: var(--bd-success, #00b42a); box-shadow: 0 0 0 3px rgba(0, 180, 42, 0.14); flex: none; }
.bd-gw__dot.stale { background: var(--bd-warning, #ff7d00); box-shadow: 0 0 0 3px rgba(255, 125, 0, 0.14); }
.bd-gw__main { flex: 1; min-width: 0; }
.bd-gw__id { font-weight: 600; color: var(--bd-t1, #1d2129); }
.bd-gw__meta { font-size: 12px; color: var(--bd-t3, #86909c); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bd-gw__nums { font-size: 12px; color: var(--bd-t3, #86909c); margin-top: 3px; }
.bd-gw__nums b { color: var(--bd-primary, #165DFF); font-weight: 600; }
.bd-gw__seen { font-size: 12px; color: var(--bd-t3, #86909c); flex: none; }
.bd-rid { color: var(--bd-accent, #165DFF); font-weight: 600; }
.bd-rtag { display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 12px; margin-right: 6px; }
.bd-anyt { font-size: 12px; color: var(--bd-t4, #c9cdd4); }
.bd-empty { text-align: center; color: var(--bd-t3, #86909c); padding: 28px 0; }
.bd-uform__f .req { color: var(--bd-danger, #f53f3f); margin-left: 2px; }
.bd-uform__hint { font-size: 12px; color: var(--bd-t3, #86909c); margin-top: 4px; line-height: 1.5; }
.bd-srctag { display: inline-flex; align-items: center; gap: 3px; margin-left: 8px; padding: 0 7px; height: 18px; border-radius: 4px; font-size: 11px; color: var(--bd-accent, #165DFF); background: rgba(22, 93, 255, 0.08); vertical-align: middle; cursor: default; }
</style>
