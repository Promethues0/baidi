<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">资源策略 · 数据面授权</div>
        <div class="bd-page__sub">受 SPA 门控的后端资源（id→后端 + 角色/用户/用户组/组织细粒度授权）· control 托管，网关注册后周期热拉取生效</div>
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
        <div v-for="g in gateways" :key="g.id" class="bd-gw" :class="{ open: expanded.has(g.id) }">
          <div class="bd-gw__row" @click="toggleGw(g.id)">
            <span class="bd-gw__dot" :class="{ stale: isStale(g) }" />
            <div class="bd-gw__main">
              <div class="bd-gw__id">{{ g.id }}<span v-if="g.sessions?.length" class="bd-gw__badge">会话 {{ g.sessions.length }}</span></div>
              <div class="bd-gw__meta"><span class="bd-mono">proxy {{ g.proxy }}</span> · <span class="bd-mono">spa {{ g.spa }}</span></div>
              <div class="bd-gw__nums">已授权客户端 <b>{{ g.clients }}</b> · 活跃隧道 <b>{{ g.tunnels }}</b> · 运行 <b>{{ upt(g.uptime) }}</b> · 版本 <b>{{ g.version || '—' }}</b></div>
            </div>
            <span class="bd-gw__seen">{{ seenAgo(g.lastSeen) }}</span>
            <icon-down class="bd-gw__chev" :class="{ up: expanded.has(g.id) }" />
          </div>
          <div v-if="expanded.has(g.id)" class="bd-gw__sessions">
            <div v-if="!g.sessions?.length" class="bd-gw__nosess">当前无活跃放行会话（无客户端敲门）</div>
            <table v-else class="bd-gw__stab">
              <thead><tr><th>用户</th><th>源 IP</th><th>角色</th><th>敲门时刻</th><th>在线时长</th></tr></thead>
              <tbody>
                <tr v-for="s in g.sessions" :key="s.ip + s.user">
                  <td>{{ s.user || '—' }}</td>
                  <td class="bd-mono">{{ s.ip }}</td>
                  <td><span :style="{ color: roleColor(s.role) }">{{ s.role || 'user' }}</span></td>
                  <td>{{ atOf(s.since) }}</td>
                  <td>{{ durOf(s.since) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
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
          <tr><th>资源 id</th><th>名称</th><th>后端</th><th>可达性</th><th>敏感度</th><th>授权角色</th><th>授权用户</th><th>授权组织 / 用户组</th><th class="r">操作</th></tr>
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
              <!-- 网关侧真实拨测的聚合（60s 一轮随心跳上报）。「未探测」是三态之一：
                   旧网关不上报 / 新资源未到下一轮，绝不显示成可达——那正是
                   「一切显示正常、点开才炸」要消灭的形态。 -->
              <a-tooltip v-if="reachOf(r.id)" :content="reachTip(r.id)">
                <span class="bd-rtag" :style="tagStyle(reachColor(reachOf(r.id)!.status))">{{ reachLabel(reachOf(r.id)!.status) }}<template v-if="reachOf(r.id)!.status === 'ok'"> · {{ reachOf(r.id)!.ms }}ms</template></span>
              </a-tooltip>
              <span v-else class="bd-rtag" :style="tagStyle('#86909C')">未探测</span>
            </td>
            <td>
              <!-- 高敏是**可执行**的标记：终端被判降权的用户会从这一行的允许集合里被摘掉
                   （网关 denyUsers + 客户端剖面同步），不是一枚纯展示的标签。 -->
              <a-tooltip :content="sensTip(r.sensitivity)">
                <span class="bd-rtag" :style="tagStyle(sensColor(r.sensitivity))">{{ sensLabel(r.sensitivity) }}</span>
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
            <td>
              <template v-if="(r.allowOrgs || []).length || (r.allowGroups || []).length">
                <span v-for="o in r.allowOrgs || []" :key="'o' + o" class="bd-rtag" :style="tagStyle('#00B42A')">
                  <icon-apps />{{ orgName(o) }}
                </span>
                <span v-for="g in r.allowGroups || []" :key="'g' + g" class="bd-rtag" :style="tagStyle('#FF7D00')">
                  <icon-user-group />{{ groupName(g) }}
                </span>
                <!-- ★把子树语义的实际影响显式写出来：授权「ACME 集团」看着只是一个标签，
                     实际覆盖的是整棵树上的所有人。数字与网关放行的那批人同源。 -->
                <a-tooltip :content="effectiveTip(r)">
                  <span class="bd-effect">生效 {{ effectiveOf(r).length }} 个账号</span>
                </a-tooltip>
              </template>
              <span v-else class="bd-anyt">未按组织/用户组授权</span>
            </td>
            <td class="r">
              <span class="bd-link" @click="openEdit(r)">编辑</span>
              <span class="bd-link bd-link--danger" style="margin-left: 12px" @click="del(r)">删除</span>
            </td>
          </tr>
          <tr v-if="!resources.length"><td colspan="9" class="bd-empty">暂无资源，点右上「新增资源」创建</td></tr>
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
        <div class="bd-uform__f"><label>敏感度</label>
          <a-select v-model="form.sensitivity">
            <a-option value="low">low · 低敏（已评估，不敏感）</a-option>
            <a-option value="normal">normal · 普通（默认）</a-option>
            <a-option value="high">high · 高敏（终端降权时暂停访问）</a-option>
          </a-select>
          <div class="bd-uform__hint">★这是**风险降权的唯一判据**：终端被判 degrade 的用户，high 资源会从网关允许集合与客户端剖面里同时摘除（普通资源与隧道不受影响），并在客户端显式告知原因。门户侧 high 资源默认走自助申请审批。</div>
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
        <div class="bd-uform__f"><label>授权组织（空＝不按组织授权）</label>
          <a-select v-model="form.allowOrgs" multiple allow-clear placeholder="不按组织授权">
            <a-option v-for="o in orgOpts" :key="o.id" :value="o.id">
              {{ indentOf(o) }}{{ o.name }} · {{ o.accounts.length }} 人
            </a-option>
          </a-select>
          <div class="bd-uform__hint">★含子树：授权某组织即涵盖它**全部后代组织**的用户。括号里的人数已按子树算好（与网关实际放行口径同源）</div>
        </div>
        <div class="bd-uform__f"><label>授权用户组（空＝不按用户组授权）</label>
          <a-select v-model="form.allowGroups" multiple allow-clear placeholder="不按用户组授权">
            <a-option v-for="g in groupOpts" :key="g.id" :value="g.id">
              {{ g.name }}<template v-if="g.kind === 'role'"> · 角色派生</template> · {{ g.accounts.length }} 人
            </a-option>
          </a-select>
        </div>
        <div v-if="form.allowOrgs.length || form.allowGroups.length" class="bd-effectbox">
          展开后生效账号 <b>{{ formEffective.length }}</b> 个
          <span v-if="formEffective.length">：{{ formEffective.slice(0, 8).join('、') }}<template v-if="formEffective.length > 8"> 等</template></span>
          <!-- 空集必须显式提示：控制面把它如实下发成「拒绝所有人」，
               管理员若以为"选了组织就有人能进"，会一直查不到为什么连不上。 -->
          <em v-else>—— 所选组织/用户组当前没有任何成员，该资源将拒绝所有人（角色/账号维度另算）</em>
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
import { api, type Resource, type ResourcesResp, type SubjectOption, type GatewayReg, type GatewaysResp, type AddrObject, type ServiceObject, type ObjectBundle } from '@/lib/api';

const live = ref(false);
const resources = ref<Resource[]>([]);
// 授权主体候选。accounts 由控制面**展开好**（组织那份已含全部后代组织的成员）——
// 前端只做集合并，不自己走组织树，见 SubjectOption 的说明。
const orgOpts = ref<SubjectOption[]>([]);
const groupOpts = ref<SubjectOption[]>([]);
const gateways = ref<GatewayReg[]>([]);
const addrs = ref<AddrObject[]>([]);
const services = ref<ServiceObject[]>([]);
const nowSec = ref(Math.floor(Date.now() / 1000));
const expanded = ref<Set<string>>(new Set());
let timer: ReturnType<typeof setInterval>;

function tagStyle(color: string) { return { color, background: color + '14' }; }
function roleColor(r: string) { return r === 'admin' ? '#F53F3F' : r === 'gateway' ? '#0FC6C2' : '#165DFF'; }
function isStale(g: GatewayReg) { return nowSec.value - g.lastSeen > 60; }
function toggleGw(id: string) { const e = new Set(expanded.value); e.has(id) ? e.delete(id) : e.add(id); expanded.value = e; }
function atOf(unix: number) {
  if (!unix) return '—';
  const d = new Date(unix * 1000);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}
function durOf(unix: number) {
  if (!unix) return '—';
  const s = Math.max(0, nowSec.value - unix);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}
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

/* ── 后端可达性（wave7 行动 9：网关侧拨测聚合）── */
interface ReachAgg { status: 'ok' | 'partial' | 'fail' | 'unknown'; detail: string[]; ms: number }
const reach = ref<Record<string, ReachAgg>>({});
function reachOf(id: string): ReachAgg | undefined { return reach.value[id]; }
function reachLabel(st: string) {
  return st === 'ok' ? '可达' : st === 'partial' ? '部分不可达' : st === 'fail' ? '不可达' : '未探测';
}
function reachColor(st: string) {
  return st === 'ok' ? '#00B42A' : st === 'partial' ? '#FF7D00' : st === 'fail' ? '#F53F3F' : '#86909C';
}
function reachTip(id: string) {
  const a = reach.value[id];
  return a && a.detail.length ? a.detail.join('；') : '暂无拨测详情';
}

async function load() {
  try {
    const r = await api<ResourcesResp>('/resources');
    resources.value = r.resources;
    orgOpts.value = r.orgs || []; groupOpts.value = r.groups || [];
    live.value = true;
  } catch { live.value = false; }
  try {
    const g = await api<GatewaysResp>('/gateways');
    gateways.value = g.gateways || [];
  } catch { /* 网关列表失败不影响资源管理 */ }
  try {
    const o = await api<ObjectBundle>('/objects');
    addrs.value = o.addrs || []; services.value = o.services || [];
  } catch { /* 对象库失败不影响资源管理 */ }
  try {
    const rc = await api<{ items: Record<string, ReachAgg> }>('/resources/reach');
    reach.value = rc.items || {};
  } catch { reach.value = {}; /* 可达性拉不到 → 全部显示未探测（不编造可达） */ }
}

function refLabel(r: Resource) {
  const parts: string[] = [];
  if (r.addrRef) { const a = addrs.value.find((x) => x.id === r.addrRef); parts.push(`地址：${a ? `${a.name}（${a.value}）` : r.addrRef}`); }
  if (r.svcRef) { const s = services.value.find((x) => x.id === r.svcRef); parts.push(`服务：${s ? `${s.name}（${s.proto}/${s.ports}）` : r.svcRef}`); }
  return parts.join(' · ');
}

/* ── 授权主体：展示与展开 ──
   展开只做一件事：把选中主体的 accounts **求并集**。子树语义已经在服务端算进
   accounts 里了（授权 root 那条就已经含全树的人），前端再走一遍树等于把同一套
   语义实现两遍——两份实现一旦漂移，管理员看到的人数与网关实际放行的人就对不上。 */
function orgName(id: string) { return orgOpts.value.find((o) => o.id === id)?.name || id; }
function groupName(id: string) { return groupOpts.value.find((g) => g.id === id)?.name || id; }
function indentOf(o: SubjectOption) {
  const depth = Math.max(0, (o.path || '').split('/').filter(Boolean).length - 1);
  return '　'.repeat(depth);
}
function expandAccounts(orgIds: string[], groupIds: string[]) {
  const set = new Set<string>();
  for (const id of orgIds) orgOpts.value.find((o) => o.id === id)?.accounts.forEach((a) => set.add(a));
  for (const id of groupIds) groupOpts.value.find((g) => g.id === id)?.accounts.forEach((a) => set.add(a));
  return [...set].sort();
}
function effectiveOf(r: Resource) { return expandAccounts(r.allowOrgs || [], r.allowGroups || []); }

/* ── 敏感度（风险降权的判据）── */
function sensLabel(s?: string) { return s === 'high' ? '高敏' : s === 'low' ? '低敏' : '普通'; }
function sensColor(s?: string) { return s === 'high' ? '#F53F3F' : s === 'low' ? '#00B42A' : '#86909C'; }
function sensTip(s?: string) {
  return s === 'high'
    ? '终端被判降权（degrade）的用户会被暂停访问本资源；门户侧默认走自助申请审批'
    : '不受终端降权影响：降权只摘除高敏资源，普通/低敏资源与隧道照常';
}
function effectiveTip(r: Resource) {
  const list = effectiveOf(r);
  return list.length ? `组织/用户组展开后：${list.join('、')}` : '所选组织/用户组当前没有任何成员，该维度不会放行任何人';
}

const formOpen = ref(false);
const editing = ref(false);
const saving = ref(false);
const form = reactive<{ id: string; name: string; backend: string; sensitivity: 'low' | 'normal' | 'high'; allowRoles: string[]; allowGroups: string[]; allowOrgs: string[]; addrRef: string; svcRef: string }>(
  { id: '', name: '', backend: '', sensitivity: 'normal', allowRoles: [], allowGroups: [], allowOrgs: [], addrRef: '', svcRef: '' });
const usersText = ref('');
const formEffective = computed(() => expandAccounts(form.allowOrgs, form.allowGroups));

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
  form.id = ''; form.name = ''; form.backend = ''; form.sensitivity = 'normal';
  form.allowRoles = []; form.allowGroups = []; form.allowOrgs = [];
  form.addrRef = ''; form.svcRef = ''; usersText.value = '';
  formOpen.value = true;
}
function openEdit(r: Resource) {
  editing.value = true;
  form.id = r.id; form.name = r.name; form.backend = r.backend;
  form.sensitivity = r.sensitivity || 'normal';
  form.allowRoles = [...(r.allowRoles || [])];
  form.allowGroups = [...(r.allowGroups || [])]; form.allowOrgs = [...(r.allowOrgs || [])];
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
      body: JSON.stringify({
        id: form.id, name: form.name, backend: form.backend, sensitivity: form.sensitivity,
        allowRoles: form.allowRoles, allowUsers, allowGroups: form.allowGroups, allowOrgs: form.allowOrgs,
        addrRef: form.addrRef || undefined, svcRef: form.svcRef || undefined
      })
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
.bd-gw { border: 1px solid var(--bd-border, #e5e6eb); border-radius: 8px; background: var(--bd-surface-2, #f7f8fa); }
.bd-gw.open { grid-column: 1 / -1; }
.bd-gw__row { display: flex; align-items: center; gap: 10px; padding: 10px 12px; cursor: pointer; }
.bd-gw__badge { font-size: 11px; font-weight: 600; color: var(--bd-primary, #165DFF); background: rgba(22, 93, 255, 0.1); padding: 1px 7px; border-radius: 10px; margin-left: 7px; }
.bd-gw__chev { font-size: 14px; color: var(--bd-t3, #86909c); flex: none; transition: transform 0.2s; }
.bd-gw__chev.up { transform: rotate(180deg); }
.bd-gw__sessions { border-top: 1px dashed var(--bd-border, #e5e6eb); padding: 8px 12px 12px; overflow-x: auto; }
.bd-gw__nosess { font-size: 12.5px; color: var(--bd-t3, #86909c); padding: 6px 0; }
.bd-gw__stab { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.bd-gw__stab th { text-align: left; color: var(--bd-t3, #86909c); font-weight: 500; padding: 5px 10px 5px 0; white-space: nowrap; }
.bd-gw__stab td { padding: 5px 10px 5px 0; color: var(--bd-t1, #1d2129); border-top: 1px solid var(--bd-fill-2, #f2f3f5); white-space: nowrap; }
.bd-gw__dot { width: 8px; height: 8px; border-radius: 50%; background: var(--bd-success, #00b42a); box-shadow: 0 0 0 3px rgba(0, 180, 42, 0.14); flex: none; }
.bd-gw__dot.stale { background: var(--bd-warning, #ff7d00); box-shadow: 0 0 0 3px rgba(255, 125, 0, 0.14); }
.bd-gw__main { flex: 1; min-width: 0; }
.bd-gw__id { font-weight: 600; color: var(--bd-t1, #1d2129); }
.bd-gw__meta { font-size: 12px; color: var(--bd-t3, #86909c); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bd-gw__nums { font-size: 12px; color: var(--bd-t3, #86909c); margin-top: 3px; }
.bd-gw__nums b { color: var(--bd-primary, #165DFF); font-weight: 600; }
.bd-gw__seen { font-size: 12px; color: var(--bd-t3, #86909c); flex: none; }
.bd-rid { color: var(--bd-accent, #165DFF); font-weight: 600; }
.bd-rtag { display: inline-flex; align-items: center; gap: 3px; padding: 1px 8px; border-radius: 4px; font-size: 12px; margin-right: 6px; }
.bd-effect { display: inline-block; font-size: 12px; color: var(--bd-t3, #86909c); border-bottom: 1px dashed var(--bd-border, #e5e6eb); cursor: default; }
.bd-effectbox { font-size: 12.5px; color: var(--bd-t2, #4e5969); background: var(--bd-fill-2, #f2f3f5); border-radius: 6px; padding: 8px 10px; margin-bottom: 12px; line-height: 1.6; }
.bd-effectbox b { color: var(--bd-accent, #165DFF); }
.bd-effectbox em { font-style: normal; color: var(--bd-warning, #ff7d00); }
.bd-anyt { font-size: 12px; color: var(--bd-t4, #c9cdd4); }
.bd-empty { text-align: center; color: var(--bd-t3, #86909c); padding: 28px 0; }
.bd-uform__f .req { color: var(--bd-danger, #f53f3f); margin-left: 2px; }
.bd-uform__hint { font-size: 12px; color: var(--bd-t3, #86909c); margin-top: 4px; line-height: 1.5; }
.bd-srctag { display: inline-flex; align-items: center; gap: 3px; margin-left: 8px; padding: 0 7px; height: 18px; border-radius: 4px; font-size: 11px; color: var(--bd-accent, #165DFF); background: rgba(22, 93, 255, 0.08); vertical-align: middle; cursor: default; }
</style>
