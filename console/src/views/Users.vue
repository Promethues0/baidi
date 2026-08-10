<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">用户与角色 · 访问者目录</div>
        <div class="bd-page__sub">多身份源统一纳管 · 组织树与用户组维护 · 实时在线态与账号生命周期就地处置</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <button class="bd-btn bd-btn--ghost"><icon-upload />批量导入</button>
        <button class="bd-btn" @click="openCreateUser"><icon-plus />新增用户</button>
      </div>
    </div>

    <!-- 身份源 tabs -->
    <div class="bd-tabs">
      <span v-for="d in directories" :key="d.key" class="bd-tab" :class="{ on: dir === d.key }" @click="dir = d.key">
        <icon-storage v-if="d.type === 'local'" /><icon-cloud v-else />
        {{ d.name }} <em>{{ d.users }}</em>
      </span>
    </div>

    <!-- AD 同步状态卡 -->
    <div v-if="curDir && curDir.type !== 'local'" class="bd-sync">
      <icon-sync class="bd-sync__ic" />
      <span><b>{{ curDir.name }}</b> 上次同步 {{ curDir.lastSync }} · 共 {{ curDir.users }} 用户、在线 {{ curDir.online }}</span>
      <div style="flex: 1" />
      <span class="bd-link">立即同步</span><span class="bd-link bd-link--grey" style="margin-left: 14px">同步日志</span>
    </div>

    <!-- 聚合计数 -->
    <div class="bd-agg">
      <div v-for="s in agg" :key="s.label" class="bd-agg__c">
        <span class="bd-agg__dot" :style="{ background: s.color }" /><b>{{ s.n }}</b>{{ s.label }}
      </div>
    </div>

    <div class="bd-two">
      <!-- 左栏：组织架构 / 用户组 -->
      <div class="bd-card bd-otree">
        <div class="bd-seg">
          <button class="bd-seg__b" :class="{ on: mode === 'org' }" @click="mode = 'org'">组织架构</button>
          <button class="bd-seg__b" :class="{ on: mode === 'group' }" @click="mode = 'group'">用户组</button>
        </div>

        <!-- 组织树 -->
        <template v-if="mode === 'org'">
          <button class="bd-onode" :class="{ on: org === '' }" @click="org = ''">
            <icon-apps class="bd-onode__ic" /><span class="bd-onode__t">全部用户</span>
            <span class="bd-onode__n">{{ users.length }}</span>
          </button>
          <div v-for="n in flatOrg" :key="n.key" class="bd-onode-row">
            <button class="bd-onode" :class="{ on: org === n.key }"
              :style="{ paddingLeft: 10 + n.depth * 14 + 'px' }" @click="org = n.key">
              <icon-folder v-if="n.children && n.children.length" class="bd-onode__ic" />
              <icon-user-group v-else class="bd-onode__ic" />
              <span class="bd-onode__t">{{ n.title }}</span>
              <span class="bd-onode__n">{{ n.members }}</span>
            </button>
            <span class="bd-onode__acts">
              <icon-plus title="新建子部门" @click.stop="openOrg(null, n.key)" />
              <icon-edit title="重命名 / 改上级" @click.stop="openOrg(n.key)" />
              <icon-delete title="删除" @click.stop="removeOrg(n.key, n.title)" />
            </span>
          </div>
          <button class="bd-onode bd-onode--add" @click="openOrg(null, '')"><icon-plus />新建顶级组织</button>
          <div v-if="!flatOrg.length" class="bd-otree__empty">尚无组织，先建一个。</div>
        </template>

        <!-- 用户组 -->
        <template v-else>
          <button class="bd-onode" :class="{ on: groupSel === '' }" @click="groupSel = ''">
            <icon-apps class="bd-onode__ic" /><span class="bd-onode__t">全部用户</span>
            <span class="bd-onode__n">{{ users.length }}</span>
          </button>
          <div v-for="g in groups" :key="g.id" class="bd-onode-row">
            <button class="bd-onode" :class="{ on: groupSel === g.id }" @click="groupSel = g.id">
              <icon-user-group class="bd-onode__ic" />
              <span class="bd-onode__t">{{ g.name }}<em v-if="g.kind === 'role'" class="bd-kindtag">角色派生</em></span>
              <span class="bd-onode__n">{{ g.members }}</span>
            </button>
            <span class="bd-onode__acts">
              <icon-user-add v-if="g.kind === 'static'" title="编辑成员" @click.stop="openMembers(g)" />
              <icon-edit title="编辑用户组" @click.stop="openGroup(g)" />
              <icon-delete title="删除" @click.stop="removeGroup(g)" />
            </span>
          </div>
          <button class="bd-onode bd-onode--add" @click="openGroup(null)"><icon-plus />新建用户组</button>
          <div v-if="!groups.length" class="bd-otree__empty">尚无用户组。角色组的成员由用户的展示角色派生，不用手工维护。</div>
        </template>
      </div>

      <!-- 用户表 -->
      <div class="bd-tablecard" style="flex: 1; min-width: 0">
        <div class="bd-toolbar">
          <span class="bd-toolbar__c">{{ scopeTitle }} · {{ shown.length }} 人</span>
          <div style="flex: 1" />
          <div class="bd-searchbox" style="width: 240px"><icon-search />按用户名 / 账号 / IP 搜索</div>
        </div>
        <table class="bd-table">
          <thead>
            <tr><th>用户</th><th>所属组织</th><th>用户组</th><th>终端 / 接入</th><th>状态</th><th class="r">操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="u in shown" :key="u.id" :class="{ sel: sel?.id === u.id }">
              <td>
                <div class="bd-cellname" @click="open(u)">
                  <span class="bd-avatar" :style="{ background: avBg(u) }">{{ u.name.slice(0, 1) }}</span>
                  <span><b>{{ u.name }}<span v-if="u.risk === 'high'" class="bd-rk">高危</span></b><i class="bd-mono">{{ u.account }}</i></span>
                </div>
              </td>
              <td>{{ u.org || '—' }}</td>
              <td>
                <span v-if="!u.groups.length" class="bd-t4">—</span>
                <span v-for="gid in u.groups" :key="gid" class="bd-tg bd-tg--sm" :style="tagStyle('#722ED1')">{{ groupName(gid) }}</span>
              </td>
              <td>
                <span class="bd-st"><span class="d" :style="{ background: u.online ? 'var(--bd-success)' : 'var(--bd-t4)' }" />{{ u.online ? '在线' : '离线' }}</span>
                <span class="bd-umono">{{ u.device }} · {{ u.ip }}</span>
              </td>
              <td><span class="bd-tg" :style="tagStyle(statusMeta(u.status).color)">{{ statusMeta(u.status).label }}</span></td>
              <td class="r"><span class="bd-link" @click="open(u)">详情</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 用户详情抽屉（P5 池化：列表 → 详情） -->
    <a-drawer v-model:visible="drawer" :width="460" :footer="false" unmount-on-close>
      <template #title>访问者详情</template>
      <div v-if="sel" class="bd-ud">
        <div class="bd-ud__head">
          <span class="bd-avatar" :style="{ background: avBg(sel), width: '46px', height: '46px', fontSize: '18px' }">{{ sel.name.slice(0, 1) }}</span>
          <div>
            <div class="bd-ud__name">{{ sel.name }}<span class="bd-st" style="margin-left: 8px"><span class="d" :style="{ background: sel.online ? 'var(--bd-success)' : 'var(--bd-t4)' }" />{{ sel.online ? '在线' : '离线' }}</span></div>
            <div class="bd-ud__acct bd-mono">{{ sel.account }} · {{ sel.org || '无组织归属' }}</div>
          </div>
        </div>

        <!-- 账号生命周期状态机 -->
        <div class="bd-ud__sec">账号生命周期</div>
        <div class="bd-life">
          <div v-for="(st, i) in LIFE" :key="st.key" class="bd-life__step" :class="{ on: st.key === sel.status }">
            <span class="bd-life__dot" />{{ st.label }}<icon-right v-if="i < LIFE.length - 1" class="bd-life__arr" />
          </div>
        </div>

        <!-- 组织归属与用户组（落库） -->
        <div class="bd-ud__sec">组织与用户组</div>
        <div class="bd-uform__f"><label>所属组织</label>
          <a-select v-model="memberForm.orgId" allow-clear placeholder="未归属任何组织">
            <a-option v-for="o in flatOrg" :key="o.key" :value="o.key">{{ '　'.repeat(o.depth) + o.title }}</a-option>
          </a-select>
        </div>
        <div class="bd-uform__f"><label>用户组（仅显式成员组可改）</label>
          <a-select v-model="memberForm.groups" multiple placeholder="未加入任何用户组">
            <a-option v-for="g in staticGroups" :key="g.id" :value="g.id">{{ g.name }}</a-option>
          </a-select>
          <div v-if="derivedGroups.length" class="bd-uform__hint" style="margin: 8px 0 0">
            按角色派生：<span v-for="g in derivedGroups" :key="g.id" class="bd-tg bd-tg--sm" :style="tagStyle('#722ED1')">{{ g.name }}</span>
            —— 由用户展示角色决定，改角色才会变。
          </div>
        </div>
        <button class="bd-btn" :disabled="savingMember" @click="saveMembership">保存归属</button>

        <div class="bd-ud__sec">接入信息</div>
        <div class="bd-kv"><span>终端</span><b>{{ sel.device }}</b></div>
        <div class="bd-kv"><span>接入 IP</span><b class="bd-mono">{{ sel.ip }}</b></div>
        <div class="bd-kv"><span>认证方式</span><b>{{ sel.auth }}</b></div>
        <div class="bd-kv"><span>最后登录</span><b>{{ sel.lastLogin }}</b></div>
        <div class="bd-kv"><span>风险评估</span><b><span class="bd-tg" :style="tagStyle(riskColor(sel.risk))">{{ riskLabel(sel.risk) }}</span></b></div>

        <div class="bd-ud__sec">角色</div>
        <div class="bd-roles"><span v-for="r in sel.roles" :key="r" class="bd-tg" :style="tagStyle('#165DFF')">{{ r }}</span></div>

        <div class="bd-ud__acts">
          <button v-if="sel.status === 'locked'" class="bd-btn" @click="setStatus('active', '已解锁账号')"><icon-unlock />解锁账号</button>
          <button v-if="sel.status === 'disabled'" class="bd-btn" @click="setStatus('active', '已启用账号')"><icon-check />启用账号</button>
          <button class="bd-btn bd-btn--ghost" @click="openReset"><icon-lock />重置密码</button>
          <button v-if="sel.status !== 'disabled'" class="bd-btn bd-btn--ghost bd-btn--danger" @click="setStatus('disabled', '已禁用账号')">禁用账号</button>
        </div>
      </div>
    </a-drawer>

    <!-- 组织编辑（落库） -->
    <a-modal v-model:visible="orgOpen" :title="orgForm.id ? '编辑组织' : '新建组织'" :width="460" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__f"><label>组织名称</label><a-input v-model="orgForm.name" placeholder="如：华东大区" /></div>
        <div class="bd-uform__f"><label>上级组织</label>
          <a-select v-model="orgForm.parentId" allow-clear placeholder="不选＝作为顶级组织">
            <a-option v-for="o in orgParentOptions" :key="o.key" :value="o.key">{{ '　'.repeat(o.depth) + o.title }}</a-option>
          </a-select>
        </div>
        <div class="bd-uform__f"><label>排序值</label><a-input-number v-model="orgForm.sort" :min="0" :max="9999" /></div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="orgOpen = false">取消</button>
          <button class="bd-btn" :disabled="orgSaving" @click="saveOrg">保存并落库</button>
        </div>
      </div>
    </a-modal>

    <!-- 用户组编辑（落库） -->
    <a-modal v-model:visible="groupOpen" :title="groupForm.id ? '编辑用户组' : '新建用户组'" :width="460" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__f"><label>组名称</label><a-input v-model="groupForm.name" placeholder="如：高敏访问组" /></div>
        <div class="bd-uform__f"><label>成员来源</label>
          <a-select v-model="groupForm.kind" :disabled="!!groupForm.id">
            <a-option value="static">显式成员（管理员维护）</a-option>
            <a-option value="role">按用户角色派生（成员只读）</a-option>
          </a-select>
          <div class="bd-uform__hint" style="margin: 8px 0 0">
            角色派生组的成员 = 展示角色里含该组名的用户；组名即角色名，改不了成员，只能改角色。
          </div>
        </div>
        <div class="bd-uform__f"><label>说明</label><a-input v-model="groupForm.description" placeholder="选填" /></div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="groupOpen = false">取消</button>
          <button class="bd-btn" :disabled="groupSaving" @click="saveGroup">保存并落库</button>
        </div>
      </div>
    </a-modal>

    <!-- 组成员编辑（落库） -->
    <a-modal v-model:visible="memberOpen" title="编辑用户组成员" :width="480" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__hint">「{{ memberGroupName }}」的成员按账号维护，保存即全量覆写。</div>
        <div class="bd-uform__f"><label>成员账号</label>
          <a-select v-model="memberAccounts" multiple placeholder="选择账号">
            <a-option v-for="u in users" :key="u.id" :value="u.account">{{ u.name }}（{{ u.account }}）</a-option>
          </a-select>
        </div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="memberOpen = false">取消</button>
          <button class="bd-btn" :disabled="memberSaving" @click="saveMembers">保存成员</button>
        </div>
      </div>
    </a-modal>

    <!-- 新增用户（写入 SQLite） -->
    <a-modal v-model:visible="createOpen" title="新增用户" :width="460" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__f"><label>姓名</label><a-input v-model="form.name" placeholder="如：钱七" /></div>
        <div class="bd-uform__f"><label>登录账号</label><a-input v-model="form.account" placeholder="如：qian.qi" /></div>
        <div class="bd-uform__f"><label>所属组织</label>
          <a-select v-model="form.orgId" allow-clear placeholder="不选＝暂不归属">
            <a-option v-for="o in flatOrg" :key="o.key" :value="o.key">{{ '　'.repeat(o.depth) + o.title }}</a-option>
          </a-select>
        </div>
        <div class="bd-uform__f"><label>用户组</label>
          <a-select v-model="form.groups" multiple placeholder="选填">
            <a-option v-for="g in staticGroups" :key="g.id" :value="g.id">{{ g.name }}</a-option>
          </a-select>
        </div>
        <div class="bd-uform__f"><label>认证方式</label>
          <a-select v-model="form.auth">
            <a-option value="密码">密码</a-option><a-option value="密码+短信">密码+短信</a-option>
            <a-option value="密码+UKey">密码+UKey</a-option><a-option value="SAML SSO">SAML SSO</a-option>
          </a-select>
        </div>
        <div class="bd-uform__f"><label>初始登录口令</label>
          <a-input-password v-model="form.password" placeholder="留空则用默认 baidi@123（至少 6 位）" />
        </div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="createOpen = false">取消</button>
          <button class="bd-btn" :disabled="creating" @click="createUser">创建并落库</button>
        </div>
      </div>
    </a-modal>

    <!-- 重置口令（管理员，落库改 bcrypt 哈希） -->
    <a-modal v-model:visible="resetOpen" title="重置登录口令" :width="420" :footer="false">
      <div class="bd-uform">
        <div class="bd-uform__hint">为「{{ sel?.name }}」({{ sel?.account }}) 设置新的登录口令，立即生效、旧口令失效。</div>
        <div class="bd-uform__f"><label>新口令</label>
          <a-input-password v-model="newPw" placeholder="至少 6 位" @keyup.enter="doReset" />
        </div>
        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="resetOpen = false">取消</button>
          <button class="bd-btn" :disabled="resetting" @click="doReset">重置口令</button>
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type UserDirBundle, type Directory, type OrgUnit, type DirUser, type Org, type GroupWithMembers } from '@/lib/api';

const live = ref(false);
const directories = ref<Directory[]>([{ key: 'local', name: '本地目录', type: 'local', users: 0, online: 0, lastSync: '' }]);
const orgTree = ref<OrgUnit[]>([]);
const orgs = ref<Org[]>([]);
const groups = ref<GroupWithMembers[]>([]);
const users = ref<DirUser[]>([]);
const dir = ref('local');
const mode = ref<'org' | 'group'>('org');
const org = ref('');       // '' = 全部用户
const groupSel = ref('');  // '' = 全部用户
const sel = ref<DirUser | null>(null);
const drawer = ref(false);

const curDir = computed(() => directories.value.find((d) => d.key === dir.value));
const staticGroups = computed(() => groups.value.filter((g) => g.kind === 'static'));

interface FlatOrg extends OrgUnit { depth: number }
const flatOrg = computed<FlatOrg[]>(() => {
  const out: FlatOrg[] = [];
  const walk = (ns: OrgUnit[], d: number) => ns.forEach((n) => { out.push({ ...n, depth: d }); n.children && walk(n.children, d + 1); });
  walk(orgTree.value, 0);
  return out;
});
// 编辑某节点时，它自己与它的后代不能当上级——环形父子后端会拒（400），前端先不给选。
const orgParentOptions = computed(() => {
  if (!orgForm.id) return flatOrg.value;
  const banned = subtreeKeys(orgForm.id);
  return flatOrg.value.filter((o) => !banned.has(o.key));
});

/** 某组织节点的子树 key 集合（含自身）。按子树过滤而不是只看直属，父节点点开才看得到下面的人。 */
function subtreeKeys(key: string): Set<string> {
  const out = new Set<string>();
  const collect = (n: OrgUnit) => { out.add(n.key); n.children?.forEach(collect); };
  const find = (ns: OrgUnit[]): boolean => ns.some((n) => {
    if (n.key === key) { collect(n); return true; }
    return n.children ? find(n.children) : false;
  });
  find(orgTree.value);
  return out;
}

const scopeTitle = computed(() => {
  if (mode.value === 'group') return groups.value.find((g) => g.id === groupSel.value)?.name ?? '全部用户';
  return flatOrg.value.find((n) => n.key === org.value)?.title ?? '全部用户';
});
const shown = computed(() => {
  if (mode.value === 'group') {
    if (!groupSel.value) return users.value;
    return users.value.filter((u) => u.groups.includes(groupSel.value));
  }
  if (!org.value) return users.value;
  const keys = subtreeKeys(org.value);
  return users.value.filter((u) => keys.has(u.orgKey));
});
function groupName(id: string) { return groups.value.find((g) => g.id === id)?.name ?? id; }

const agg = computed(() => {
  const u = users.value;
  return [
    { label: '在线', n: u.filter((x) => x.online).length, color: 'var(--bd-success)' },
    { label: '离线', n: u.filter((x) => !x.online).length, color: 'var(--bd-t4)' },
    { label: '锁定', n: u.filter((x) => x.status === 'locked').length, color: 'var(--bd-danger)' },
    { label: '禁用', n: u.filter((x) => x.status === 'disabled').length, color: 'var(--bd-t3)' }
  ];
});

const LIFE = [
  { key: 'active', label: '正常' }, { key: 'idle', label: '闲置' },
  { key: 'locked', label: '锁定' }, { key: 'disabled', label: '禁用' }
];
function statusMeta(s: string) {
  return { active: { label: '正常', color: '#00B42A' }, idle: { label: '闲置', color: '#86909C' }, locked: { label: '锁定', color: '#F53F3F' }, disabled: { label: '禁用', color: '#86909C' } }[s] ?? { label: s, color: '#86909C' };
}
const AV = ['#165DFF', '#722ED1', '#00B42A', '#FF7D00', '#0FC6C2'];
function avBg(u: DirUser) { return AV[(u.account.charCodeAt(0) + u.account.length) % AV.length]; }
function tagStyle(color: string) { return { color, background: color + '14' }; }
function riskColor(r: string) { return r === 'high' ? '#F53F3F' : r === 'low' ? '#FF7D00' : '#00B42A'; }
function riskLabel(r: string) { return r === 'high' ? '高风险' : r === 'low' ? '低风险' : '正常'; }

// ── 用户详情 + 归属编辑 ──
const memberForm = reactive<{ orgId: string; groups: string[] }>({ orgId: '', groups: [] });
const savingMember = ref(false);
// 角色派生的归属在这里是只读展示：它由 users.roles 决定，混进可编辑的多选框会让人
// 以为取消勾选就能移出组，而后端会拒。
const derivedGroups = computed(() => {
  const ids = sel.value?.groups ?? [];
  return groups.value.filter((g) => g.kind === 'role' && ids.includes(g.id));
});
function open(u: DirUser) {
  sel.value = u;
  memberForm.orgId = u.orgId;
  memberForm.groups = u.groups.filter((id) => staticGroups.value.some((g) => g.id === id));
  drawer.value = true;
}
async function saveMembership() {
  if (!sel.value) return;
  savingMember.value = true;
  try {
    await api(`/users/${sel.value.id}/membership`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orgId: memberForm.orgId ?? '', groups: memberForm.groups })
    });
    Message.success('已更新组织归属与用户组');
    await load();
    const again = users.value.find((u) => u.id === sel.value?.id);
    if (again) open(again);
  } catch { Message.error('保存失败，请检查权限或后端连接'); }
  finally { savingMember.value = false; }
}

// ── 组织增删改 ──
const orgOpen = ref(false);
const orgSaving = ref(false);
const orgForm = reactive({ id: '', name: '', parentId: '', sort: 0 });
function openOrg(key: string | null, parent = '') {
  if (key) {
    const row = orgs.value.find((o) => o.id === key);
    orgForm.id = key;
    orgForm.name = row?.name ?? flatOrg.value.find((n) => n.key === key)?.title ?? '';
    orgForm.parentId = row?.parentId ?? '';
    orgForm.sort = row?.sort ?? 0;
  } else {
    orgForm.id = ''; orgForm.name = ''; orgForm.parentId = parent; orgForm.sort = 0;
  }
  orgOpen.value = true;
}
async function saveOrg() {
  if (!orgForm.name.trim()) { Message.warning('请填写组织名称'); return; }
  orgSaving.value = true;
  try {
    await api('/orgs', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: orgForm.id, name: orgForm.name, parentId: orgForm.parentId ?? '', sort: orgForm.sort })
    });
    Message.success(orgForm.id ? '组织已更新' : '组织已创建');
    orgOpen.value = false;
    await load();
  } catch (e) { Message.error(reason(e, '保存组织失败')); }
  finally { orgSaving.value = false; }
}
async function removeOrg(key: string, title: string) {
  try {
    await api(`/orgs/${key}`, { method: 'DELETE' });
    Message.success(`已删除组织「${title}」`);
    if (org.value === key) org.value = '';
    await load();
  } catch (e) { Message.error(reason(e, '删除失败：该组织可能仍有子部门或成员')); }
}

// ── 用户组增删改 + 成员 ──
const groupOpen = ref(false);
const groupSaving = ref(false);
const groupForm = reactive<{ id: string; name: string; kind: 'static' | 'role'; description: string }>(
  { id: '', name: '', kind: 'static', description: '' });
function openGroup(g: GroupWithMembers | null) {
  if (g) { groupForm.id = g.id; groupForm.name = g.name; groupForm.kind = g.kind; groupForm.description = g.description; }
  else { groupForm.id = ''; groupForm.name = ''; groupForm.kind = 'static'; groupForm.description = ''; }
  groupOpen.value = true;
}
async function saveGroup() {
  if (!groupForm.name.trim()) { Message.warning('请填写组名称'); return; }
  groupSaving.value = true;
  try {
    await api('/groups', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...groupForm })
    });
    Message.success(groupForm.id ? '用户组已更新' : '用户组已创建');
    groupOpen.value = false;
    await load();
  } catch (e) { Message.error(reason(e, '保存失败：组名可能与已有组重复')); }
  finally { groupSaving.value = false; }
}
async function removeGroup(g: GroupWithMembers) {
  try {
    await api(`/groups/${g.id}`, { method: 'DELETE' });
    Message.success(`已删除用户组「${g.name}」`);
    if (groupSel.value === g.id) groupSel.value = '';
    await load();
  } catch (e) { Message.error(reason(e, '删除失败')); }
}

const memberOpen = ref(false);
const memberSaving = ref(false);
const memberGroupID = ref('');
const memberGroupName = ref('');
const memberAccounts = ref<string[]>([]);
function openMembers(g: GroupWithMembers) {
  memberGroupID.value = g.id; memberGroupName.value = g.name;
  memberAccounts.value = [...g.memberAccounts];
  memberOpen.value = true;
}
async function saveMembers() {
  memberSaving.value = true;
  try {
    await api(`/groups/${memberGroupID.value}/members`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accounts: memberAccounts.value })
    });
    Message.success('成员已更新');
    memberOpen.value = false;
    await load();
  } catch (e) { Message.error(reason(e, '保存成员失败')); }
  finally { memberSaving.value = false; }
}

function reason(e: unknown, fallback: string) {
  const msg = e instanceof Error ? e.message : '';
  return msg ? `${fallback}（${msg}）` : fallback;
}

async function load() {
  try {
    const b = await api<UserDirBundle>('/users');
    directories.value = b.directories;
    orgTree.value = b.orgTree ?? [];
    users.value = (b.users ?? []).map((u) => ({ ...u, groups: u.groups ?? [] }));
    live.value = true;
  } catch { live.value = false; return; }
  // 组织扁平清单（带 parentId/sort，编辑用）与用户组清单（带成员账号）都只有 admin 能读；
  // 拉不到就退化成"只能看树、不能改"，不把整页打成未连状态。
  try { orgs.value = (await api<{ orgs: Org[] }>('/orgs')).orgs ?? []; } catch { orgs.value = []; }
  try { groups.value = (await api<{ groups: GroupWithMembers[] }>('/groups')).groups ?? []; } catch { groups.value = []; }
}

// 改账号状态（禁用/启用/解锁）→ 落库
async function setStatus(status: string, label: string) {
  if (!sel.value) return;
  try {
    await api(`/users/${sel.value.id}/status`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
    Message.success(`${sel.value.name}：${label}`);
    drawer.value = false;
    await load();
  } catch { Message.error('操作失败，请检查权限或后端连接'); }
}

// 新增用户 → 落库
const createOpen = ref(false);
const creating = ref(false);
const form = reactive<{ name: string; account: string; orgId: string; groups: string[]; auth: string; password: string }>(
  { name: '', account: '', orgId: '', groups: [], auth: '密码+短信', password: '' });
function openCreateUser() {
  form.orgId = mode.value === 'org' ? org.value : '';
  form.groups = mode.value === 'group' && groupSel.value && staticGroups.value.some((g) => g.id === groupSel.value)
    ? [groupSel.value] : [];
  createOpen.value = true;
}
async function createUser() {
  if (!form.name || !form.account) { Message.warning('请填写姓名与账号'); return; }
  if (form.password && form.password.length < 6) { Message.warning('初始口令至少 6 位'); return; }
  creating.value = true;
  try {
    await api('/users', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...form, orgId: form.orgId ?? '', device: '未登记', ip: '—', roles: [] })
    });
    Message.success(`已新增用户「${form.name}」并落库`);
    createOpen.value = false;
    form.name = ''; form.account = ''; form.password = '';
    await load();
  } catch (e) {
    Message.error(reason(e, '新增失败，请检查权限或后端连接'));
  } finally {
    creating.value = false;
  }
}

// 重置口令 → 落库改哈希
const resetOpen = ref(false);
const resetting = ref(false);
const newPw = ref('');
function openReset() { newPw.value = ''; resetOpen.value = true; }
async function doReset() {
  if (!sel.value) return;
  if (newPw.value.length < 6) { Message.warning('口令至少 6 位'); return; }
  resetting.value = true;
  try {
    await api(`/users/${sel.value.id}/password`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: newPw.value })
    });
    Message.success(`已重置「${sel.value.name}」的登录口令`);
    resetOpen.value = false;
  } catch { Message.error('重置失败，请检查权限或后端连接'); }
  finally { resetting.value = false; }
}

onMounted(load);
</script>

<style scoped>
.bd-tabs { display: flex; gap: 4px; margin-bottom: 14px; }
.bd-tab { display: flex; align-items: center; gap: 7px; font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }
.bd-tab em { font-style: normal; font-size: 11px; color: var(--bd-t3); }
.bd-tab.on em { color: var(--bd-primary); }

.bd-sync { display: flex; align-items: center; gap: 10px; font-size: 12.5px; color: var(--bd-t2); background: var(--bd-tag-blue-bg); border: 1px solid var(--bd-primary-b); border-radius: 8px; padding: 10px 14px; margin-bottom: 14px; }
.bd-sync__ic { color: var(--bd-primary); font-size: 16px; }

.bd-agg { display: flex; gap: 24px; padding: 0 2px 16px; }
.bd-agg__c { display: flex; align-items: center; gap: 7px; font-size: 13px; color: var(--bd-t3); }
.bd-agg__c b { font-size: 20px; font-weight: 700; color: var(--bd-t1); }
.bd-agg__dot { width: 8px; height: 8px; border-radius: 50%; }

.bd-two { display: flex; gap: 16px; align-items: flex-start; }
.bd-otree { width: 246px; flex: none; padding: 10px; }
.bd-otree__empty { font-size: 12px; color: var(--bd-t3); line-height: 1.7; padding: 8px; }
.bd-seg { display: flex; gap: 4px; padding: 2px; margin-bottom: 8px; background: var(--bd-fill-1); border-radius: 7px; }
.bd-seg__b { flex: 1; height: 28px; border: none; background: transparent; border-radius: 5px; cursor: pointer; font-size: 12.5px; color: var(--bd-t2); }
.bd-seg__b.on { background: var(--bd-bg-1, #fff); color: var(--bd-primary); font-weight: 600; box-shadow: 0 1px 3px rgba(0, 0, 0, .07); }

.bd-onode-row { position: relative; }
.bd-onode-row:hover .bd-onode__acts { display: flex; }
.bd-onode { width: 100%; display: flex; align-items: center; gap: 8px; height: 36px; padding-right: 10px; border: none; background: transparent; border-radius: 7px; cursor: pointer; font-size: 13px; color: var(--bd-t2); }
.bd-onode:hover { background: var(--bd-fill-2); }
.bd-onode.on { background: var(--bd-primary-1); color: var(--bd-primary); font-weight: 500; }
.bd-onode--add { color: var(--bd-primary); padding-left: 10px; gap: 6px; margin-top: 4px; }
.bd-onode__ic { font-size: 15px; flex: none; }
.bd-onode__t { flex: 1; text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bd-onode__n { font-size: 11px; color: var(--bd-t3); }
.bd-onode__acts { display: none; position: absolute; right: 6px; top: 0; height: 36px; align-items: center; gap: 8px; background: var(--bd-fill-2); padding-left: 8px; border-radius: 0 7px 7px 0; }
.bd-onode__acts > * { font-size: 13px; color: var(--bd-t3); cursor: pointer; }
.bd-onode__acts > *:hover { color: var(--bd-primary); }
.bd-kindtag { font-style: normal; font-size: 10px; color: #722ED1; background: #722ED114; padding: 1px 5px; border-radius: 3px; margin-left: 6px; }

.bd-toolbar__c { font-size: 12.5px; color: var(--bd-t3); }
.bd-table tr.sel { background: var(--bd-primary-1); }
.bd-rk { font-size: 10px; color: var(--bd-danger); background: var(--bd-tag-red-bg); padding: 1px 5px; border-radius: 3px; margin-left: 6px; font-weight: 600; }
.bd-umono { display: block; font-size: 11px; color: var(--bd-t3); margin-top: 3px; font-family: ui-monospace, monospace; }
.bd-tg--sm { font-size: 11px; padding: 1px 6px; margin-right: 4px; }
.bd-t4 { color: var(--bd-t4); }

/* 抽屉 */
.bd-ud__head { display: flex; align-items: center; gap: 14px; padding-bottom: 18px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-ud__name { font-size: 17px; font-weight: 700; display: flex; align-items: center; }
.bd-ud__acct { font-size: 12px; color: var(--bd-t3); margin-top: 3px; }
.bd-ud__sec { font-size: 13px; font-weight: 600; margin: 20px 0 12px; }
.bd-life { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
.bd-life__step { display: flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--bd-t4); }
.bd-life__dot { width: 8px; height: 8px; border-radius: 50%; background: var(--bd-t4); }
.bd-life__step.on { color: var(--bd-t1); font-weight: 600; }
.bd-life__step.on .bd-life__dot { background: var(--bd-primary); box-shadow: 0 0 0 3px var(--bd-primary-1); }
.bd-life__arr { color: var(--bd-t4); font-size: 13px; margin: 0 4px; }
.bd-kv { display: flex; align-items: center; justify-content: space-between; padding: 9px 0; border-bottom: 1px solid var(--bd-fill-1); font-size: 13px; }
.bd-kv span { color: var(--bd-t3); }
.bd-kv b { font-weight: 500; color: var(--bd-t1); }
.bd-roles { display: flex; gap: 8px; flex-wrap: wrap; }
.bd-ud__acts { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 24px; }

.bd-uform__hint { font-size: 12.5px; color: var(--bd-t3); line-height: 1.6; margin-bottom: 16px; }
.bd-uform__f { margin-bottom: 16px; }
.bd-uform__f > label { display: block; font-size: 13px; font-weight: 500; color: var(--bd-t1); margin-bottom: 7px; }
.bd-uform__f :deep(.arco-input-wrapper), .bd-uform__f :deep(.arco-select-view) { width: 100%; }
.bd-uform__foot { display: flex; justify-content: flex-end; gap: 10px; margin-top: 22px; }
.bd-uform__foot .bd-btn[disabled] { opacity: .6; cursor: not-allowed; }
</style>
