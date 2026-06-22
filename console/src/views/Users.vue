<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">用户与角色 · 访问者目录</div>
        <div class="bd-page__sub">多身份源统一纳管 · 组织树浏览 · 实时在线态与账号生命周期就地处置</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <button class="bd-btn bd-btn--ghost"><icon-upload />批量导入</button>
        <button class="bd-btn"><icon-plus />新增用户</button>
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
      <!-- 组织树 -->
      <div class="bd-card bd-otree">
        <div class="bd-otree__h">组织架构</div>
        <button v-for="n in flatOrg" :key="n.key" class="bd-onode" :class="{ on: org === n.key }"
          :style="{ paddingLeft: 10 + n.depth * 16 + 'px' }" @click="org = n.key">
          <icon-folder v-if="n.depth === 0" class="bd-onode__ic" /><icon-user-group v-else class="bd-onode__ic" />
          <span class="bd-onode__t">{{ n.title }}</span>
          <span class="bd-onode__n">{{ n.members }}</span>
        </button>
      </div>

      <!-- 用户表 -->
      <div class="bd-tablecard" style="flex: 1; min-width: 0">
        <div class="bd-toolbar">
          <span class="bd-toolbar__c">{{ orgTitle }} · {{ shown.length }} 人</span>
          <div style="flex: 1" />
          <div class="bd-searchbox" style="width: 240px"><icon-search />按用户名 / 账号 / IP 搜索</div>
        </div>
        <table class="bd-table">
          <thead>
            <tr><th>用户</th><th>所属组织</th><th>终端 / 接入</th><th>认证方式</th><th>状态</th><th class="r">操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="u in shown" :key="u.id" :class="{ sel: sel?.id === u.id }">
              <td>
                <div class="bd-cellname" @click="open(u)">
                  <span class="bd-avatar" :style="{ background: avBg(u) }">{{ u.name.slice(0, 1) }}</span>
                  <span><b>{{ u.name }}<span v-if="u.risk === 'high'" class="bd-rk">高危</span></b><i class="bd-mono">{{ u.account }}</i></span>
                </div>
              </td>
              <td>{{ u.org }}</td>
              <td>
                <span class="bd-st"><span class="d" :style="{ background: u.online ? 'var(--bd-success)' : 'var(--bd-t4)' }" />{{ u.online ? '在线' : '离线' }}</span>
                <span class="bd-umono">{{ u.device }} · {{ u.ip }}</span>
              </td>
              <td>{{ u.auth }}</td>
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
            <div class="bd-ud__acct bd-mono">{{ sel.account }} · {{ sel.org }}</div>
          </div>
        </div>

        <!-- 账号生命周期状态机 -->
        <div class="bd-ud__sec">账号生命周期</div>
        <div class="bd-life">
          <div v-for="(st, i) in LIFE" :key="st.key" class="bd-life__step" :class="{ on: st.key === sel.status }">
            <span class="bd-life__dot" />{{ st.label }}<icon-right v-if="i < LIFE.length - 1" class="bd-life__arr" />
          </div>
        </div>

        <div class="bd-ud__sec">接入信息</div>
        <div class="bd-kv"><span>终端</span><b>{{ sel.device }}</b></div>
        <div class="bd-kv"><span>接入 IP</span><b class="bd-mono">{{ sel.ip }}</b></div>
        <div class="bd-kv"><span>认证方式</span><b>{{ sel.auth }}</b></div>
        <div class="bd-kv"><span>最后登录</span><b>{{ sel.lastLogin }}</b></div>
        <div class="bd-kv"><span>风险评估</span><b><span class="bd-tg" :style="tagStyle(riskColor(sel.risk))">{{ riskLabel(sel.risk) }}</span></b></div>

        <div class="bd-ud__sec">角色</div>
        <div class="bd-roles"><span v-for="r in sel.roles" :key="r" class="bd-tg" :style="tagStyle('#165DFF')">{{ r }}</span></div>

        <div class="bd-ud__acts">
          <button v-if="sel.status === 'locked'" class="bd-btn" @click="act('已解锁')"><icon-unlock />解锁账号</button>
          <button class="bd-btn bd-btn--ghost" @click="act('密码重置链接已发送')">重置密码</button>
          <button v-if="sel.online" class="bd-btn bd-btn--ghost" @click="act('已强制下线')">强制下线</button>
          <button class="bd-btn bd-btn--ghost bd-btn--danger" @click="act('已禁用账号')">禁用账号</button>
        </div>
      </div>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type UserDirBundle, type Directory, type OrgUnit, type DirUser } from '@/lib/api';

const live = ref(false);
const directories = ref<Directory[]>([{ key: 'local', name: '本地目录', type: 'local', users: 0, online: 0, lastSync: '' }]);
const orgTree = ref<OrgUnit[]>([]);
const users = ref<DirUser[]>([]);
const dir = ref('local');
const org = ref('root');
const sel = ref<DirUser | null>(null);
const drawer = ref(false);

const curDir = computed(() => directories.value.find((d) => d.key === dir.value));

interface FlatOrg extends OrgUnit { depth: number }
const flatOrg = computed<FlatOrg[]>(() => {
  const out: FlatOrg[] = [];
  const walk = (ns: OrgUnit[], d: number) => ns.forEach((n) => { out.push({ ...n, depth: d }); n.children && walk(n.children, d + 1); });
  walk(orgTree.value, 0);
  return out;
});
const orgTitle = computed(() => flatOrg.value.find((n) => n.key === org.value)?.title ?? '全部');
const shown = computed(() => (org.value === 'root' ? users.value : users.value.filter((u) => u.orgKey === org.value)));

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

function open(u: DirUser) { sel.value = u; drawer.value = true; }
function act(msg: string) { Message.success(`${sel.value?.name}：${msg}`); }

onMounted(async () => {
  try {
    const b = await api<UserDirBundle>('/users');
    directories.value = b.directories; orgTree.value = b.orgTree; users.value = b.users; live.value = true;
  } catch { live.value = false; }
});
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
.bd-otree { width: 220px; flex: none; padding: 10px; }
.bd-otree__h { font-size: 12px; font-weight: 600; color: var(--bd-t3); padding: 4px 8px 10px; }
.bd-onode { width: 100%; display: flex; align-items: center; gap: 8px; height: 36px; padding-right: 10px; border: none; background: transparent; border-radius: 7px; cursor: pointer; font-size: 13px; color: var(--bd-t2); }
.bd-onode:hover { background: var(--bd-fill-2); }
.bd-onode.on { background: var(--bd-primary-1); color: var(--bd-primary); font-weight: 500; }
.bd-onode__ic { font-size: 15px; flex: none; }
.bd-onode__t { flex: 1; text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bd-onode__n { font-size: 11px; color: var(--bd-t3); }

.bd-toolbar__c { font-size: 12.5px; color: var(--bd-t3); }
.bd-table tr.sel { background: var(--bd-primary-1); }
.bd-rk { font-size: 10px; color: var(--bd-danger); background: var(--bd-tag-red-bg); padding: 1px 5px; border-radius: 3px; margin-left: 6px; font-weight: 600; }
.bd-umono { display: block; font-size: 11px; color: var(--bd-t3); margin-top: 3px; font-family: ui-monospace, monospace; }

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
</style>
