<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">IPSec VPN 组网</div>
        <div class="bd-page__sub">站点到站点隧道 · IKEv2 · 国密 SM 套件 / 后量子 ML-KEM 混合 · 复用烛龙 IPSEC 引擎</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <button class="bd-btn" :disabled="!live" :title="live ? '' : '降级演示模式下不可写入'" @click="openCreate"><icon-plus />新建站点</button>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'topo' }" @click="tab = 'topo'">拓扑总览</span>
      <span class="bd-tab" :class="{ on: tab === 'list' }" @click="tab = 'list'">站点清单</span>
    </div>

    <!-- ============ 拓扑总览（P8 SVG）============ -->
    <div v-show="tab === 'topo'">
      <!-- 聚合统计 -->
      <div class="bd-stats">
        <div class="bd-card bd-stat">
          <div class="bd-stat__n">{{ sites.length }}</div>
          <div class="bd-stat__c">站点总数</div>
        </div>
        <div class="bd-card bd-stat">
          <div class="bd-stat__n" style="color: #00B42A">{{ upCount }}</div>
          <div class="bd-stat__c">在线隧道</div>
        </div>
        <div class="bd-card bd-stat">
          <div class="bd-stat__n" style="color: #F53F3F">{{ gmCount }}</div>
          <div class="bd-stat__c">国密 SM 站点</div>
        </div>
        <div class="bd-card bd-stat">
          <div class="bd-stat__n" style="color: #722ED1">{{ pqCount }}</div>
          <div class="bd-stat__c">后量子混合</div>
        </div>
      </div>

      <div class="bd-card bd-topo">
        <svg viewBox="0 0 960 460" width="100%" preserveAspectRatio="xMidYMid meet" font-family="-apple-system, 'PingFang SC', 'Segoe UI', sans-serif">
          <!-- 中心到各站点连线 -->
          <g v-for="(s, i) in sites" :key="'edge-' + s.id">
            <line
              :x1="hubCx" :y1="hubCy" :x2="nodePos(i).x" :y2="nodePos(i).y"
              fill="none" :stroke="strokeColor(s.status)" stroke-width="2"
              :stroke-dasharray="s.status === 'down' ? '5 5' : ''"
            />
          </g>

          <!-- 各站点节点 -->
          <g v-for="(s, i) in sites" :key="'node-' + s.id">
            <rect
              :x="nodePos(i).x - 86" :y="nodePos(i).y - 30" width="172" height="60" rx="10"
              fill="#FFFFFF" :stroke="strokeColor(s.status)" stroke-width="1.5"
            />
            <circle :cx="nodePos(i).x - 70" :cy="nodePos(i).y - 12" r="5" :fill="strokeColor(s.status)" />
            <text :x="nodePos(i).x - 58" :y="nodePos(i).y - 8" font-size="13" font-weight="600" fill="#1D2129">{{ s.name }}</text>
            <text :x="nodePos(i).x - 70" :y="nodePos(i).y + 14" font-size="11" fill="#86909C" font-family="ui-monospace, monospace">{{ s.remoteSubnet || '—' }}</text>
            <!-- 国密 / PQ 徽标 -->
            <g v-if="s.suite === 'gm'">
              <rect :x="nodePos(i).x + 32" :y="nodePos(i).y + 4" width="34" height="18" rx="9" fill="#FEF1F0" />
              <text :x="nodePos(i).x + 49" :y="nodePos(i).y + 17" font-size="10" font-weight="600" fill="#F53F3F" text-anchor="middle">国密</text>
            </g>
            <g v-if="s.pqHybrid">
              <rect :x="nodePos(i).x + 32" :y="nodePos(i).y - 22" width="34" height="18" rx="9" fill="#F5F0FF" />
              <text :x="nodePos(i).x + 49" :y="nodePos(i).y - 9" font-size="10" font-weight="600" fill="#722ED1" text-anchor="middle">PQ</text>
            </g>
          </g>

          <!-- 中心：本端网关 · 总部 -->
          <g>
            <rect :x="hubCx - 80" :y="hubCy - 34" width="160" height="68" rx="12" fill="#F2F7FF" stroke="#BEDAFF" stroke-width="1.5" />
            <circle :cx="hubCx - 56" :cy="hubCy - 8" r="9" fill="#165DFF" />
            <text :x="hubCx - 40" :y="hubCy - 3" font-size="14" font-weight="700" fill="#1D2129">本端网关</text>
            <text :x="hubCx" :y="hubCy + 20" font-size="12" fill="#86909C" text-anchor="middle">总部 · 烛龙 IPSEC 引擎</text>
          </g>

          <!-- 图例 -->
          <g transform="translate(24, 432)">
            <text x="0" y="12" font-size="12" font-weight="600" fill="#4E5969">图例</text>
            <line x1="56" y1="8" x2="88" y2="8" stroke="#00B42A" stroke-width="2" />
            <text x="96" y="12" font-size="12" fill="#86909C">已建立（实线）</text>
            <line x1="216" y1="8" x2="248" y2="8" stroke="#FF7D00" stroke-width="2" />
            <text x="256" y="12" font-size="12" fill="#86909C">协商中</text>
            <line x1="330" y1="8" x2="362" y2="8" stroke="#F53F3F" stroke-width="2" stroke-dasharray="5 5" />
            <text x="370" y="12" font-size="12" fill="#86909C">未建立（虚线）</text>
          </g>
        </svg>
      </div>
    </div>

    <!-- ============ 站点清单 ============ -->
    <div v-show="tab === 'list'" class="bd-tablecard">
      <div class="bd-toolbar">
        <span class="bd-toolbar__c">站点到站点隧道 · {{ shownSites.length }} 个</span>
        <div style="flex: 1" />
        <div class="bd-searchbox" style="width: 240px">
          <icon-search />
          <input v-model="kw" class="bd-searchbox__in" placeholder="按站点 / 网段 / 对端搜索" />
        </div>
      </div>
      <table class="bd-table">
        <thead>
          <tr>
            <th>站点</th><th>网段</th><th>IKE / 认证</th><th>套件</th>
            <th>相位参数</th><th>状态</th><th>流量</th><th>最近建立</th><th class="r">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in shownSites" :key="s.id">
            <td>
              <b style="color: var(--bd-t1); font-weight: 500">{{ s.name }}</b>
              <div class="bd-mono" style="font-size: 11px; color: var(--bd-t3); margin-top: 2px">{{ s.peer }}</div>
            </td>
            <td>
              <span class="bd-mono" style="font-size: 11.5px">{{ s.localSubnet || '—' }} ⇄ {{ s.remoteSubnet || '—' }}</span>
            </td>
            <td>
              <span class="bd-mono" style="font-size: 11.5px; color: var(--bd-t2)">{{ s.ikeVersion }}</span>
              <span class="bd-tg" :style="tagStyle(authColor(s.auth))" style="margin-left: 6px">{{ authText(s.auth) }}</span>
            </td>
            <td>
              <span class="bd-tg" :style="tagStyle(s.suite === 'gm' ? '#F53F3F' : '#86909C')">{{ s.suite === 'gm' ? '国密 SM' : '标准' }}</span>
              <span v-if="s.pqHybrid" class="bd-tg" :style="tagStyle('#722ED1')" style="margin-left: 4px">PQ 混合</span>
              <span v-if="s.pfs" class="bd-tg" :style="tagStyle('#00B42A')" style="margin-left: 4px">PFS</span>
            </td>
            <td>
              <div class="bd-mono" style="font-size: 11px; color: var(--bd-t3); line-height: 1.6">
                <div>相一 {{ s.phase1.enc }} / {{ s.phase1.hash }} / {{ s.phase1.dh }}</div>
                <div>相二 {{ s.phase2.enc }} / {{ s.phase2.hash }} / {{ s.phase2.dh }}</div>
              </div>
            </td>
            <td>
              <span class="bd-st"><span class="d" :style="{ background: strokeColor(s.status) }" />{{ statusText(s.status) }}</span>
            </td>
            <td>
              <div class="bd-mono" style="font-size: 11px; color: var(--bd-t3); line-height: 1.6">
                <div>↓ {{ formatBytes(s.rxBytes) }}</div>
                <div>↑ {{ formatBytes(s.txBytes) }}</div>
              </div>
            </td>
            <td><span style="font-size: 12px; color: var(--bd-t3)">{{ s.lastUp || '—' }}</span></td>
            <td class="r">
              <span class="bd-link" @click="toggle(s)">{{ s.status === 'up' ? '停用' : '启用' }}</span>
              <span class="bd-link" style="margin-left: 12px" @click="openEdit(s)">编辑</span>
              <a-popconfirm content="确定删除该站点隧道？" @ok="del(s)">
                <span class="bd-link bd-link--danger" style="margin-left: 12px">删除</span>
              </a-popconfirm>
            </td>
          </tr>
          <tr v-if="!shownSites.length"><td colspan="9" class="bd-empty">{{ kw ? '无匹配站点' : '暂无站点，点右上「新建站点」创建' }}</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 新建 / 编辑 站点 -->
    <a-modal v-model:visible="formOpen" :title="editing ? '编辑站点隧道' : '新建站点隧道'" :width="560" :footer="false" unmount-on-close>
      <div class="bd-uform">
        <div class="bd-uform__group">基本</div>
        <div class="bd-uform__row">
          <div class="bd-uform__f"><label>站点名称<i class="req">*</i></label>
            <a-input v-model="form.name" placeholder="如 上海分支" />
          </div>
          <div class="bd-uform__f"><label>对端网关地址<i class="req">*</i></label>
            <a-input v-model="form.peer" placeholder="如 203.0.113.20" />
          </div>
        </div>
        <div class="bd-uform__row">
          <div class="bd-uform__f"><label>本端网段</label>
            <a-input v-model="form.localSubnet" placeholder="如 10.10.0.0/16" />
          </div>
          <div class="bd-uform__f"><label>对端网段</label>
            <a-input v-model="form.remoteSubnet" placeholder="如 10.20.0.0/16" />
          </div>
        </div>

        <div class="bd-uform__group">认证 · 套件</div>
        <div class="bd-uform__row">
          <div class="bd-uform__f"><label>认证方式</label>
            <a-select v-model="form.auth">
              <a-option value="psk">预共享密钥（PSK）</a-option>
              <a-option value="cert">证书</a-option>
              <a-option value="sm2cert">SM2 证书</a-option>
            </a-select>
          </div>
          <div class="bd-uform__f"><label>密码套件</label>
            <a-radio-group v-model="form.suite" type="button" @change="onSuiteChange">
              <a-radio value="standard">标准</a-radio>
              <a-radio value="gm">国密</a-radio>
            </a-radio-group>
          </div>
        </div>
        <div class="bd-uform__row">
          <div class="bd-uform__f bd-uform__sw"><label>PFS 完美前向保密</label><a-switch v-model="form.pfs" /></div>
          <div class="bd-uform__f bd-uform__sw"><label>后量子 ML-KEM 混合</label><a-switch v-model="form.pqHybrid" /></div>
        </div>
        <div class="bd-uform__note">协议版本固定为 <span class="bd-mono">IKEv2</span>，提交时自动带上。</div>

        <div class="bd-uform__group">相一参数（IKE SA）</div>
        <div class="bd-uform__row3">
          <div class="bd-uform__f"><label>加密</label>
            <a-select v-model="form.phase1.enc"><a-option v-for="e in ENC_OPTS" :key="e" :value="e">{{ e }}</a-option></a-select>
          </div>
          <div class="bd-uform__f"><label>哈希</label>
            <a-select v-model="form.phase1.hash"><a-option v-for="h in HASH_OPTS" :key="h" :value="h">{{ h }}</a-option></a-select>
          </div>
          <div class="bd-uform__f"><label>DH 群</label>
            <a-select v-model="form.phase1.dh"><a-option v-for="d in DH_OPTS" :key="d" :value="d">{{ d }}</a-option></a-select>
          </div>
        </div>

        <div class="bd-uform__group">相二参数（IPSec SA）</div>
        <div class="bd-uform__row3">
          <div class="bd-uform__f"><label>加密</label>
            <a-select v-model="form.phase2.enc"><a-option v-for="e in ENC_OPTS" :key="e" :value="e">{{ e }}</a-option></a-select>
          </div>
          <div class="bd-uform__f"><label>哈希</label>
            <a-select v-model="form.phase2.hash"><a-option v-for="h in HASH_OPTS" :key="h" :value="h">{{ h }}</a-option></a-select>
          </div>
          <div class="bd-uform__f"><label>DH 群</label>
            <a-select v-model="form.phase2.dh"><a-option v-for="d in DH_OPTS" :key="d" :value="d">{{ d }}</a-option></a-select>
          </div>
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
import { ref, reactive, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type IpsecSite, type IpsecResp } from '@/lib/api';

const tab = ref<'topo' | 'list'>('topo');
const live = ref(false);
const saving = ref(false);

const ENC_OPTS = ['AES256-GCM', 'AES256-CBC', 'AES128-GCM', 'SM4-GCM', 'SM4-CBC'];
const HASH_OPTS = ['SHA256', 'SHA384', 'SM3'];
const DH_OPTS = ['group14', 'group19', 'group21', 'group24'];

/* ── 内置 mock（结构同后端 IpsecResp）── */
const MOCK: IpsecResp = {
  sites: [
    {
      id: 'site-sh', name: '上海分支', peer: '203.0.113.20', localSubnet: '10.10.0.0/16', remoteSubnet: '10.20.0.0/16',
      ikeVersion: 'IKEv2', auth: 'sm2cert', suite: 'gm',
      phase1: { enc: 'SM4-GCM', hash: 'SM3', dh: 'group24' },
      phase2: { enc: 'SM4-GCM', hash: 'SM3', dh: 'group24' },
      pfs: true, pqHybrid: true,
      status: 'up', rxBytes: 4283934720, txBytes: 1879048192, lastUp: '2026-06-24 09:12'
    },
    {
      id: 'site-bj', name: '北京总部备线', peer: '198.51.100.7', localSubnet: '10.10.0.0/16', remoteSubnet: '10.30.0.0/16',
      ikeVersion: 'IKEv2', auth: 'cert', suite: 'standard',
      phase1: { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' },
      phase2: { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' },
      pfs: true, pqHybrid: false,
      status: 'up', rxBytes: 912680550, txBytes: 524288000, lastUp: '2026-06-24 08:41'
    },
    {
      id: 'site-gz', name: '广州办事处', peer: '192.0.2.55', localSubnet: '10.10.0.0/16', remoteSubnet: '10.40.0.0/24',
      ikeVersion: 'IKEv2', auth: 'psk', suite: 'standard',
      phase1: { enc: 'AES128-GCM', hash: 'SHA256', dh: 'group14' },
      phase2: { enc: 'AES128-GCM', hash: 'SHA256', dh: 'group14' },
      pfs: false, pqHybrid: false,
      status: 'connecting', rxBytes: 0, txBytes: 4096, lastUp: '—'
    },
    {
      id: 'site-cd', name: '成都灾备', peer: '203.0.113.99', localSubnet: '10.10.0.0/16', remoteSubnet: '10.50.0.0/16',
      ikeVersion: 'IKEv2', auth: 'cert', suite: 'standard',
      phase1: { enc: 'AES256-CBC', hash: 'SHA384', dh: 'group21' },
      phase2: { enc: 'AES256-CBC', hash: 'SHA384', dh: 'group21' },
      pfs: true, pqHybrid: false,
      status: 'down', rxBytes: 0, txBytes: 0, lastUp: '2026-06-23 22:05'
    }
  ]
};

const sites = ref<IpsecSite[]>([]);

/* ── 站点清单关键词检索（拓扑总览不受影响，始终展示全部）── */
const kw = ref('');
const shownSites = computed(() => {
  const k = kw.value.trim().toLowerCase();
  if (!k) return sites.value;
  return sites.value.filter((s) =>
    [s.name, s.peer, s.localSubnet, s.remoteSubnet].some((f) => (f || '').toLowerCase().includes(k))
  );
});

const upCount = computed(() => sites.value.filter((s) => s.status === 'up').length);
const gmCount = computed(() => sites.value.filter((s) => s.suite === 'gm').length);
const pqCount = computed(() => sites.value.filter((s) => s.pqHybrid).length);

/* ── SVG 极坐标布局 ── */
const hubCx = 480;
const hubCy = 240;
const radius = 170;
function nodePos(i: number) {
  const n = sites.value.length || 1;
  const angle = (i / n) * Math.PI * 2 - Math.PI / 2;
  return { x: hubCx + radius * Math.cos(angle), y: hubCy + radius * Math.sin(angle) };
}

/* ── 颜色 / 文案 ── */
function strokeColor(status: string) {
  return status === 'up' ? '#00B42A' : status === 'connecting' ? '#FF7D00' : '#F53F3F';
}
function statusText(status: string) {
  return status === 'up' ? '已建立' : status === 'connecting' ? '协商中' : '未建立';
}
function authText(auth: string) {
  return auth === 'psk' ? '预共享密钥' : auth === 'cert' ? '证书' : 'SM2 证书';
}
function authColor(auth: string) {
  return auth === 'psk' ? '#86909C' : auth === 'cert' ? '#165DFF' : '#F53F3F';
}
function tagStyle(color: string) { return { color, background: color + '14' }; }

function formatBytes(n: number): string {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

/* ── 表单 ── */
const formOpen = ref(false);
const editing = ref(false);
const form = reactive<IpsecSite>({
  id: '', name: '', peer: '', localSubnet: '', remoteSubnet: '',
  ikeVersion: 'IKEv2', auth: 'psk', suite: 'standard',
  phase1: { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' },
  phase2: { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' },
  pfs: true, pqHybrid: false,
  status: 'down', rxBytes: 0, txBytes: 0, lastUp: ''
});

function applyDefaults(suite: 'standard' | 'gm') {
  if (suite === 'gm') {
    form.phase1 = { enc: 'SM4-GCM', hash: 'SM3', dh: 'group24' };
    form.phase2 = { enc: 'SM4-GCM', hash: 'SM3', dh: 'group24' };
  } else {
    form.phase1 = { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' };
    form.phase2 = { enc: 'AES256-GCM', hash: 'SHA256', dh: 'group19' };
  }
}
function onSuiteChange(v: string | number | boolean) {
  applyDefaults(v === 'gm' ? 'gm' : 'standard');
}

function openCreate() {
  editing.value = false;
  form.id = ''; form.name = ''; form.peer = ''; form.localSubnet = ''; form.remoteSubnet = '';
  form.ikeVersion = 'IKEv2'; form.auth = 'psk'; form.suite = 'standard';
  form.pfs = true; form.pqHybrid = false;
  form.status = 'down'; form.rxBytes = 0; form.txBytes = 0; form.lastUp = '';
  applyDefaults('standard');
  formOpen.value = true;
}
function openEdit(s: IpsecSite) {
  editing.value = true;
  form.id = s.id; form.name = s.name; form.peer = s.peer;
  form.localSubnet = s.localSubnet; form.remoteSubnet = s.remoteSubnet;
  form.ikeVersion = s.ikeVersion || 'IKEv2'; form.auth = s.auth; form.suite = s.suite;
  form.phase1 = { ...s.phase1 }; form.phase2 = { ...s.phase2 };
  form.pfs = s.pfs; form.pqHybrid = s.pqHybrid;
  form.status = s.status; form.rxBytes = s.rxBytes; form.txBytes = s.txBytes; form.lastUp = s.lastUp;
  formOpen.value = true;
}

async function save() {
  if (!live.value) { Message.warning('当前为降级演示，未连接后端，无法写入'); return; }
  if (!form.name || !form.peer) { Message.warning('站点名称与对端网关地址必填'); return; }
  saving.value = true;
  const payload: IpsecSite = {
    ...form,
    ikeVersion: 'IKEv2',
    phase1: { ...form.phase1 },
    phase2: { ...form.phase2 }
  };
  try {
    await api('/ipsec', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    Message.success(`站点「${form.name}」已落库`);
    formOpen.value = false;
    await load();
  } catch { Message.error('保存失败，请检查管理员权限或后端连接'); } finally { saving.value = false; }
}

async function del(s: IpsecSite) {
  if (!live.value) { Message.warning('当前为降级演示，未连接后端，无法写入'); return; }
  try {
    await api(`/ipsec/${s.id}`, { method: 'DELETE' });
    Message.success(`站点「${s.name}」已删除`);
    await load();
  } catch { Message.error('删除失败，请检查权限或后端连接'); }
}

async function toggle(s: IpsecSite) {
  if (!live.value) { Message.warning('当前为降级演示，未连接后端，无法写入'); return; }
  try {
    await api(`/ipsec/${s.id}/toggle`, { method: 'POST' });
    await load();
  } catch { Message.error('启停失败，请检查权限或后端连接'); }
}

async function load() {
  try {
    const r = await api<IpsecResp>('/ipsec');
    sites.value = r.sites; live.value = true;
  } catch { sites.value = MOCK.sites; live.value = false; }
}

onMounted(load);
</script>

<style scoped>
/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

/* 聚合统计 */
.bd-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 16px; }
.bd-stat { padding: 16px 18px; }
.bd-stat__n { font-size: 28px; font-weight: 700; color: var(--bd-t1); line-height: 1.1; }
.bd-stat__c { margin-top: 6px; font-size: 12.5px; color: var(--bd-t3); }

/* 拓扑卡 */
.bd-topo { padding: 16px 18px; }
.bd-topo svg { display: block; }

/* 搜索框输入 */
.bd-searchbox__in { border: none; outline: none; background: transparent; flex: 1; min-width: 0; font-size: 13px; color: var(--bd-t1); }
.bd-searchbox__in::placeholder { color: var(--bd-t3); }

/* 降级演示下禁用写入按钮 */
.bd-btn:disabled { opacity: .5; cursor: not-allowed; }

/* 表单 */
.bd-uform__group { font-size: 13px; font-weight: 600; color: var(--bd-t1); margin: 16px 0 10px; padding-bottom: 6px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-uform__group:first-child { margin-top: 0; }
.bd-uform__row { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.bd-uform__row3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; }
.bd-uform__f { margin-bottom: 12px; }
.bd-uform__f label { display: block; font-size: 12.5px; color: var(--bd-t2); margin-bottom: 6px; }
.bd-uform__f .req { color: var(--bd-danger); margin-left: 2px; font-style: normal; }
.bd-uform__sw { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.bd-uform__sw label { margin-bottom: 0; }
.bd-uform__note { font-size: 12px; color: var(--bd-t3); margin: -2px 0 6px; }
.bd-uform__foot { display: flex; justify-content: flex-end; gap: 10px; margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--bd-fill-2); }
.bd-empty { text-align: center; color: var(--bd-t3); padding: 28px 0; }
</style>
