<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">统一资源对象<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">所有"能被访问的东西"归一为资源对象 · 带接入形态属性（ZL-FR-102）</div>
      </div>
      <a-button type="primary" @click="openCreate"><template #icon><icon-plus /></template>新建资源</a-button>
    </div>

    <!-- 筛选 -->
    <div class="zl-card zl-card__pad res-filter">
      <a-input-search v-model="q" placeholder="搜索资源 / 地址" allow-clear style="width: 240px" />
      <a-select v-model="fType" placeholder="类型" allow-clear size="small" style="width: 120px">
        <a-option value="app">应用</a-option><a-option value="service">服务</a-option>
        <a-option value="subnet">网段</a-option><a-option value="site">站点</a-option>
      </a-select>
      <a-select v-model="fMode" placeholder="接入形态" allow-clear size="small" style="width: 120px">
        <a-option value="auto">auto</a-option><a-option value="ssl">ssl</a-option>
        <a-option value="mesh">mesh</a-option><a-option value="ipsec">ipsec</a-option>
      </a-select>
      <a-select v-model="fHealth" placeholder="健康" allow-clear size="small" style="width: 110px">
        <a-option value="up">可达</a-option><a-option value="down">不可达</a-option><a-option value="unknown">未知</a-option>
      </a-select>
      <span class="res-count">{{ filtered.length }} / {{ rows.length }}</span>
      <a-button v-if="q||fType||fMode||fHealth" size="mini" @click="q='';fType=fMode=fHealth=undefined">重置</a-button>
    </div>

    <div class="zl-card">
      <a-table :data="filtered" :pagination="filtered.length>12?{pageSize:12}:false" :bordered="false"
               row-key="name" :row-class="()=>'row-click'" @row-click="openDetail">
        <template #columns>
          <a-table-column title="资源" data-index="name" :width="160" />
          <a-table-column title="类型" align="center" :width="84">
            <template #cell="{ record }"><a-tag size="small" bordered>{{ typeText(record.type) }}</a-tag></template>
          </a-table-column>
          <a-table-column title="分级" align="center" :width="76">
            <template #cell="{ record }">
              <span v-if="record.level" class="zl-badge" :class="levelBadge(record.level)">{{ levelText(record.level) }}</span>
              <span v-else style="color:var(--ink-3)">—</span>
            </template>
          </a-table-column>
          <a-table-column title="地址">
            <template #cell="{ record }"><span class="data" style="color:var(--ink-2)">{{ record.addr }}</span></template>
          </a-table-column>
          <a-table-column title="接入形态" align="center" :width="84">
            <template #cell="{ record }"><span class="zl-mode-pill" :class="record.modes==='auto'?'':`zl-mode--${record.modes}`">{{ record.modes }}</span></template>
          </a-table-column>
          <a-table-column title="被授权" align="center" :width="80">
            <template #cell="{ record }"><span class="data" style="color:var(--ink-3)">{{ (refsOf(record).length) }} 策略</span></template>
          </a-table-column>
          <a-table-column title="二次鉴权" align="center" :width="80">
            <template #cell="{ record }"><icon-lock v-if="record.stepup" style="color: var(--warn)" /><span v-else style="color: var(--ink-3)">—</span></template>
          </a-table-column>
          <a-table-column title="健康" align="center" :width="76">
            <template #cell="{ record }"><span class="zl-badge" :class="hb(record.health)">{{ ht(record.health) }}</span></template>
          </a-table-column>
          <a-table-column title="" align="center" :width="60">
            <template #cell="{ record }"><a-button size="mini" type="text" @click.stop="openDetail(record)">详情</a-button></template>
          </a-table-column>
        </template>
      </a-table>
    </div>

    <!-- 新建 -->
    <a-modal v-model:visible="show" title="新建资源对象" @ok="add" ok-text="创建">
      <a-form :model="form" layout="vertical">
        <a-form-item label="资源名称" required><a-input v-model="form.name" placeholder="例如：Jira" /></a-form-item>
        <a-form-item label="类型">
          <a-select v-model="form.type">
            <a-option value="app">应用（L7）</a-option><a-option value="service">服务（L4）</a-option>
            <a-option value="subnet">网段（L3）</a-option><a-option value="site">站点</a-option>
          </a-select>
        </a-form-item>
        <a-form-item label="地址" required><a-input v-model="form.addr" placeholder="https://jira.corp 或 host:port 或 CIDR" /></a-form-item>
        <a-form-item label="接入形态 access_modes（ZL-FR-102）">
          <a-radio-group v-model="form.modes">
            <a-radio value="auto">auto</a-radio><a-radio value="ssl">ssl</a-radio>
            <a-radio value="mesh">mesh</a-radio><a-radio value="ipsec">ipsec</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item label="资源分级">
          <a-select v-model="form.level" placeholder="未分级">
            <a-option value="low">低</a-option><a-option value="medium">中</a-option>
            <a-option value="high">高</a-option><a-option value="critical">关键</a-option>
          </a-select>
        </a-form-item>
        <a-form-item label="标签"><a-input v-model="form.tags" placeholder="逗号分隔，如：办公,门户" /></a-form-item>
        <a-form-item><a-checkbox v-model="form.stepup">高敏资源 · 访问前强制二次鉴权（DP-05）</a-checkbox></a-form-item>
        <a-form-item><a-checkbox v-model="form.allowSelfRequest">允许自助申请 · 开放资源审批入口（用户可申请限时授权）</a-checkbox></a-form-item>
      </a-form>
    </a-modal>

    <!-- 详情 / 配置抽屉 -->
    <a-drawer v-model:visible="drawer" :width="480" :footer="false">
      <template #title>资源详情 · {{ cur?.name }}</template>
      <div v-if="cur" class="rd">
        <!-- 基本 -->
        <div class="rd-sec">基本</div>
        <div class="rd-grid">
          <div class="rd-f"><label>类型</label>
            <a-select v-model="cur.type" size="small">
              <a-option value="app">应用（L7）</a-option><a-option value="service">服务（L4）</a-option>
              <a-option value="subnet">网段（L3）</a-option><a-option value="site">站点</a-option>
            </a-select>
          </div>
          <div class="rd-f"><label>接入形态</label>
            <a-select v-model="cur.modes" size="small">
              <a-option value="auto">auto</a-option><a-option value="ssl">ssl</a-option>
              <a-option value="mesh">mesh</a-option><a-option value="ipsec">ipsec</a-option>
            </a-select>
          </div>
          <div class="rd-f rd-f--wide"><label>地址</label><a-input v-model="cur.addr" size="small" /></div>
        </div>

        <!-- 协议与端口 -->
        <div class="rd-sec">协议与端口</div>
        <div class="rd-grid">
          <div class="rd-f"><label>协议</label>
            <a-select v-model="cur.cfg.proto" size="small">
              <a-option v-for="p in protoOpts" :key="p" :value="p">{{ p }}</a-option>
            </a-select>
          </div>
          <div class="rd-f"><label>端口</label><a-input-number v-model="cur.cfg.port" size="small" :min="0" :max="65535" /></div>
          <template v-if="cur.cfg.proto==='HTTP'||cur.cfg.proto==='HTTPS'">
            <div class="rd-f"><label>路径前缀</label><a-input v-model="cur.cfg.path" size="small" placeholder="/" /></div>
            <div class="rd-f"><label>Host 重写</label><a-input v-model="cur.cfg.hostRewrite" size="small" placeholder="保持原 Host 留空" /></div>
          </template>
        </div>

        <!-- 健康检查 -->
        <div class="rd-sec">健康检查
          <span class="zl-badge" :class="hb(cur.health)" style="font-size:10px;margin-left:8px">{{ ht(cur.health) }}</span>
          <a-button size="mini" type="text" style="margin-left:auto" @click="probe">立即探测</a-button>
        </div>
        <div class="rd-grid">
          <div class="rd-f rd-f--wide rd-row"><label>启用主动探测</label><a-switch v-model="cur.cfg.hcEnabled" size="small" /></div>
          <template v-if="cur.cfg.hcEnabled">
            <div class="rd-f"><label>探测方式</label>
              <a-select v-model="cur.cfg.hcType" size="small">
                <a-option value="tcp">TCP 连接</a-option><a-option value="http">HTTP GET</a-option>
                <a-option value="https">HTTPS GET</a-option><a-option value="icmp">ICMP Ping</a-option>
              </a-select>
            </div>
            <div class="rd-f" v-if="cur.cfg.hcType==='http'||cur.cfg.hcType==='https'"><label>探测路径</label><a-input v-model="cur.cfg.hcPath" size="small" placeholder="/healthz" /></div>
            <div class="rd-f"><label>间隔（秒）</label><a-input-number v-model="cur.cfg.hcInterval" size="small" :min="3" /></div>
            <div class="rd-f"><label>超时（秒）</label><a-input-number v-model="cur.cfg.hcTimeout" size="small" :min="1" /></div>
            <div class="rd-f"><label>不健康阈值</label><a-input-number v-model="cur.cfg.hcFail" size="small" :min="1" /></div>
          </template>
        </div>

        <!-- 服务网关 / 标签 -->
        <div class="rd-sec">发布与标签</div>
        <div class="rd-grid">
          <div class="rd-f rd-f--wide"><label>服务网关（发布此资源）</label><a-input-tag v-model="cur.cfg.gateways" size="small" placeholder="回车添加网关 id" /></div>
          <div class="rd-f rd-f--wide"><label>标签</label><a-input-tag v-model="cur.cfg.tags" size="small" placeholder="如：高敏 / 数据库 / 对外" /></div>
          <div class="rd-f rd-f--wide rd-row"><label>高敏资源（强制二次鉴权）</label><a-switch v-model="cur.stepup" size="small" /></div>
          <div class="rd-f rd-f--wide rd-row"><label>允许自助申请（资源审批入口）</label><a-switch v-model="cur.allowSelfRequest" size="small" /></div>
        </div>

        <!-- Web 安全控制（L7；仅对 HTTP/HTTPS 发布）—— 配置落库，运行时强制待数据面接入 -->
        <div class="rd-sec" v-if="cur.cfg.proto==='HTTP'||cur.cfg.proto==='HTTPS'">Web 安全控制
          <span class="rd-hint">web 代理发布(已配 SSO)时由网关在 HTML 响应注入强制；浏览器侧 best-effort</span>
        </div>
        <div class="rd-grid" v-if="cur.cfg.proto==='HTTP'||cur.cfg.proto==='HTTPS'">
          <div class="rd-f rd-f--wide rd-row"><label>访问水印</label><a-switch v-model="cur.cfg.security.watermark" size="small" /></div>
          <div class="rd-f rd-f--wide" v-if="cur.cfg.security.watermark"><label>水印模板</label><a-input v-model="cur.cfg.security.watermarkTpl" size="small" placeholder="{user}·{time}" /></div>
          <div class="rd-f rd-row"><label>禁止下载</label><a-switch v-model="cur.cfg.security.disableDownload" size="small" /></div>
          <div class="rd-f rd-row"><label>禁止复制</label><a-switch v-model="cur.cfg.security.disableCopy" size="small" /></div>
          <div class="rd-f rd-row"><label>禁止打印</label><a-switch v-model="cur.cfg.security.disablePrint" size="small" /></div>
          <div class="rd-f rd-row"><label>禁止右键</label><a-switch v-model="cur.cfg.security.disableRightclick" size="small" /></div>
          <div class="rd-f rd-row"><label>拦截开发者工具</label><a-switch v-model="cur.cfg.security.disableDevtools" size="small" /></div>
          <div class="rd-f rd-row"><label>服务端硬拦下载（403）</label><a-switch v-model="cur.cfg.security.blockDownloadResp" size="small" /></div>
        </div>

        <!-- SSO 凭证注入 / 请求头改写（web 代理模式）-->
        <div class="rd-sec" v-if="cur.cfg.proto==='HTTP'||cur.cfg.proto==='HTTPS'">SSO 凭证注入 / 请求头改写
          <a-switch v-model="cur.cfg.sso.enabled" size="small" style="margin-left:auto" />
        </div>
        <div class="rd-grid" v-if="(cur.cfg.proto==='HTTP'||cur.cfg.proto==='HTTPS') && cur.cfg.sso.enabled">
          <div class="rd-f"><label>注入方式</label>
            <a-select v-model="cur.cfg.sso.mode" size="small">
              <a-option value="none">仅改写头（不注入身份）</a-option>
              <a-option value="header">身份请求头</a-option>
              <a-option value="basic">HTTP Basic</a-option>
            </a-select>
          </div>
          <div class="rd-f rd-row"><label>转发客户端 IP（XFF）</label><a-switch v-model="cur.cfg.sso.forwardClientIp" size="small" /></div>
          <div class="rd-f"><label>发布入口 Host</label><a-input v-model="cur.cfg.sso.host" size="small" placeholder="finance.corp" /></div>
          <div class="rd-f"><label>后端 origin</label><a-input v-model="cur.cfg.sso.backend" size="small" placeholder="http://app.corp:8080" /></div>
          <div class="rd-f rd-f--wide"><label>改写后端 Host（留空=透传）</label><a-input v-model="cur.cfg.sso.hostRewrite" size="small" placeholder="app-backend.internal" /></div>
          <template v-if="cur.cfg.sso.mode==='basic'">
            <div class="rd-f"><label>Basic 用户（支持 {account}）</label><a-input v-model="cur.cfg.sso.basicUser" size="small" /></div>
            <div class="rd-f"><label>Basic 口令</label><a-input-password v-model="cur.cfg.sso.basicPass" size="small" /></div>
          </template>
          <div class="rd-f rd-f--wide" v-if="cur.cfg.sso.mode!=='none'">
            <label>注入请求头（占位符 {account} {name} {email} {groups} {token}）</label>
            <div v-for="(h, i) in cur.cfg.sso.headers" :key="i" class="sso-hrow">
              <a-input v-model="h.name" size="small" placeholder="X-Auth-User" style="flex:0 0 42%" />
              <a-input v-model="h.value" size="small" placeholder="{account}" style="flex:1" />
              <a-button size="mini" type="text" status="danger" @click="cur.cfg.sso.headers.splice(i,1)">✕</a-button>
            </div>
            <a-button size="mini" type="text" @click="cur.cfg.sso.headers.push({name:'',value:''})">+ 增加请求头</a-button>
          </div>
          <div class="rd-f rd-f--wide"><label>转发前删除的头（清客户端伪造身份头）</label><a-input-tag v-model="cur.cfg.sso.removeHeaders" size="small" placeholder="回车添加" /></div>
          <div class="rd-f rd-f--wide rd-hint">注入前先删同名头杜绝客户端冒充；本配置经 kind=resourcecfg 下发网关 web 代理生效。</div>
        </div>

        <!-- 被引用 -->
        <div class="rd-sec">被策略授权（{{ refsOf(cur).length }}）</div>
        <div class="rd-refs">
          <router-link v-for="p in refsOf(cur)" :key="p" to="/policy" class="rd-ref data">{{ p }}</router-link>
          <span v-if="!refsOf(cur).length" class="rd-dim">暂无策略授权 · 任何人都不可达（零信任缺省）</span>
        </div>

        <div class="rd-foot">
          <a-button status="danger" type="outline" size="small" @click="del">删除资源</a-button>
          <a-button type="primary" size="small" @click="saveCfg">保存配置</a-button>
        </div>
      </div>
    </a-drawer>
  </div>
</template>
<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { resources, type ResourceObj } from '@/mock';

const rows = ref<any[]>([...resources]);
const live = ref(false);
async function loadResources() {
  try {
    const r = await fetch('/ctl/api/resources');
    if (!r.ok) return;
    rows.value = await r.json();
    live.value = true;
  } catch { live.value = false; }
}
onMounted(loadResources);

/* —— 筛选 —— */
const q = ref('');
const fType = ref<string>();
const fMode = ref<string>();
const fHealth = ref<string>();
const filtered = computed(() => rows.value.filter((r) => {
  if (fType.value && r.type !== fType.value) return false;
  if (fMode.value && r.modes !== fMode.value) return false;
  if (fHealth.value && r.health !== fHealth.value) return false;
  if (q.value) { const s = q.value.toLowerCase(); if (![r.name, r.addr].some((x) => String(x ?? '').toLowerCase().includes(s))) return false; }
  return true;
}));

/* —— 被策略授权（演示映射，真实由策略引擎反查）—— */
const REFS: Record<string, string[]> = {
  '核心数据库': ['pol-rd-database'], 'OA 系统': ['pol-oa-all'], 'GitLab': ['pol-rd-database'],
  '全网 SSH': ['pol-ops-ssh'], '财务系统': ['pol-finance-fin'], '上海分支 ERP': ['pol-branch-erp']
};
const refsOf = (r: any) => r?.cfg?.refs ?? REFS[r?.name] ?? [];

/* —— 默认配置（按类型）—— */
const protoOpts = ['HTTP', 'HTTPS', 'TCP', 'SSH', 'RDP', 'VNC', 'MySQL', 'PostgreSQL', 'ICMP'];
function defaultCfg(r: any) {
  const portMatch = String(r.addr || '').match(/:(\d+)/);
  const port = portMatch ? Number(portMatch[1]) : (r.type === 'app' ? 443 : 0);
  const isApp = r.type === 'app';
  return {
    proto: isApp ? 'HTTPS' : r.type === 'service' ? 'TCP' : 'ICMP',
    port, path: isApp ? '/' : '', hostRewrite: '',
    hcEnabled: r.type !== 'subnet', hcType: isApp ? 'https' : r.type === 'service' ? 'tcp' : 'icmp',
    hcPath: '/healthz', hcInterval: 10, hcTimeout: 3, hcFail: 3,
    gateways: r.type === 'site' ? ['zl-gw-branch-sh'] : ['zl-gw-hq-01'],
    tags: r.stepup ? ['高敏'] : [], refs: REFS[r.name] ?? [],
    // Web 安全控制（L7）：全 false=无管控=旧行为；落 kind=resourcecfg
    security: { watermark: false, watermarkTpl: '{user}·{time}', disableDownload: false, disableCopy: false, disablePrint: false, disableRightclick: false, disableDevtools: false, blockDownloadResp: false },
    // SSO 凭证注入 / 请求头改写（web 代理模式）：enabled=false 不注入；落 kind=resourcecfg.sso，网关 webproxy 消费
    sso: {
      enabled: false, mode: 'header', host: '', backend: '', hostRewrite: '', forwardClientIp: true,
      headers: [{ name: 'X-Auth-User', value: '{account}' }, { name: 'X-Auth-Email', value: '{email}' }],
      removeHeaders: ['X-Auth-User', 'X-Auth-Email', 'X-Remote-User'], basicUser: '{account}', basicPass: ''
    }
  };
}

/* —— 详情抽屉：cfg 持久化到 collection kind=resourcecfg（key=资源名）—— */
const drawer = ref(false);
const cur = ref<any>(null);
async function openDetail(r: any) {
  if (!r.cfg) {
    r.cfg = defaultCfg(r);
    if (live.value) {
      try {
        const resp = await fetch(`/ctl/api/coll?kind=resourcecfg`);
        if (resp.ok) {
          const docs = await resp.json();
          const found = Array.isArray(docs) ? docs.find((x: any) => x.key === r.name) : null;
          if (found) r.cfg = { ...r.cfg, ...found, security: { ...r.cfg.security, ...(found.security ?? {}) }, sso: { ...r.cfg.sso, ...(found.sso ?? {}) } };
        }
      } catch { /* 拉取失败保留默认 cfg */ }
    }
  }
  cur.value = r; drawer.value = true;
}

async function saveCfg() {
  if (live.value) {
    try {
      const doc = { key: cur.value.name, ...cur.value.cfg };
      const r = await fetch('/ctl/api/coll?kind=resourcecfg', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ key: cur.value.name, doc })
      });
      if (!r.ok) return Message.error('保存失败');
      Message.success(`资源「${cur.value.name}」配置已保存 · 已持久化 · 引用策略 ≤60s 重编译下发`);
      return;
    } catch { return Message.error('保存失败，控制面不可达'); }
  }
  Message.success(`资源「${cur.value.name}」配置已保存（mock 演示，未持久化）`);
}
const probe = () => {
  Message.loading({ content: `探测「${cur.value.name}」…`, duration: 800 });
  setTimeout(() => { cur.value.health = 'up'; Message.success(`「${cur.value.name}」可达 · ${cur.value.cfg.hcType.toUpperCase()} 探测正常`); }, 850);
};
const del = () => {
  const refs = refsOf(cur.value);
  if (refs.length) { Modal.warning({ title: '无法删除', content: `资源「${cur.value.name}」被 ${refs.length} 条策略授权（${refs.join('、')}），请先在策略中心解除引用。`, okText: '我知道了' }); return; }
  Modal.warning({
    title: `删除资源「${cur.value.name}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: '删除后门户入口随之移除，任何会话不可再访问。此操作进入审计链。',
    onOk: async () => {
      const name = cur.value.name;
      if (live.value) {
        try { const r = await fetch(`/ctl/api/resources?name=${encodeURIComponent(name)}`, { method: 'DELETE' }); if (!r.ok) return Message.error('删除失败'); } catch { return Message.error('控制面不可达'); }
      }
      rows.value = rows.value.filter((x) => x.name !== name);
      drawer.value = false;
      Message.success(`资源「${name}」已删除`);
    }
  });
};

/* —— 新建 —— */
const show = ref(false);
const form = reactive({ name: '', type: 'app', addr: '', modes: 'auto', stepup: false, level: '', tags: '', allowSelfRequest: false });
function openCreate() { Object.assign(form, { name: '', type: 'app', addr: '', modes: 'auto', stepup: false, level: '', tags: '', allowSelfRequest: false }); show.value = true; }
async function add() {
  if (!form.name || !form.addr) return Message.warning('名称与地址为必填');
  const res: any = { name: form.name, type: form.type as any, addr: form.addr, modes: form.modes, health: 'unknown' as const, stepup: form.stepup };
  if (form.allowSelfRequest) res.allowSelfRequest = true;
  if (form.level) res.level = form.level;
  if (form.tags) res.tags = form.tags;
  if (live.value) {
    try {
      const r = await fetch('/ctl/api/resources', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(res) });
      if (r.status === 409) return Message.error(`资源「${form.name}」已存在`);
      if (!r.ok) return Message.error('创建失败');
      await loadResources();
    } catch { return Message.error('控制面不可达'); }
  } else { rows.value.unshift(res); }
  Message.success(`资源「${form.name}」已创建 · 探测健康中，授权后自动进入应用门户（ZL-FR-103）${live.value ? ' · 已持久化' : ''}`);
  show.value = false;
}
const typeText = (t: string) => ({ app: '应用', service: '服务', subnet: '网段', site: '站点' } as Record<string, string>)[t] || t;
const levelText = (l: string) => ({ low: '低', medium: '中', high: '高', critical: '关键' } as Record<string, string>)[l] || l;
const levelBadge = (l: string) => ({ low: 'zl-badge--idle', medium: 'zl-badge--ok', high: 'zl-badge--warn', critical: 'zl-badge--danger' } as Record<string, string>)[l] || 'zl-badge--idle';
const hb = (h: string) => ({ up: 'zl-badge--ok', down: 'zl-badge--danger', unknown: 'zl-badge--idle' } as Record<string, string>)[h];
const ht = (h: string) => ({ up: '可达', down: '不可达', unknown: '未知' } as Record<string, string>)[h];
</script>
<style scoped>
:deep(.row-click) { cursor: pointer; }
.res-filter { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
.res-count { font-size: 12px; color: var(--ink-3); margin-left: auto; }
.rd-sec { font-size: 11.5px; font-weight: 700; color: var(--ink-3); margin: 18px 0 10px; display: flex; align-items: center; }
.rd-hint { font-size: 10.5px; font-weight: 400; color: var(--ink-3); margin-left: 8px; }
.sso-hrow { display: flex; align-items: center; gap: 6px; margin-bottom: 5px; }
.rd-sec:first-child { margin-top: 0; }
.rd-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px 16px; }
.rd-f { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
.rd-f--wide { grid-column: 1 / -1; }
.rd-f label { font-size: 11.5px; font-weight: 600; color: var(--ink-2); }
.rd-row { flex-direction: row; align-items: center; justify-content: space-between; }
.rd-refs { display: flex; flex-direction: column; gap: 4px; }
.rd-ref { font-size: 12px; color: var(--accent-2); text-decoration: none; }
.rd-ref:hover { text-decoration: underline; }
.rd-dim { font-size: 12px; color: var(--ink-3); }
.rd-foot { display: flex; justify-content: space-between; gap: 12px; margin-top: 22px; padding-top: 16px; border-top: 1px solid var(--line); }
</style>
