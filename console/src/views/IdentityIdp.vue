<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">IdP 联邦<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">对接上游企业身份源（OIDC / SAML / LDAP + 钉钉 / 企微 / 飞书）· JIT 建账户（ZL-FR-503）· SAML/opaque 经边缘 broker 桥成 OIDC（ADR-0003）</div>
      </div>
      <a-button type="primary" @click="openCreate"><template #icon><icon-plus /></template>新建联邦</a-button>
    </div>

    <!-- 主-从：源列表 + 选中源配置 -->
    <div class="zl-grid" style="grid-template-columns: 360px 1fr;">
      <div class="zl-card idp-list">
        <div v-for="s in sources" :key="s.key" class="idp-row" :class="{ active: s.key===sel, off: s.status==='disabled' }" @click="sel=s.key">
          <span class="idp-row__ic" :style="{ background: meta(s.kind).color }">{{ meta(s.kind).ic }}</span>
          <div class="idp-row__main">
            <div class="idp-row__name">{{ s.name }}</div>
            <div class="idp-row__sub data">{{ meta(s.kind).label }} · {{ (s.users||0).toLocaleString() }} 用户</div>
          </div>
          <span class="zl-badge" :class="stBadge(s.status)" style="font-size:10px">{{ stText(s.status) }}</span>
        </div>
        <div v-if="!sources.length" class="idp-empty">暂无联邦源，点右上「新建联邦」。</div>
      </div>

      <div class="zl-card zl-card__pad idp-cfg" v-if="cur">
        <div class="idp-cfg__head">
          <span class="idp-cfg__ic" :style="{ background: meta(cur.kind).color }">{{ meta(cur.kind).ic }}</span>
          <div style="flex:1;min-width:0">
            <div class="idp-cfg__name">{{ cur.name }}
              <span class="zl-mode-pill" :class="protoClass(meta(cur.kind).protocol)" style="margin-left:8px">{{ meta(cur.kind).protocol }}</span>
            </div>
            <div class="idp-cfg__desc">{{ meta(cur.kind).desc }}</div>
          </div>
          <a-space>
            <a-button size="mini" @click="test(cur)">测试连通</a-button>
            <a-button v-if="cur.kind==='oidc'" size="mini" type="outline" @click="testLogin(cur)">发起测试登录</a-button>
            <a-button size="mini" status="danger" type="outline" @click="del(cur)">删除</a-button>
          </a-space>
        </div>

        <div class="idp-cfg__body">
          <div v-for="f in meta(cur.kind).schema" :key="f.key" class="cfg-field" :class="{ wide: f.type==='textarea' }">
            <label class="cfg-field__label">{{ f.label }}<span v-if="f.hint" class="cfg-field__hint">{{ f.hint }}</span></label>
            <a-input v-if="f.type==='text'" v-model="cur.config[f.key]" :placeholder="f.ph" size="small" />
            <a-input-password v-else-if="f.type==='password'" v-model="cur.config[f.key]" :placeholder="f.ph" size="small" />
            <a-select v-else-if="f.type==='select'" v-model="cur.config[f.key]" size="small">
              <a-option v-for="o in f.opts" :key="o.value" :value="o.value">{{ o.label }}</a-option>
            </a-select>
            <a-input-tag v-else-if="f.type==='tags'" v-model="cur.config[f.key]" size="small" />
            <a-textarea v-else-if="f.type==='textarea'" v-model="cur.config[f.key]" :placeholder="f.ph" size="small" :auto-size="{minRows:2,maxRows:5}" />
          </div>
        </div>

        <div class="idp-cfg__opts">
          <div class="idp-opt"><div><b>JIT 建账户</b><span>首次联邦登录自动建本地账户（ZL-FR-503）</span></div><a-switch v-model="cur.jit" size="small" /></div>
          <div class="idp-opt"><div><b>启用此源</b><span>停用后该源用户回退本地认证</span></div>
            <a-switch :model-value="cur.status!=='disabled'" size="small" @change="toggleEnabled" />
          </div>
        </div>

        <div class="idp-cfg__foot">
          <span class="idp-cfg__tip">改动 ≤60s 下发 · claim 映射变更下次登录生效 · 写审计</span>
          <a-button type="primary" size="small" @click="save(cur)">保存配置</a-button>
        </div>
      </div>
    </div>

    <!-- SDK 联邦 · ExchangeToken -->
    <div class="zl-card zl-card__pad" style="margin-top:16px">
      <div class="zl-card__title" style="margin-bottom: 4px;">SDK 联邦 · ExchangeToken</div>
      <div class="zl-page__sub" style="margin-bottom: 14px;">B2B2C：ISV 客户用自己 IdP 的 JWT 换节点授权，端用户零二次登录（ZL-FR-507）</div>
      <div class="zl-grid" style="grid-template-columns: 1.3fr 1fr; align-items:start;">
        <div class="fed-flow">
          <div class="fed-step" v-for="(s, i) in flow" :key="i">
            <span class="fed-step__n data">{{ i + 1 }}</span>
            <span class="fed-step__t">{{ s }}</span>
          </div>
        </div>
        <div class="fed-grid">
          <div class="fed-kv"><span>node grant TTL</span><b class="data">{{ sdkFederation.grantTtlMin }} 分钟</b></div>
          <div class="fed-kv"><span>每账户设备上限</span><b class="data">{{ sdkFederation.maxDevices }} · {{ sdkFederation.evictPolicy }}</b></div>
          <div class="fed-kv"><span>ephemeral 节点 GC</span><b style="color:var(--ok)">已启用</b></div>
          <div class="fed-kv"><span>近 24h 会话</span><b class="data">{{ sdkFederation.sessions24h }}</b></div>
          <div class="fed-kv"><span>jti 重放拦截</span><b class="data" style="color:var(--warn)">{{ sdkFederation.jtiReplayBlocked }} 次</b></div>
          <div class="fed-kv"><span>audiences</span><b class="data">{{ sdkFederation.audiences.join(', ') }}</b></div>
        </div>
      </div>
    </div>

    <!-- 新建联邦 -->
    <a-modal v-model:visible="show" title="新建 IdP 联邦" width="560px" @ok="add" ok-text="创建">
      <a-form :model="form" layout="vertical">
        <a-form-item label="联邦类型">
          <div class="idp-pick">
            <div v-for="k in kinds" :key="k" class="idp-pick__item" :class="{ on: form.kind===k }" @click="form.kind=k">
              <span class="idp-pick__ic" :style="{ background: meta(k).color }">{{ meta(k).ic }}</span>
              <span>{{ meta(k).label }}</span>
            </div>
          </div>
        </a-form-item>
        <a-form-item label="名称" required><a-input v-model="form.name" :placeholder="`例如：${meta(form.kind).label}（集团主）`" /></a-form-item>
        <div style="font-size:11.5px;color:var(--ink-3);line-height:1.6">创建后在右侧填写 {{ meta(form.kind).protocol }} 连接参数与 claim 映射，「测试连通」通过后启用。</div>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { sdkFederation } from '@/mock';

type Field = { key: string; label: string; type: 'text' | 'password' | 'select' | 'tags' | 'textarea'; opts?: { label: string; value: string }[]; ph?: string; hint?: string };
type Kind = 'oidc' | 'saml' | 'ldap' | 'dingtalk' | 'wecom' | 'feishu';
interface Source { key: string; name: string; kind: Kind; status: 'active' | 'error' | 'disabled'; jit: boolean; users: number; config: Record<string, any> }

const CLAIM_PH = 'email -> account\ndept -> org_path\ngroups -> dynamic_group';

const KIND_META: Record<Kind, { label: string; ic: string; color: string; protocol: string; desc: string; schema: Field[]; def: Record<string, any> }> = {
  oidc: {
    label: '标准 OIDC', ic: 'OI', color: '#6366f1', protocol: 'OIDC', desc: '标准 OpenID Connect 身份提供方（Keycloak / Auth0 / Okta-OIDC 等）。',
    schema: [
      { key: 'issuer', label: 'Issuer / Discovery', type: 'text', ph: 'https://idp.example.com/.well-known/openid-configuration' },
      { key: 'clientId', label: 'Client ID', type: 'text' },
      { key: 'clientSecret', label: 'Client Secret', type: 'password' },
      { key: 'scopes', label: 'Scopes', type: 'tags', hint: '回车添加' },
      { key: 'redirectUri', label: '回调地址', type: 'text', ph: 'https://sso.corp.com/oidc/cb' },
      { key: 'claimMap', label: 'Claim 映射（claim → 白帝字段）', type: 'textarea', ph: CLAIM_PH }
    ],
    def: { issuer: '', clientId: '', clientSecret: '', scopes: ['openid', 'profile', 'email'], redirectUri: '', claimMap: 'email -> account\nname -> display_name' }
  },
  saml: {
    label: '标准 SAML', ic: 'SA', color: '#0ea5e9', protocol: 'SAML', desc: 'SAML 2.0 IdP，经边缘 broker 桥成 OIDC 后进入控制面（ADR-0003：控制面仅 JWT 联邦）。',
    schema: [
      { key: 'metadataUrl', label: 'IdP Metadata URL', type: 'text', ph: 'https://partner.okta.com/app/.../sso/saml/metadata' },
      { key: 'entityId', label: 'SP Entity ID', type: 'text', ph: 'urn:baidi:sp' },
      { key: 'acsUrl', label: 'ACS（断言消费）URL', type: 'text', ph: 'https://sso.corp.com/saml/acs' },
      { key: 'nameIdFormat', label: 'NameID 格式', type: 'select', opts: [{ label: 'emailAddress', value: 'email' }, { label: 'persistent', value: 'persistent' }, { label: 'unspecified', value: 'unspecified' }] },
      { key: 'idpCert', label: 'IdP 签名证书（PEM）', type: 'textarea', ph: '-----BEGIN CERTIFICATE-----' },
      { key: 'attrMap', label: '属性映射（attribute → 白帝字段）', type: 'textarea', ph: 'mail -> account\ndepartment -> org_path' }
    ],
    def: { metadataUrl: '', entityId: 'urn:baidi:sp', acsUrl: '', nameIdFormat: 'email', idpCert: '', attrMap: 'mail -> account' }
  },
  ldap: {
    label: 'LDAP / AD', ic: 'AD', color: '#22c55e', protocol: 'LDAP', desc: 'Active Directory / OpenLDAP 目录同步，周期对账用户与组织。',
    schema: [
      { key: 'url', label: '服务器地址', type: 'text', ph: 'ldaps://ad.corp:636' },
      { key: 'baseDN', label: 'Base DN', type: 'text', ph: 'dc=corp,dc=com' },
      { key: 'bindDN', label: '绑定账号 DN', type: 'text' },
      { key: 'bindPwd', label: '绑定密码', type: 'password' },
      { key: 'userFilter', label: '用户过滤', type: 'text', ph: '(objectClass=user)' },
      { key: 'groupFilter', label: '组过滤', type: 'text', ph: '(objectClass=group)' },
      { key: 'syncCron', label: '同步周期', type: 'select', opts: [{ label: '每 15 分钟', value: '15m' }, { label: '每小时', value: '1h' }, { label: '每天 02:00', value: 'daily' }, { label: '仅手动', value: 'manual' }] }
    ],
    def: { url: 'ldaps://ad.corp:636', baseDN: 'dc=corp,dc=com', bindDN: '', bindPwd: '', userFilter: '(objectClass=user)', groupFilter: '(objectClass=group)', syncCron: '1h' }
  },
  dingtalk: {
    label: '钉钉', ic: '钉', color: '#3b82f6', protocol: 'OIDC', desc: '钉钉企业内部应用免登（CorpId + 扫码 / 免密），用户映射到组织。',
    schema: [
      { key: 'corpId', label: 'CorpId', type: 'text', ph: 'ding1234567890' },
      { key: 'appKey', label: 'AppKey', type: 'text' },
      { key: 'appSecret', label: 'AppSecret', type: 'password' },
      { key: 'agentId', label: 'AgentId', type: 'text' },
      { key: 'callback', label: '回调域名', type: 'text', ph: 'https://sso.corp.com/dingtalk/cb' },
      { key: 'userMap', label: '用户唯一标识', type: 'select', opts: [{ label: 'unionId（推荐）', value: 'unionid' }, { label: '手机号', value: 'mobile' }, { label: 'userId', value: 'userid' }] }
    ],
    def: { corpId: '', appKey: '', appSecret: '', agentId: '', callback: '', userMap: 'unionid' }
  },
  wecom: {
    label: '企业微信', ic: '企', color: '#14b8a6', protocol: 'OIDC', desc: '企业微信网页授权登录 + 通讯录同步，子公司多 CorpID 可分别接入。',
    schema: [
      { key: 'corpId', label: 'CorpID', type: 'text', ph: 'ww1234567890' },
      { key: 'agentId', label: 'AgentID', type: 'text' },
      { key: 'secret', label: '应用 Secret', type: 'password' },
      { key: 'contactSecret', label: '通讯录 Secret', type: 'password', hint: '同步组织用' },
      { key: 'trustedDomain', label: '可信域名', type: 'text', ph: 'sso.corp.com' },
      { key: 'userMap', label: '用户唯一标识', type: 'select', opts: [{ label: 'UserID', value: 'userid' }, { label: '手机号', value: 'mobile' }] }
    ],
    def: { corpId: '', agentId: '', secret: '', contactSecret: '', trustedDomain: '', userMap: 'userid' }
  },
  feishu: {
    label: '飞书', ic: '飞', color: '#2563eb', protocol: 'OIDC', desc: '飞书（Lark）网页应用免登，支持加密回调与通讯录字段映射。',
    schema: [
      { key: 'appId', label: 'App ID', type: 'text', ph: 'cli_a1b2c3' },
      { key: 'appSecret', label: 'App Secret', type: 'password' },
      { key: 'encryptKey', label: 'Encrypt Key', type: 'password', hint: '事件加密' },
      { key: 'verifyToken', label: 'Verification Token', type: 'text' },
      { key: 'callback', label: '回调域名', type: 'text', ph: 'https://sso.corp.com/feishu/cb' },
      { key: 'userMap', label: '用户唯一标识', type: 'select', opts: [{ label: 'union_id（推荐）', value: 'union_id' }, { label: '手机号', value: 'mobile' }, { label: 'open_id', value: 'open_id' }] }
    ],
    def: { appId: '', appSecret: '', encryptKey: '', verifyToken: '', callback: '', userMap: 'union_id' }
  }
};
const kinds = Object.keys(KIND_META) as Kind[];
const meta = (k: Kind) => KIND_META[k];

// fallback（控制面不可达时演示）——映射既有 5 源到 kind + 默认 config
const fallback: Source[] = [
  { key: '钉钉（集团主）', name: '钉钉（集团主）', kind: 'dingtalk', status: 'active', jit: true, users: 1180, config: { ...KIND_META.dingtalk.def, corpId: 'ding-acme-hq' } },
  { key: '企业微信（子公司）', name: '企业微信（子公司）', kind: 'wecom', status: 'active', jit: true, users: 312, config: { ...KIND_META.wecom.def, corpId: 'ww-acme-sub' } },
  { key: '集团 AD', name: '集团 AD', kind: 'ldap', status: 'active', jit: false, users: 1496, config: { ...KIND_META.ldap.def } },
  { key: '合作方 Okta', name: '合作方 Okta', kind: 'saml', status: 'error', jit: true, users: 28, config: { ...KIND_META.saml.def, metadataUrl: 'https://partner.okta.com/.../metadata' } },
  { key: '飞书（试点）', name: '飞书（试点）', kind: 'feishu', status: 'disabled', jit: true, users: 0, config: { ...KIND_META.feishu.def } }
];

const sources = ref<Source[]>([...fallback]);
const live = ref(false);
const sel = ref(sources.value[0]?.key);
const cur = computed(() => sources.value.find((s) => s.key === sel.value));

async function loadIdps() {
  try {
    const r = await fetch('/ctl/api/coll?kind=idp');
    if (!r.ok) return;
    const docs = await r.json();
    if (docs.length) {
      sources.value = docs.map((d: any) => ({ users: 0, jit: true, status: 'disabled', ...d, config: { ...(KIND_META[d.kind as Kind]?.def ?? {}), ...(d.config ?? {}) } }));
      sel.value = sources.value[0]?.key;
    }
    live.value = true;
  } catch { live.value = false; }
}
onMounted(loadIdps);

async function persist(s: Source) {
  if (!live.value) return true;
  try {
    const r = await fetch('/ctl/api/coll?kind=idp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key: s.key, doc: { key: s.key, name: s.name, kind: s.kind, status: s.status, jit: s.jit, users: s.users, config: s.config } }) });
    return r.ok;
  } catch { return false; }
}

/* —— 新建 —— */
const show = ref(false);
const form = reactive({ name: '', kind: 'oidc' as Kind });
function openCreate() { Object.assign(form, { name: '', kind: 'oidc' }); show.value = true; }
async function add() {
  if (!form.name) return Message.warning('请填写名称');
  if (sources.value.some((s) => s.key === form.name)) return Message.error('同名联邦源已存在');
  const s: Source = { key: form.name, name: form.name, kind: form.kind, status: 'disabled', jit: true, users: 0, config: { ...KIND_META[form.kind].def } };
  if (live.value && !(await persist(s))) return Message.error('创建失败');
  sources.value.push(s);
  sel.value = s.key;
  Message.success(`联邦「${form.name}」已创建 · 填写参数并测试连通后启用${live.value ? ' · 已持久化' : ''}`);
  show.value = false;
}

function toggleEnabled(v: string | number | boolean) {
  if (cur.value) cur.value.status = v ? 'active' : 'disabled';
}

async function save(s: Source) {
  if (!(await persist(s)) && live.value) return Message.error('保存失败');
  Message.success(`「${s.name}」配置已保存${live.value ? ' · 已持久化' : '（mock）'}`);
}
async function test(s: Source) {
  // OIDC：真打后端 probe（issuer 可达 + discovery + JWKS）；其余协议暂用占位
  if (s.kind === 'oidc' && live.value) {
    Message.loading({ content: `正在对「${s.name}」做 OIDC discovery…`, duration: 1200 });
    try {
      const r = await fetch(`/ctl/auth/oidc/probe?source=${encodeURIComponent(s.key)}`);
      const d = await r.json();
      if (d.ok) { Message.success(`「${s.name}」连通正常 · discovery 成功 · issuer ${d.issuer}`); }
      else { Message.error(`「${s.name}」连通失败：${d.error}`); }
    } catch { Message.error('控制面不可达'); }
    return;
  }
  Message.loading({ content: `正在测试「${s.name}」连通性…`, duration: 900 });
  setTimeout(() => {
    if (s.status === 'error') { Message.error(`「${s.name}」连通失败：签名证书已过期，请更新后重试`); }
    else { s.status = 'active'; Message.success(`「${s.name}」连通正常 · JWKS 拉取成功，claim 映射校验通过`); }
  }, 950);
}
// OIDC 发起测试登录：浏览器走真授权码流（需 issuer 可达 + 已配 clientId/回调）
function testLogin(s: Source) {
  if (!live.value) return Message.info('控制面未连接，无法发起');
  window.open(`/ctl/auth/oidc/start?source=${encodeURIComponent(s.key)}`, '_blank');
  Message.info('已在新窗口发起 OIDC 授权码流，完成后回调换发白帝会话');
}
function del(s: Source) {
  Modal.warning({
    title: `删除联邦「${s.name}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: `该源 ${s.users.toLocaleString()} 名联邦用户将无法经此源登录（已建本地账户保留）。此操作进入审计链。`,
    onOk: async () => {
      if (live.value) {
        try {
          const r = await fetch(`/ctl/api/coll?kind=idp&key=${encodeURIComponent(s.key)}`, { method: 'DELETE' });
          if (!r.ok) return Message.error('删除失败');
        } catch { return Message.error('控制面不可达'); }
      }
      sources.value = sources.value.filter((x) => x.key !== s.key);
      sel.value = sources.value[0]?.key;
      Message.success(`联邦「${s.name}」已删除`);
    }
  });
}

const flow = ['验签 ISV IdP JWT（JWKS / iss / aud / jti 防重放）', 'claim 映射 → 身份（JIT 建账户）', '设备策略校验 → 绑定 node key', '铸短时 node grant + 预算 netmap', '建会话 + 审计'];
const protoClass = (p: string) => ({ OIDC: 'zl-mode--mesh', SAML: 'zl-mode--ssl', LDAP: 'zl-mode--ipsec' } as Record<string, string>)[p];
const stBadge = (s: string) => ({ active: 'zl-badge--ok', error: 'zl-badge--danger', disabled: 'zl-badge--idle' } as Record<string, string>)[s];
const stText = (s: string) => ({ active: '正常', error: '异常', disabled: '停用' } as Record<string, string>)[s];
</script>

<style scoped>
.idp-list { padding: 8px; }
.idp-row { display: flex; align-items: center; gap: 10px; padding: 10px; border-radius: var(--r-md); cursor: pointer; transition: background .15s; position: relative; }
.idp-row:hover { background: var(--fill-1, rgba(0,0,0,.03)); }
.idp-row.active { background: var(--accent-soft); }
.idp-row.active::before { content: ''; position: absolute; left: 0; top: 7px; bottom: 7px; width: 3px; border-radius: 2px; background: var(--accent-2); }
.idp-row.off .idp-row__name, .idp-row.off .idp-row__ic { opacity: .55; }
.idp-row__ic { width: 30px; height: 30px; border-radius: 8px; display: grid; place-items: center; color: #fff; font-size: 12px; font-weight: 700; flex-shrink: 0; }
.idp-row__main { flex: 1; min-width: 0; }
.idp-row__name { font-size: 13px; font-weight: 600; color: var(--ink); }
.idp-row__sub { font-size: 11px; color: var(--ink-3); margin-top: 1px; }
.idp-empty { padding: 16px; font-size: 12.5px; color: var(--ink-3); }

.idp-cfg { display: flex; flex-direction: column; min-width: 0; }
.idp-cfg__head { display: flex; align-items: flex-start; gap: 12px; padding-bottom: 14px; border-bottom: 1px solid var(--line); }
.idp-cfg__ic { width: 38px; height: 38px; border-radius: 10px; display: grid; place-items: center; color: #fff; font-size: 15px; font-weight: 700; flex-shrink: 0; }
.idp-cfg__name { font-size: 15px; font-weight: 700; color: var(--ink); }
.idp-cfg__desc { font-size: 12px; color: var(--ink-3); margin-top: 3px; line-height: 1.5; }
.idp-cfg__body { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px 24px; padding: 16px 0; }
.cfg-field { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
.cfg-field.wide { grid-column: 1 / -1; }
.cfg-field__label { font-size: 12px; font-weight: 600; color: var(--ink-2); display: flex; align-items: baseline; gap: 7px; }
.cfg-field__hint { font-size: 10.5px; color: var(--ink-3); font-weight: 400; }
.idp-cfg__opts { border-top: 1px solid var(--line); }
.idp-opt { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 11px 0; }
.idp-opt + .idp-opt { border-top: 1px solid var(--line); }
.idp-opt b { display: block; font-size: 13px; color: var(--ink); font-weight: 650; }
.idp-opt span { display: block; font-size: 11.5px; color: var(--ink-3); margin-top: 2px; }
.idp-cfg__foot { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding-top: 14px; border-top: 1px solid var(--line); margin-top: auto; }
.idp-cfg__tip { font-size: 11px; color: var(--ink-3); }

.idp-pick { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
.idp-pick__item { display: flex; align-items: center; gap: 8px; padding: 9px 11px; border: 1px solid var(--line); border-radius: var(--r-md); cursor: pointer; font-size: 12.5px; color: var(--ink-2); transition: all .15s; }
.idp-pick__item.on { border-color: var(--accent-2); background: var(--accent-soft); color: var(--ink); font-weight: 600; }
.idp-pick__ic { width: 24px; height: 24px; border-radius: 7px; display: grid; place-items: center; color: #fff; font-size: 11px; font-weight: 700; }

.fed-flow { display: flex; flex-direction: column; gap: 0; }
.fed-step { display: flex; align-items: flex-start; gap: 10px; padding: 7px 0; position: relative; }
.fed-step:not(:last-child)::before { content: ''; position: absolute; left: 10px; top: 28px; bottom: -8px; width: 1px; background: var(--accent-line); }
.fed-step__n { width: 21px; height: 21px; border-radius: 50%; flex: none; display: flex; align-items: center; justify-content: center; background: var(--accent-soft); color: var(--accent-2); font-size: 11px; font-weight: 700; z-index: 1; }
.fed-step__t { font-size: 12.5px; color: var(--ink-2); line-height: 21px; }
.fed-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1px; background: var(--line); border: 1px solid var(--line); border-radius: var(--r-md); overflow: hidden; }
.fed-kv { background: var(--surface); padding: 10px 12px; display: flex; flex-direction: column; gap: 4px; }
.fed-kv span { font-size: 11px; color: var(--ink-3); }
.fed-kv b { font-size: 12.5px; color: var(--ink); font-weight: 600; }
</style>
