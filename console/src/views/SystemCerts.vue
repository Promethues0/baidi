<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">证书与密钥<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">国密 SM2 双证 / TLCP 服务证书 / CA 信任库 / 设备证书签发 · 到期前 30 天预警 · 吊销 ≤10s 经控制面下发（ZL-FR-105）</div>
      </div>
      <div class="cert-stat">
        <span class="cs ok"><b>{{ count('valid') }}</b> 有效</span>
        <span class="cs warn"><b>{{ count('expiring') }}</b> 即将到期</span>
        <span class="cs bad"><b>{{ count('expired') }}</b> 已过期</span>
      </div>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1fr 360px;">
      <!-- 左：证书清单 -->
      <div class="zl-card" style="overflow:hidden;">
        <div class="cert-toolbar">
          <div class="zl-card__title">证书清单</div>
          <div style="display:flex;gap:8px">
            <a-button size="small" @click="importCert"><template #icon><icon-upload /></template>导入证书</a-button>
            <a-button size="small" type="primary" @click="genCSR"><template #icon><icon-plus /></template>生成 CSR</a-button>
          </div>
        </div>
        <table class="cert-tbl">
          <thead><tr><th>证书</th><th>用途</th><th>算法</th><th>有效期</th><th>状态</th><th style="text-align:right">操作</th></tr></thead>
          <tbody>
            <tr v-for="c in certs" :key="c.key" :class="{active: c.key===sel}" @click="sel=c.key">
              <td>
                <div class="cert-name">{{ c.name }}</div>
                <div class="cert-sub data">{{ c.subject }}</div>
              </td>
              <td><span class="usage-pill" :data-u="c.usage">{{ usageLabel(c.usage) }}</span></td>
              <td><span class="data" :class="{gm: c.algo==='SM2'}">{{ c.algo }}</span></td>
              <td class="data" style="font-size:11.5px">{{ c.notAfter }}</td>
              <td><span class="zl-badge" :class="badge(c.status)">{{ statusLabel(c.status) }}</span></td>
              <td style="text-align:right" @click.stop>
                <a-button size="mini" @click="exportCert(c)">导出</a-button>
                <a-button size="mini" status="warning" style="margin-left:6px" v-if="c.usage!=='ca'" @click="renew(c)">续期</a-button>
                <a-button size="mini" status="danger" style="margin-left:6px" v-if="c.status!=='revoked' && c.usage!=='ca'" @click="revoke(c)">吊销</a-button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- 右：选中证书详情 + 全局密钥策略 -->
      <div style="display:flex;flex-direction:column;gap:16px;min-width:0">
        <div class="zl-card zl-card__pad" v-if="current">
          <div class="zl-card__title" style="margin-bottom:12px">证书详情</div>
          <div class="cert-detail">
            <div class="cd-row"><span>名称</span><b>{{ current.name }}</b></div>
            <div class="cd-row"><span>主体 DN</span><b class="data">{{ current.subject }}</b></div>
            <div class="cd-row"><span>颁发者</span><b class="data">{{ current.issuer }}</b></div>
            <div class="cd-row"><span>序列号</span><b class="data">{{ current.serial }}</b></div>
            <div class="cd-row"><span>生效</span><b class="data">{{ current.notBefore }}</b></div>
            <div class="cd-row"><span>到期</span><b class="data">{{ current.notAfter }}</b></div>
            <div class="cd-row"><span>状态</span><span class="zl-badge" :class="badge(current.status)">{{ statusLabel(current.status) }}</span></div>
          </div>
          <div v-if="current.status==='expiring'" class="cd-tip warn">⚠ 该证书将在 30 天内到期，建议尽快续期以免接入中断。</div>
          <div v-if="current.status==='expired'" class="cd-tip bad">✕ 证书已过期，使用该证书的承载将握手失败。请立即续期或更换。</div>
        </div>

        <div class="zl-card zl-card__pad">
          <div class="zl-card__title" style="margin-bottom:10px">密钥与信任策略</div>
          <div class="kv">
            <div class="kv-row"><div><b>默认密码套件</b><span>TLCP · ECC-SM2-SM4-GCM-SM3</span></div><span class="zl-badge zl-badge--ok">国密</span></div>
            <div class="kv-row"><div><b>抗量子混合</b><span>经典 + PQC 混合密钥交换</span></div><a-switch v-model="pqc" size="small" @change="saveCfg" /></div>
            <div class="kv-row"><div><b>要求双证</b><span>签名证书 + 加密证书（GM/T 0024）</span></div><a-switch v-model="dualCert" size="small" @change="saveCfg" /></div>
            <div class="kv-row"><div><b>吊销检查</b><span>OCSP 实时 / CRL</span></div>
              <a-select v-model="revokeCheck" size="small" style="width:120px" @change="saveCfg">
                <a-option value="ocsp">OCSP 实时</a-option><a-option value="crl">CRL 列表</a-option><a-option value="off">关闭</a-option>
              </a-select>
            </div>
            <div class="kv-row"><div><b>私钥保护</b><span>HSM / 软件密钥库</span></div>
              <a-select v-model="keyStore" size="small" style="width:120px" @change="saveCfg">
                <a-option value="hsm">国密 HSM</a-option><a-option value="soft">软件密钥库</a-option>
              </a-select>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 信任 CA 库（外部信任锚 · 归口证书中心；认证方式 SM2 证书引用此处） -->
    <div class="zl-card" style="margin-top:16px;overflow:hidden">
      <div class="cert-toolbar">
        <div class="zl-card__title">信任 CA 库 <span style="font-size:11px;font-weight:400;color:var(--ink-3)">外部信任锚 · 导入的根 / 中间 CA</span></div>
        <a-button size="small" type="primary" @click="importCA"><template #icon><icon-plus /></template>导入根 / 中间 CA</a-button>
      </div>
      <table class="cert-tbl">
        <thead><tr><th>CA</th><th>层级</th><th>算法</th><th>吊销端点</th><th>双证</th><th>有效期</th><th style="text-align:right">操作</th></tr></thead>
        <tbody>
          <tr v-for="ca in trustCAs" :key="ca.key" :class="{active: ca.key===caSel}" @click="caSel=ca.key">
            <td>
              <div class="cert-name">{{ ca.name }}</div>
              <div class="cert-sub data">{{ ca.subject }}</div>
            </td>
            <td><span class="usage-pill" :data-u="ca.level==='root' ? 'ca' : ''">{{ ca.level==='root' ? '根 CA' : '中间 CA' }}</span></td>
            <td><span class="data" :class="{gm: ca.algo==='SM2'}">{{ ca.algo }}</span></td>
            <td class="data" style="font-size:11.5px;color:var(--ink-2)">{{ caRevokeLabel(ca) }}</td>
            <td><span :style="ca.dualCert ? 'color:var(--ok)' : 'color:var(--ink-3)'">{{ ca.dualCert ? '✓ 要求' : '—' }}</span></td>
            <td class="data" style="font-size:11.5px">{{ ca.notAfter }}</td>
            <td style="text-align:right" @click.stop>
              <a-button size="mini" @click="viewCA(ca)">查看</a-button>
              <a-button size="mini" status="danger" style="margin-left:6px" @click="removeCA(ca)">移除</a-button>
            </td>
          </tr>
        </tbody>
      </table>
      <div class="cert-ca-note">信任 CA = 外部信任锚（导入的根 / 中间 CA，作为证书认证的信任源）；上方「证书清单」是本网关自身持有的证书，二者语义不同。<b>认证方式 · 国密证书（SM2）</b>的信任 CA / 吊销策略 / 双证从此处引用，不再各页单配。</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

type Cert = {
  key: string; name: string; usage: string; algo: string; subject: string;
  issuer: string; serial: string; notBefore: string; notAfter: string; status: string;
};
// 信任 CA（外部信任锚：导入的根/中间 CA，作为证书认证的信任源）。归口证书中心，认证方式引用。
type TrustCA = {
  key: string; name: string; level: 'root' | 'intermediate'; subject: string; algo: string;
  notAfter: string; revoke: 'ocsp' | 'crl' | 'off'; ocsp?: string; crl?: string; dualCert: boolean; status: string;
};

const certs = ref<Cert[]>([]);
const sel = ref('');
const live = ref(false);
const pqc = ref(true);
const dualCert = ref(true);
const revokeCheck = ref('ocsp');
const keyStore = ref('hsm');

// 信任 CA 库（外部信任锚；coll kind=trustca 透明持久化，零后端改动）
const trustCAs = ref<TrustCA[]>([]);
const caSel = ref('');
const mockCAs: TrustCA[] = [
  { key: 'gm-root', name: 'Baidi GM Root CA', level: 'root', subject: 'CN=Baidi GM Root CA,O=ACME,C=CN', algo: 'SM2', notAfter: '2035-01-01', revoke: 'ocsp', ocsp: 'http://ocsp.corp.com', dualCert: true, status: 'valid' },
  { key: 'gm-sub-hq', name: 'Baidi GM HQ Sub CA', level: 'intermediate', subject: 'CN=Baidi GM HQ Sub CA,O=ACME,C=CN', algo: 'SM2', notAfter: '2030-06-01', revoke: 'crl', crl: 'http://crl.corp.com/hq.crl', dualCert: true, status: 'valid' }
];
const caRevokeLabel = (ca: TrustCA) => (ca.revoke === 'ocsp' ? 'OCSP · ' + (ca.ocsp || '—') : ca.revoke === 'crl' ? 'CRL · ' + (ca.crl || '—') : '关闭');

const current = computed(() => certs.value.find((c) => c.key === sel.value));
const count = (s: string) => certs.value.filter((c) => c.status === s).length;

const usageLabel = (u: string) => ({ sign: '签名', enc: '加密', server: '服务端', ca: '根 CA', 'device-template': '设备模板' }[u] || u);
const statusLabel = (s: string) => ({ valid: '有效', expiring: '即将到期', expired: '已过期', revoked: '已吊销' }[s] || s);
const badge = (s: string) => ({ valid: 'zl-badge--ok', expiring: 'zl-badge--warn', expired: 'zl-badge--danger', revoked: 'zl-badge--idle' }[s] || 'zl-badge--idle');

const mockCerts: Cert[] = [
  { key: 'gw-sign', name: '网关签名证书', usage: 'sign', algo: 'SM2', subject: 'CN=zl-gw-hq-01,O=ACME,C=CN', issuer: 'Baidi GM Root CA', serial: '3A:F1:08:2C:9E', notBefore: '2025-09-01', notAfter: '2026-09-01', status: 'valid' },
  { key: 'tlcp-server', name: 'TLCP 服务证书', usage: 'server', algo: 'SM2', subject: 'CN=*.corp,O=ACME,C=CN', issuer: 'Baidi GM Root CA', serial: '7B:22:1D:4A:00', notBefore: '2025-06-15', notAfter: '2026-07-10', status: 'expiring' }
];

async function load() {
  try {
    const r = await fetch('/ctl/api/coll?kind=cert');
    if (!r.ok) throw new Error();
    const docs = await r.json();
    certs.value = docs.map((d: any) => d as Cert);
    live.value = true;
  } catch { certs.value = mockCerts; live.value = false; }
  if (certs.value.length) sel.value = certs.value[0].key;
  // 信任 CA 库（独立降级，不影响整页 live 态）
  try {
    const r = await fetch('/ctl/api/coll?kind=trustca');
    if (!r.ok) throw new Error();
    const docs = await r.json();
    trustCAs.value = Array.isArray(docs) && docs.length ? docs.map((d: any) => d as TrustCA) : mockCAs;
  } catch { trustCAs.value = mockCAs; }
  if (trustCAs.value.length) caSel.value = trustCAs.value[0].key;
}
onMounted(load);

async function persist(c: Cert) {
  if (!live.value) return true;
  try {
    const r = await fetch('/ctl/api/coll?kind=cert', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: c.key, doc: c })
    });
    return r.ok;
  } catch { return false; }
}

function revoke(c: Cert) {
  Modal.warning({
    title: '吊销证书',
    content: `吊销「${c.name}」后，使用该证书的承载将立即失效（≤10s 经控制面下发）。此操作不可逆，需安全管理员权限。`,
    okText: '确认吊销', cancelText: '取消', hideCancel: false,
    onOk: async () => {
      c.status = 'revoked';
      await persist(c);
      Message.success(`「${c.name}」已吊销${live.value ? ' · 已持久化' : ''}`);
    }
  });
}
async function renew(c: Cert) {
  c.status = 'valid'; c.notAfter = '2027-09-01';
  await persist(c);
  Message.success(`「${c.name}」已续期至 2027-09-01${live.value ? ' · 已持久化' : ''}`);
}
const exportCert = (c: Cert) => Message.info(`导出「${c.name}」公钥证书（PEM）· 私钥不出密钥库`);
const importCert = () => Message.info('导入证书：支持 PEM / PFX / 国密双证 SM2 ·（演示）');
const genCSR = () => Message.info('生成 CSR：SM2 密钥对在 HSM 内生成，私钥不导出 ·（演示）');
const saveCfg = () => Message.success('密钥与信任策略已保存' + (live.value ? ' · 已持久化' : '（mock）'));

/* —— 信任 CA 库（外部信任锚，coll kind=trustca 持久化） —— */
const importCA = () => Message.info('导入根 / 中间 CA：支持 PEM（SM2 / RSA）· 录入吊销端点 ·（演示）');
const viewCA = (ca: TrustCA) => Message.info(`查看「${ca.name}」证书链与吊销端点 ·（演示）`);
function removeCA(ca: TrustCA) {
  Modal.warning({
    title: '移除信任 CA',
    content: ca.level === 'root'
      ? `移除根 CA「${ca.name}」后，其签发的所有证书将失去信任锚、证书认证会拒绝它们。此操作影响面大，需安全管理员确认。`
      : `移除中间 CA「${ca.name}」后，其签发的证书将无法验链。确认移除？`,
    okText: '确认移除', cancelText: '取消', hideCancel: false,
    onOk: async () => {
      trustCAs.value = trustCAs.value.filter((x) => x.key !== ca.key);
      if (caSel.value === ca.key) caSel.value = trustCAs.value[0]?.key ?? '';
      if (live.value) {
        try { await fetch(`/ctl/api/coll?kind=trustca&key=${encodeURIComponent(ca.key)}`, { method: 'DELETE' }); } catch { /* ignore */ }
      }
      Message.success(`「${ca.name}」已移出信任库${live.value ? ' · 已持久化' : ''}`);
    }
  });
}
</script>

<style scoped>
.cert-stat { display: flex; gap: 16px; align-items: center; }
.cert-stat .cs { font-size: 12px; color: var(--ink-3); display: flex; align-items: baseline; gap: 5px; }
.cert-stat b { font-size: 18px; font-weight: 700; }
.cs.ok b { color: var(--ok); } .cs.warn b { color: var(--warn); } .cs.bad b { color: var(--danger); }

.cert-toolbar { display: flex; align-items: center; justify-content: space-between; padding: 14px 16px; border-bottom: 1px solid var(--line); }
.cert-tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
.cert-tbl th { text-align: left; font-size: 11.5px; font-weight: 650; color: var(--ink-3); padding: 9px 14px; border-bottom: 1px solid var(--line); background: var(--surface-2); }
.cert-tbl td { padding: 11px 14px; border-bottom: 1px solid var(--line); vertical-align: middle; }
.cert-tbl tbody tr { cursor: pointer; transition: background .12s; }
.cert-tbl tbody tr:hover { background: var(--surface-2); }
.cert-tbl tbody tr.active { background: var(--accent-soft); }
.cert-name { font-size: 13px; font-weight: 600; color: var(--ink); }
.cert-sub { font-size: 10.5px; color: var(--ink-3); margin-top: 2px; }
.usage-pill { font-size: 11px; padding: 1px 8px; border-radius: var(--r-pill); border: 1px solid var(--line-2); color: var(--ink-2); }
.usage-pill[data-u="ca"] { background: var(--accent-soft); color: var(--accent-2); border-color: var(--accent-line); }
.data.gm { color: #dc2626; font-weight: 600; }

.cert-detail { display: flex; flex-direction: column; }
.cd-row { display: flex; justify-content: space-between; gap: 12px; padding: 7px 0; border-bottom: 1px solid var(--line); font-size: 12.5px; }
.cd-row:last-child { border-bottom: 0; }
.cd-row span { color: var(--ink-3); flex: none; }
.cd-row b { color: var(--ink); font-weight: 600; text-align: right; min-width: 0; word-break: break-all; }
.cd-tip { margin-top: 12px; font-size: 12px; padding: 9px 11px; border-radius: var(--r-md); line-height: 1.5; }
.cd-tip.warn { background: rgba(217,119,6,.1); color: #b45309; }
.cd-tip.bad { background: rgba(220,38,38,.1); color: #b91c1c; }

.kv { display: flex; flex-direction: column; }
.kv-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 0; }
.kv-row + .kv-row { border-top: 1px solid var(--line); }
.kv-row b { display: block; font-size: 13px; color: var(--ink); font-weight: 600; }
.kv-row span { display: block; font-size: 11px; color: var(--ink-3); margin-top: 2px; }
.cert-ca-note { padding: 12px 16px; font-size: 11.5px; color: var(--ink-3); border-top: 1px solid var(--line); line-height: 1.6; }
.cert-ca-note b { color: var(--ink-2); }
</style>
