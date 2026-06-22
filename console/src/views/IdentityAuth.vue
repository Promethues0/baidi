<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">认证方式与 MFA<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">主认证 → MFA 判定 → 令牌签发（ZL-FR-501..506）· 每种方式可独立配置 · MFA 范围与触发归〈认证策略〉· 管理员强制 MFA 为内置安全门禁（REQ-SEC-007）</div>
      </div>
      <div class="auth-stat">
        <span><b>{{ enabledCount('primary') }}</b>/{{ catCount('primary') }} 主认证</span>
        <span><b>{{ enabledCount('mfa') }}</b>/{{ catCount('mfa') }} 二次认证</span>
      </div>
    </div>

    <!-- 主-从：方式列表 + 选中方式配置 -->
    <div class="zl-grid" style="grid-template-columns: 360px 1fr;">
      <!-- 左：方式列表（分主认证 / 二次认证） -->
      <div class="zl-card auth-list">
        <div v-for="cat in cats" :key="cat.key" class="auth-cat">
          <div class="auth-cat__title">{{ cat.title }}<span class="auth-cat__hint">{{ cat.hint }}</span></div>
          <div
            v-for="m in methodsOf(cat.key)" :key="m.k"
            class="auth-row" :class="{ active: m.k === sel, off: !m.on }"
            @click="sel = m.k">
            <span class="auth-row__ic" :style="{ background: m.color }">{{ m.ic }}</span>
            <div class="auth-row__main">
              <div class="auth-row__name">{{ m.name }}</div>
              <div class="auth-row__desc">{{ m.tag }}</div>
            </div>
            <a-switch v-model="m.on" size="small" :disabled="m.locked" @click.stop @change="toggle(m)" />
          </div>
        </div>
      </div>

      <!-- 右：选中方式的配置详情 -->
      <div class="zl-card zl-card__pad auth-cfg" v-if="current">
        <div class="auth-cfg__head">
          <span class="auth-cfg__ic" :style="{ background: current.color }">{{ current.ic }}</span>
          <div style="flex:1;min-width:0">
            <div class="auth-cfg__name">{{ current.name }}
              <span class="zl-badge" :class="current.on ? 'zl-badge--ok' : 'zl-badge--idle'" style="font-size:10.5px;margin-left:8px">{{ current.on ? '已启用' : '已停用' }}</span>
              <span v-if="current.locked" class="zl-badge zl-badge--warn" style="font-size:10.5px;margin-left:6px">🔒 安全门禁锁定</span>
            </div>
            <div class="auth-cfg__desc">{{ current.desc }}</div>
          </div>
          <a-switch v-model="current.on" :disabled="current.locked" @change="toggle(current)" />
        </div>

        <div class="auth-cfg__body" :class="{ 'auth-cfg__body--plain': current.k === 'pwd' }">
          <!-- 账号密码：口令规则归口令策略 / 失败锁定归账号安全，本页不重复配置 -->
          <div v-if="current.k === 'pwd'" class="pwd-redirect">
            <p class="pwd-redirect__lead">账号密码登录已纳入「认证方式」开关管理。具体规则在专门的策略页统一配置，避免多处重复、口径打架：</p>
            <div class="pwd-redirect__links">
              <router-link to="/identity/pwd-policy" class="pwd-link">
                <span class="pwd-link__t">口令策略 →</span>
                <span class="pwd-link__d">复杂度 / 有效期 / 历史 / 首登改密 / 弱口令黑名单</span>
              </router-link>
              <router-link to="/identity/sec-policy" class="pwd-link">
                <span class="pwd-link__t">账号安全 →</span>
                <span class="pwd-link__d">失败锁定 / 防爆破 / 图形验证码 / 会话与并发</span>
              </router-link>
            </div>
            <p class="pwd-redirect__hint">本页仅控制「是否启用账号密码登录」，不再单独设置口令长度/复杂度/锁定阈值。</p>
          </div>
          <template v-else>
            <div v-for="f in current.schema" :key="f.key" class="cfg-field">
              <label class="cfg-field__label">{{ f.label }}
                <span v-if="f.hint" class="cfg-field__hint">{{ f.hint }}</span>
              </label>
              <div class="cfg-field__ctl">
                <a-input v-if="f.type==='text'" v-model="current.config[f.key]" :placeholder="f.ph" size="small" />
                <a-input-password v-else-if="f.type==='password'" v-model="current.config[f.key]" :placeholder="f.ph" size="small" />
                <a-input-number v-else-if="f.type==='number'" v-model="current.config[f.key]" size="small" :style="{width:'160px'}">
                  <template v-if="f.unit" #suffix>{{ f.unit }}</template>
                </a-input-number>
                <a-select v-else-if="f.type==='select'" v-model="current.config[f.key]" size="small" :style="{maxWidth:'260px'}">
                  <a-option v-for="o in f.opts" :key="o.value" :value="o.value">{{ o.label }}</a-option>
                </a-select>
                <a-switch v-else-if="f.type==='switch'" v-model="current.config[f.key]" size="small" />
                <a-input-tag v-else-if="f.type==='tags'" v-model="current.config[f.key]" size="small" :style="{maxWidth:'340px'}" />
                <a-textarea v-else-if="f.type==='textarea'" v-model="current.config[f.key]" :placeholder="f.ph" size="small" :auto-size="{minRows:2,maxRows:4}" />
                <template v-else-if="f.type==='caref'">
                  <a-select v-model="current.config[f.key]" multiple size="small" :style="{maxWidth:'340px'}" placeholder="从证书中心信任 CA 选择">
                    <a-option v-for="ca in caOpts" :key="ca.key" :value="ca.key">{{ ca.name }}<span style="color:var(--ink-3);margin-left:6px;font-size:10.5px">{{ ca.level==='root'?'根':'中间' }}</span></a-option>
                  </a-select>
                  <div class="caref-inherit">{{ caInheritText }}<router-link to="/system/certs" class="caref-link">管理信任 CA →</router-link></div>
                </template>
              </div>
            </div>
            <div v-if="!current.schema.length" class="cfg-empty">该方式无需额外配置。</div>
          </template>
        </div>

        <div class="auth-cfg__foot">
          <span class="auth-cfg__tip">改动 ≤60s 下发在线端点 · 写审计</span>
          <a-button type="primary" size="small" @click="saveCfg(current)">保存配置</a-button>
        </div>
      </div>
    </div>

    <!-- 全局策略：令牌签发（本页职责）+ MFA 归口跳板 -->
    <div class="zl-grid" style="grid-template-columns: 1fr; margin-top:16px;">
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title" style="margin-bottom:12px">令牌签发（ZL-FR-504/505）</div>
        <div class="auth-rows">
          <div class="auth-prow"><div><b>默认签名</b><span>EdDSA (Ed25519) · DP-14</span></div><span class="zl-badge zl-badge--ok">启用</span></div>
          <div class="auth-prow"><div><b>国密双轨</b><span>SM2 签名套件 · 信创随策略下发</span></div><a-switch v-model="sm2" size="small" /></div>
          <div class="auth-prow"><div><b>JWKS 轮换</b><span>kid 轮换 · 旧 key 宽限 7 天</span></div><span class="data" style="font-size:12px;color:var(--ink-3)">上次 2026-06-03</span></div>
        </div>
      </div>

      <!-- MFA 强制范围/二次因子/自适应触发归口认证策略，本页仅留跳板 + 门禁只读 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title" style="margin-bottom:12px">MFA 与二次认证（DP-05 / DP-14）</div>
        <p class="pwd-redirect__lead" style="margin:0 0 12px">MFA 强制范围 / 二次因子方式 / 自适应触发已归口〈认证策略〉按范围下发，本页不再重复全局配置：</p>
        <router-link to="/identity/auth-policy" class="pwd-link">
          <span class="pwd-link__t">认证策略 →</span>
          <span class="pwd-link__d">强制范围 / 二次因子方式 / 自适应触发 / 记住设备</span>
        </router-link>
        <div class="auth-prow" style="margin-top:14px">
          <div><b>管理员强制 MFA</b><span>REQ-SEC-007 安全门禁 · 内置不可删策略</span></div>
          <span class="zl-badge zl-badge--warn">已强制</span>
        </div>
        <div style="margin-top:8px"><router-link to="/identity/auth-policy" style="font-size:12px;color:var(--accent-2);text-decoration:none">查看门禁策略 →</router-link></div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { Message } from '@arco-design/web-vue';

type Field = {
  key: string; label: string;
  type: 'text' | 'password' | 'number' | 'select' | 'switch' | 'tags' | 'textarea' | 'caref';
  opts?: { label: string; value: string }[]; ph?: string; hint?: string; unit?: string;
};
type Method = {
  k: string; name: string; cat: 'primary' | 'mfa'; ic: string; color: string;
  tag: string; desc: string; on: boolean; locked?: boolean;
  schema: Field[]; config: Record<string, any>;
};

const cats = [
  { key: 'primary', title: '主认证方式', hint: '登录第一因子' },
  { key: 'mfa', title: '二次认证（MFA）', hint: '高敏 / 首登 step-up' }
];

// 认证方式目录（前端定义全集 + 配置 schema + 默认值；后端 doc 覆盖开关与配置）。
const catalog: Method[] = [
  { k: 'pwd', name: '账号密码', cat: 'primary', ic: '密', color: '#6366f1', tag: 'argon2 · 规则见口令策略',
    desc: '本地账号库口令认证，argon2id 哈希存储。口令复杂度/有效期与失败锁定由专门策略页统一管理，本页仅控制是否启用此方式。', on: true,
    schema: [], config: {} },

  { k: 'ldap', name: '域账号（LDAP/AD）', cat: 'primary', ic: 'AD', color: '#0ea5e9', tag: '企业目录对接',
    desc: '对接 Active Directory / OpenLDAP，用域账号直接登录，可同步组织与用户组。', on: false,
    schema: [
      { key: 'url', label: '服务器地址', type: 'text', ph: 'ldaps://dc.corp.com:636' },
      { key: 'baseDN', label: 'Base DN', type: 'text', ph: 'dc=corp,dc=com' },
      { key: 'bindDN', label: '绑定账号 DN', type: 'text', ph: 'cn=svc-baidi,ou=svc,dc=corp,dc=com' },
      { key: 'bindPwd', label: '绑定密码', type: 'password', ph: '••••••••' },
      { key: 'userFilter', label: '用户过滤', type: 'text', ph: '(sAMAccountName=%s)' },
      { key: 'ldaps', label: '启用 LDAPS', type: 'switch' },
      { key: 'syncGroup', label: '同步用户组', type: 'switch', hint: '映射到动态组' }
    ],
    config: { url: 'ldaps://dc.corp.com:636', baseDN: 'dc=corp,dc=com', bindDN: '', bindPwd: '', userFilter: '(sAMAccountName=%s)', ldaps: true, syncGroup: true } },

  { k: 'sms', name: '短信验证码', cat: 'primary', ic: '信', color: '#22c55e', tag: '系统级自动填充',
    desc: '一次性短信验证码，系统级自动填充不读短信库（SSL-PRD §14）。', on: true,
    schema: [
      { key: 'gateway', label: '短信网关', type: 'select', opts: [{ label: '阿里云短信', value: 'aliyun' }, { label: '腾讯云短信', value: 'tencent' }, { label: '华为云短信', value: 'huawei' }, { label: '自建网关', value: 'self' }] },
      { key: 'accessKey', label: 'AccessKey / AppID', type: 'text', ph: 'LTAI5t...' },
      { key: 'sign', label: '短信签名', type: 'text', ph: '【白帝安全】' },
      { key: 'template', label: '模板 ID', type: 'text', ph: 'SMS_123456' },
      { key: 'digits', label: '验证码位数', type: 'number', unit: '位' },
      { key: 'ttl', label: '有效期', type: 'number', unit: '秒' },
      { key: 'rateLimit', label: '发送频率限制', type: 'number', unit: '条/分钟' }
    ],
    config: { gateway: 'aliyun', accessKey: '', sign: '【白帝安全】', template: '', digits: 6, ttl: 300, rateLimit: 1 } },

  { k: 'email', name: '邮箱验证码', cat: 'primary', ic: '邮', color: '#f59e0b', tag: 'SMTP 一次性码',
    desc: '邮箱一次性验证码，适合无手机号的外部协作者。', on: false,
    schema: [
      { key: 'smtp', label: 'SMTP 服务器', type: 'text', ph: 'smtp.corp.com' },
      { key: 'port', label: '端口', type: 'number' },
      { key: 'from', label: '发件账号', type: 'text', ph: 'noreply@corp.com' },
      { key: 'pwd', label: '发件密码', type: 'password' },
      { key: 'tls', label: '启用 TLS', type: 'switch' },
      { key: 'ttl', label: '有效期', type: 'number', unit: '秒' }
    ],
    config: { smtp: '', port: 465, from: '', pwd: '', tls: true, ttl: 600 } },

  { k: 'qr', name: '扫码登录', cat: 'primary', ic: '扫', color: '#14b8a6', tag: '已登录端扫码',
    desc: '已登录的移动端扫桌面端二维码，免输密码完成登录。', on: true,
    schema: [
      { key: 'ttl', label: '二维码有效期', type: 'number', unit: '秒' },
      { key: 'poll', label: '轮询间隔', type: 'number', unit: '毫秒' },
      { key: 'sameTenant', label: '仅限同企业', type: 'switch' }
    ],
    config: { ttl: 120, poll: 1500, sameTenant: true } },

  { k: 'oauth-scan', name: '第三方扫码', cat: 'primary', ic: '群', color: '#3b82f6', tag: '企微/钉钉/飞书',
    desc: '企业微信 / 钉钉 / 飞书扫码授权登录，复用既有组织身份。', on: false,
    schema: [
      { key: 'platform', label: '第三方平台', type: 'select', opts: [{ label: '企业微信', value: 'wecom' }, { label: '钉钉', value: 'dingtalk' }, { label: '飞书', value: 'feishu' }] },
      { key: 'corpId', label: '企业 ID / CorpID', type: 'text', ph: 'ww1234567890' },
      { key: 'appId', label: '应用 AppID', type: 'text' },
      { key: 'appSecret', label: '应用 Secret', type: 'password' },
      { key: 'callback', label: '回调域名', type: 'text', ph: 'https://sso.corp.com/cb' },
      { key: 'mapField', label: '用户映射字段', type: 'select', opts: [{ label: '手机号', value: 'mobile' }, { label: '邮箱', value: 'email' }, { label: 'UserID', value: 'userid' }] }
    ],
    config: { platform: 'wecom', corpId: '', appId: '', appSecret: '', callback: '', mapField: 'mobile' } },

  { k: 'cert-sm2', name: '国密证书（SM2）', cat: 'primary', ic: '证', color: '#dc2626', tag: 'SM2 双证 · 引用证书中心',
    desc: '国密 SM2 数字证书认证，服务账号 / 无人值守节点主认证方式。信任 CA / 吊销策略 / 双证引用〈系统·证书与密钥〉，不在此重复配置。', on: true,
    schema: [
      { key: 'trustCA', label: '信任 CA', type: 'caref', hint: '引用证书中心信任 CA 库' },
      { key: 'subjectField', label: '主体匹配字段', type: 'select', opts: [{ label: 'CN（通用名）', value: 'cn' }, { label: 'SAN（备用名）', value: 'san' }, { label: 'OU（组织单元）', value: 'ou' }] }
    ],
    config: { trustCA: [], subjectField: 'cn' } },

  { k: 'ukey', name: '国密 UKey', cat: 'primary', ic: 'U', color: '#b91c1c', tag: '智能密码钥匙',
    desc: '硬件智能密码钥匙（USBKey），私钥不出硬件，PIN 解锁，最高强度。', on: false,
    schema: [
      { key: 'vendor', label: '厂商', type: 'select', opts: [{ label: '飞天诚信', value: 'ftsafe' }, { label: '握奇', value: 'watchdata' }, { label: '海泰方圆', value: 'haitai' }, { label: '其他（PKCS#11）', value: 'pkcs11' }] },
      { key: 'middleware', label: '中间件路径', type: 'text', ph: '/usr/lib/libgm-p11.so' },
      { key: 'pinRetry', label: 'PIN 尝试次数', type: 'number', unit: '次' },
      { key: 'requirePresent', label: '要求物理在位', type: 'switch', hint: '拔出即下线' }
    ],
    config: { vendor: 'ftsafe', middleware: '', pinRetry: 5, requirePresent: true } },

  { k: 'bio', name: '生物识别', cat: 'primary', ic: '生', color: '#8b5cf6', tag: '端侧 · 模板不出设备',
    desc: '端侧生物解锁凭证（SE/TEE/HUKS），生物模板不出设备，仅返回解锁断言。', on: true,
    schema: [
      { key: 'types', label: '支持类型', type: 'tags', ph: '指纹 / 人脸 / 声纹' },
      { key: 'store', label: '模板存储', type: 'select', opts: [{ label: '端侧 SE 安全单元', value: 'se' }, { label: '端侧 TEE', value: 'tee' }] },
      { key: 'liveness', label: '活体检测', type: 'switch' },
      { key: 'fallback', label: '回退方式', type: 'select', opts: [{ label: 'OTP', value: 'otp' }, { label: '密码', value: 'pwd' }] }
    ],
    config: { types: ['指纹', '人脸'], store: 'se', liveness: true, fallback: 'otp' } },

  { k: 'radius', name: 'RADIUS', cat: 'primary', ic: 'R', color: '#64748b', tag: '对接既有认证',
    desc: '对接企业既有 RADIUS（如堡垒机 / 准入），复用已有口令体系。', on: false,
    schema: [
      { key: 'host', label: '服务器地址', type: 'text', ph: '10.0.0.10' },
      { key: 'port', label: '端口', type: 'number' },
      { key: 'secret', label: '共享密钥', type: 'password' },
      { key: 'proto', label: '协议', type: 'select', opts: [{ label: 'PAP', value: 'pap' }, { label: 'CHAP', value: 'chap' }, { label: 'MSCHAPv2', value: 'mschapv2' }] },
      { key: 'timeout', label: '超时', type: 'number', unit: '秒' }
    ],
    config: { host: '', port: 1812, secret: '', proto: 'mschapv2', timeout: 5 } },

  { k: 'totp', name: 'TOTP 动态令牌', cat: 'mfa', ic: 'T', color: '#0d9488', tag: '管理员 MFA 保底',
    desc: '基于时间的一次性口令（Google Authenticator 等），管理员 MFA 最低保障不可全局关闭。', on: true, locked: true,
    schema: [
      { key: 'alg', label: '哈希算法', type: 'select', opts: [{ label: 'SHA-1（兼容）', value: 'sha1' }, { label: 'SHA-256', value: 'sha256' }, { label: 'SM3（国密）', value: 'sm3' }] },
      { key: 'digits', label: '位数', type: 'select', opts: [{ label: '6 位', value: '6' }, { label: '8 位', value: '8' }] },
      { key: 'period', label: '周期', type: 'number', unit: '秒' },
      { key: 'skew', label: '漂移窗口', type: 'number', unit: '步' }
    ],
    config: { alg: 'sha1', digits: '6', period: 30, skew: 1 } },

  { k: 'webauthn', name: 'WebAuthn / FIDO2', cat: 'mfa', ic: 'F', color: '#7c3aed', tag: '无密码 Passkey',
    desc: '控制台与门户的无密码二次验证（passkey / 安全密钥），抗钓鱼。', on: true,
    schema: [
      { key: 'rpId', label: 'RP ID', type: 'text', ph: 'corp.com' },
      { key: 'uv', label: '用户验证', type: 'select', opts: [{ label: '必须（required）', value: 'required' }, { label: '偏好（preferred）', value: 'preferred' }] },
      { key: 'authType', label: '认证器类型', type: 'select', opts: [{ label: '平台（Face/Touch ID）', value: 'platform' }, { label: '跨平台（安全密钥）', value: 'cross-platform' }, { label: '不限', value: 'any' }] },
      { key: 'residentKey', label: '驻留密钥（Discoverable）', type: 'switch' }
    ],
    config: { rpId: 'corp.com', uv: 'preferred', authType: 'any', residentKey: true } },

  { k: 'push', name: '推送确认', cat: 'mfa', ic: '推', color: '#2563eb', tag: 'App 一键确认',
    desc: 'App 推送登录请求，一键批准 / 拒绝，含登录地点与防疲劳轰炸。', on: false,
    schema: [
      { key: 'channel', label: '推送通道', type: 'select', opts: [{ label: '自建（APNs + FCM）', value: 'self' }, { label: '极光推送', value: 'jpush' }, { label: '个推', value: 'getui' }] },
      { key: 'timeout', label: '确认超时', type: 'number', unit: '秒' },
      { key: 'showGeo', label: '显示登录地点', type: 'switch' },
      { key: 'antiFatigue', label: '防疲劳轰炸', type: 'switch', hint: '连续拒绝后冷却' }
    ],
    config: { channel: 'self', timeout: 60, showGeo: true, antiFatigue: true } },

  { k: 'hw-otp', name: '硬件令牌 OTP', cat: 'mfa', ic: 'H', color: '#475569', tag: 'OATH 离线令牌',
    desc: '离线硬件 OATH 令牌（OTP token），无网环境二次认证。', on: false,
    schema: [
      { key: 'standard', label: '标准', type: 'select', opts: [{ label: 'TOTP（时间）', value: 'totp' }, { label: 'HOTP（计数）', value: 'hotp' }] },
      { key: 'seedImport', label: '种子导入', type: 'select', opts: [{ label: 'PSKC 文件', value: 'pskc' }, { label: '手工录入', value: 'manual' }] },
      { key: 'digits', label: '位数', type: 'select', opts: [{ label: '6 位', value: '6' }, { label: '8 位', value: '8' }] }
    ],
    config: { standard: 'totp', seedImport: 'pskc', digits: '6' } }
];

const methods = ref<Method[]>(catalog.map((m) => ({ ...m, config: { ...m.config } })));
const sel = ref('cert-sm2');
const live = ref(false);
const current = computed(() => methods.value.find((m) => m.k === sel.value));

const methodsOf = (cat: string) => methods.value.filter((m) => m.cat === cat);
const catCount = (cat: string) => methods.value.filter((m) => m.cat === cat).length;
const enabledCount = (cat: string) => methods.value.filter((m) => m.cat === cat && m.on).length;

const sm2 = ref(false);

// 信任 CA 引用：cert-sm2 的 trustCA 从证书中心信任库选；展示继承的吊销/双证策略
const caOpts = ref<{ key: string; name: string; level: string; revoke: string; dualCert: boolean }[]>([]);
const mockCAOpts = [
  { key: 'gm-root', name: 'Baidi GM Root CA', level: 'root', revoke: 'ocsp', dualCert: true },
  { key: 'gm-sub-hq', name: 'Baidi GM HQ Sub CA', level: 'intermediate', revoke: 'crl', dualCert: true }
];
async function loadCAs() {
  try {
    const r = await fetch('/ctl/api/coll?kind=trustca');
    if (!r.ok) throw new Error();
    const docs = await r.json();
    caOpts.value = Array.isArray(docs) && docs.length ? docs.map((d: any) => ({ key: d.key, name: d.name, level: d.level, revoke: d.revoke, dualCert: d.dualCert })) : mockCAOpts;
  } catch { caOpts.value = mockCAOpts; }
}
const caInheritText = computed(() => {
  const picked = caOpts.value.filter((c) => ((current.value?.config?.trustCA as string[]) || []).includes(c.key));
  if (!picked.length) return '未选择信任 CA · 证书认证将拒绝所有证书 · ';
  const revokes = [...new Set(picked.map((c) => c.revoke))];
  const revLabel = revokes.length === 1 ? ({ ocsp: 'OCSP 实时', crl: 'CRL 列表', off: '关闭' } as Record<string, string>)[revokes[0]] : '按各 CA';
  return `继承：吊销检查 ${revLabel} · 双证 ${picked.every((c) => c.dualCert) ? '要求' : '混合'} · `;
});

// 认证方式来自控制面 /ctl/api/coll?kind=authmethod（持久化）；覆盖到 catalog 的开关/配置。
async function loadMethods() {
  try {
    const r = await fetch('/ctl/api/coll?kind=authmethod');
    if (!r.ok) return;
    const docs = await r.json();
    const byKey: Record<string, any> = {};
    for (const d of docs) byKey[d.k ?? d.key] = d;
    methods.value = catalog.map((m) => {
      const d = byKey[m.k];
      return {
        ...m,
        on: d && typeof d.on === 'boolean' ? d.on : m.on,
        config: { ...m.config, ...(d?.config ?? {}) }
      };
    });
    live.value = true;
  } catch { live.value = false; }
}
onMounted(() => { loadMethods(); loadCAs(); });

async function persist(m: Method) {
  if (!live.value) return true;
  try {
    const r = await fetch('/ctl/api/coll?kind=authmethod', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: m.k, doc: { k: m.k, name: m.name, cat: m.cat, on: m.on, config: m.config } })
    });
    return r.ok;
  } catch { return false; }
}

async function toggle(m: Method) {
  const ok = await persist(m);
  if (!ok && live.value) { m.on = !m.on; return Message.error('操作失败，已回滚'); }
  Message.info(`「${m.name}」已${m.on ? '启用' : '停用'} · ≤60s 下发在线端点${live.value ? ' · 已持久化' : ''}`);
}

async function saveCfg(m: Method) {
  const ok = await persist(m);
  if (!ok && live.value) return Message.error('保存失败');
  Message.success(`「${m.name}」配置已保存${live.value ? ' · 已持久化' : '（mock）'}`);
}

</script>

<style scoped>
.auth-stat { display: flex; gap: 18px; align-items: center; }
.auth-stat span { font-size: 12px; color: var(--ink-3); }
.auth-stat b { font-size: 17px; color: var(--ink); font-weight: 700; margin-right: 2px; }

/* 左：方式列表 */
.auth-list { padding: 8px; overflow: hidden; }
.auth-cat { padding: 6px 4px 10px; }
.auth-cat__title { font-size: 11.5px; font-weight: 700; color: var(--ink-2); text-transform: none; padding: 6px 10px; display: flex; align-items: baseline; gap: 8px; }
.auth-cat__hint { font-size: 10.5px; color: var(--ink-3); font-weight: 400; }
.auth-row { display: flex; align-items: center; gap: 10px; padding: 9px 10px; border-radius: var(--r-md); cursor: pointer; transition: background .15s; position: relative; }
.auth-row:hover { background: var(--fill-1, rgba(0,0,0,.03)); }
.auth-row.active { background: var(--accent-soft); }
.auth-row.active::before { content: ''; position: absolute; left: 0; top: 6px; bottom: 6px; width: 3px; border-radius: 2px; background: var(--accent-2); }
.auth-row.off .auth-row__name, .auth-row.off .auth-row__ic { opacity: .5; }
.auth-row__ic { width: 28px; height: 28px; border-radius: 8px; display: grid; place-items: center; color: #fff; font-size: 12px; font-weight: 700; flex-shrink: 0; }
.auth-row__main { flex: 1; min-width: 0; }
.auth-row__name { font-size: 13px; font-weight: 600; color: var(--ink); line-height: 1.2; }
.auth-row__desc { font-size: 10.5px; color: var(--ink-3); margin-top: 1px; }

/* 右：配置详情 */
.auth-cfg { display: flex; flex-direction: column; min-width: 0; }
.auth-cfg__head { display: flex; align-items: flex-start; gap: 12px; padding-bottom: 14px; border-bottom: 1px solid var(--line); }
.auth-cfg__ic { width: 38px; height: 38px; border-radius: 10px; display: grid; place-items: center; color: #fff; font-size: 15px; font-weight: 700; flex-shrink: 0; }
.auth-cfg__name { font-size: 15px; font-weight: 700; color: var(--ink); }
.auth-cfg__desc { font-size: 12px; color: var(--ink-3); margin-top: 3px; line-height: 1.5; }
.auth-cfg__body { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px 24px; padding: 16px 0; }
.cfg-field { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
.cfg-field__label { font-size: 12px; font-weight: 600; color: var(--ink-2); display: flex; align-items: baseline; gap: 7px; }
.cfg-field__hint { font-size: 10.5px; color: var(--ink-3); font-weight: 400; }
.cfg-field__ctl { min-width: 0; }
.cfg-empty { color: var(--ink-3); font-size: 12.5px; padding: 12px 0; }

/* 账号密码：归位跳转块（口令规则归口令策略 / 锁定归账号安全） */
.auth-cfg__body--plain { display: block; }
.pwd-redirect { padding: 4px 0 2px; }
.pwd-redirect__lead { font-size: 12.5px; color: var(--ink-2); line-height: 1.6; margin: 0 0 12px; }
.pwd-redirect__links { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.pwd-link { display: flex; flex-direction: column; gap: 4px; padding: 12px 14px; border: 1px solid var(--line); border-radius: var(--r-md); text-decoration: none; transition: all .15s; }
.pwd-link:hover { border-color: var(--accent-2); background: var(--accent-soft); }
.pwd-link__t { font-size: 13px; font-weight: 650; color: var(--accent-2); }
.pwd-link__d { font-size: 11px; color: var(--ink-3); line-height: 1.5; }
.pwd-redirect__hint { font-size: 11px; color: var(--ink-3); margin: 12px 0 0; line-height: 1.6; }
.caref-inherit { font-size: 11px; color: var(--ink-3); margin-top: 6px; line-height: 1.5; }
.caref-link { color: var(--accent-2); text-decoration: none; margin-left: 4px; }
.caref-link:hover { text-decoration: underline; }
.auth-cfg__foot { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding-top: 14px; border-top: 1px solid var(--line); margin-top: auto; }
.auth-cfg__tip { font-size: 11px; color: var(--ink-3); }

/* 全局策略行 */
.auth-rows { display: flex; flex-direction: column; }
.auth-prow { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 11px 0; }
.auth-prow + .auth-prow { border-top: 1px solid var(--line); }
.auth-prow b { display: block; font-size: 13px; color: var(--ink); font-weight: 650; }
.auth-prow span { display: block; font-size: 11.5px; color: var(--ink-3); margin-top: 2px; }
</style>
