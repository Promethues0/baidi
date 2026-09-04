<template>
  <div class="bd-portal">
    <!-- 左侧品牌区 -->
    <aside class="bd-brand">
      <div class="bd-brand__top">
        <div class="bd-brand__logo">
          <span class="bd-brand__mark">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
              <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
              <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
          </span>
          <span class="bd-brand__name">
            <b>白帝 · 零信任</b>
            <i>ZTNA · SDP 安全接入门户</i>
          </span>
        </div>
      </div>

      <div class="bd-brand__mid">
        <h1 class="bd-brand__h">先认证，<br />后连接。</h1>
        <p class="bd-brand__sub">免客户端的零信任安全接入网关，让业务对未授权者彻底隐身。</p>

        <ul class="bd-sell">
          <li>
            <span class="bd-sell__ic"><icon-safe /></span>
            <span class="bd-sell__t"><b>默认不信任 · 持续验证</b><i>每一次访问都重新校验身份与设备</i></span>
          </li>
          <li>
            <span class="bd-sell__ic"><icon-eye-invisible /></span>
            <span class="bd-sell__t"><b>先认证后连接</b><i>SPA 单包敲门授权，未授权者看不到业务</i></span>
          </li>
          <li>
            <span class="bd-sell__ic"><icon-common /></span>
            <span class="bd-sell__t"><b>免客户端 · 跨平台跨浏览器</b><i>B/S 直达，无需安装任何代理</i></span>
          </li>
        </ul>
      </div>

      <div class="bd-brand__foot">
        <span class="bd-stealth"><span class="bd-stealth__dot" />SPA 敲门授权 · 先认证后连接</span>
      </div>
    </aside>

    <!-- 右侧登录卡 -->
    <main class="bd-pane">
      <div class="bd-card">
        <span class="bd-card__mark">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
            <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </span>

        <!-- 步骤一：账号口令 -->
        <template v-if="step === 'login'">
          <h2 class="bd-card__h">欢迎登录</h2>
          <p class="bd-card__p">请使用企业账号登录白帝安全接入门户</p>

          <div v-if="errMsg" class="bd-tip bd-tip--err">
            <icon-close-circle-fill />
            <span>{{ errMsg }}</span>
          </div>

          <a-form :model="form" layout="vertical" @submit.prevent>
            <!-- 认证域：只有配了 ≥2 个外部认证源时才出现。★它不是"多一个可选项"——不选
                 的话后端会拒绝登录，因为挨个去问等于把明文口令投递给每一台目录服务器。 -->
            <a-form-item v-if="authDomains.length" field="directory" hide-label>
              <a-select v-model="form.directory" size="large" placeholder="选择你所属的认证域">
                <template #prefix><icon-apps /></template>
                <a-option v-for="d in authDomains" :key="d.id" :value="d.id">
                  {{ d.name }}<span class="bd-dirkind">{{ d.kind.toUpperCase() }}</span>
                </a-option>
              </a-select>
            </a-form-item>
            <a-form-item field="username" hide-label>
              <a-input
                v-model="form.username"
                placeholder="用户名 / 工号"
                size="large"
                allow-clear
                @keyup.enter="submitLogin"
              >
                <template #prefix><icon-user /></template>
              </a-input>
            </a-form-item>
            <a-form-item field="password" hide-label>
              <a-input-password
                v-model="form.password"
                placeholder="登录口令"
                size="large"
                allow-clear
                @keyup.enter="submitLogin"
              >
                <template #prefix><icon-lock /></template>
              </a-input-password>
            </a-form-item>
          </a-form>

          <a-button
            type="primary"
            long
            size="large"
            :loading="loading"
            class="bd-submit"
            @click="submitLogin"
          >
            登录
          </a-button>

          <!-- 企业身份（OIDC）入口：按 auth_sources 真实行渲染，没有已启用的源就整段不出现。 -->
          <template v-if="oidcProviders.length">
            <div class="bd-oidc__sep"><span>或使用企业身份登录</span></div>
            <a-button v-for="pv in oidcProviders" :key="pv.id" long class="bd-oidc__btn"
              :disabled="loading" @click="startOidc(pv.id)">
              <template #icon><icon-idcard /></template>
              {{ pv.name }}
            </a-button>
          </template>
        </template>

        <!-- 步骤二：passkey 二次认证（WebAuthn 断言） -->
        <template v-else-if="step === 'webauthn'">
          <h2 class="bd-card__h">二次认证</h2>
          <p class="bd-card__p">为账号 <b>{{ form.username }}</b> 完成 passkey 验证</p>

          <div class="bd-tip bd-tip--warn">
            <icon-safe />
            <span>{{ mfaReason || '请用已注册的 passkey 完成二次认证。' }}</span>
          </div>

          <div class="bd-pk">
            <span class="bd-pk__ic"><icon-fingerprint /></span>
            <div class="bd-pk__t">
              <b>Touch ID / Windows Hello / 安全密钥</b>
              <i>公钥密码学验证，抗钓鱼——凭据永不离开你的设备</i>
            </div>
          </div>

          <a-button
            type="primary"
            long
            size="large"
            :loading="loading"
            class="bd-submit"
            @click="submitWebauthn"
          >
            使用 passkey 验证
          </a-button>
          <a-button type="text" long class="bd-back" @click="backToLogin">
            <template #icon><icon-left /></template>
            返回重新登录
          </a-button>
        </template>

        <!-- 步骤二：TOTP 动态验证码（RFC 6238，已启用 TOTP 的账号强制） -->
        <template v-else-if="step === 'totp'">
          <h2 class="bd-card__h">二次认证</h2>
          <p class="bd-card__p">为账号 <b>{{ form.username }}</b> 输入动态验证码</p>

          <div class="bd-tip bd-tip--warn">
            <icon-safe />
            <span>{{ mfaReason || '请输入认证器 App 中的 6 位动态验证码。' }}</span>
          </div>

          <a-form :model="form" layout="vertical" @submit.prevent>
            <a-form-item field="mfaCode" hide-label>
              <a-input
                v-model="form.mfaCode"
                placeholder="6 位动态验证码"
                size="large"
                allow-clear
                :max-length="6"
                @keyup.enter="submitTotp"
              >
                <template #prefix><icon-mobile /></template>
              </a-input>
            </a-form-item>
          </a-form>

          <a-button
            type="primary"
            long
            size="large"
            :loading="loading"
            class="bd-submit"
            @click="submitTotp"
          >
            验证并登录
          </a-button>
          <a-button type="text" long class="bd-back" @click="backToLogin">
            <template #icon><icon-left /></template>
            返回重新登录
          </a-button>
        </template>

        <!-- 强制改密：初始口令须由本人换掉后才发正常会话 -->
        <template v-else-if="step === 'changepw'">
          <h2 class="bd-card__h">修改初始口令</h2>
          <p class="bd-card__p">账号 <b>{{ form.username }}</b> 正在使用初始口令，须修改后才能进入门户</p>

          <div v-if="pwMsg" class="bd-tip bd-tip--err">
            <icon-close-circle-fill />
            <span>{{ pwMsg }}</span>
          </div>

          <a-form :model="pwForm" layout="vertical" @submit.prevent>
            <a-form-item field="pw" hide-label>
              <a-input-password
                v-model="pwForm.pw"
                placeholder="新口令（至少 8 位，不得与初始口令相同）"
                size="large"
                allow-clear
                @keyup.enter="submitChangePw"
              >
                <template #prefix><icon-lock /></template>
              </a-input-password>
            </a-form-item>
            <a-form-item field="pw2" hide-label>
              <a-input-password
                v-model="pwForm.pw2"
                placeholder="再次输入新口令"
                size="large"
                allow-clear
                @keyup.enter="submitChangePw"
              >
                <template #prefix><icon-lock /></template>
              </a-input-password>
            </a-form-item>
          </a-form>

          <a-button
            type="primary"
            long
            size="large"
            :loading="loading"
            class="bd-submit"
            @click="submitChangePw"
          >
            修改并登录
          </a-button>
          <a-button type="text" long class="bd-back" @click="backToLogin">
            <template #icon><icon-left /></template>
            返回重新登录
          </a-button>
        </template>

        <!-- 步骤二（legacy）：未配置 WebAuthn 且账号未注册 TOTP 时的演示验证码回落，只在裸 IP
             演示站可达。★文案不许写「短信」：系统从不发送任何短信，后端收的是编译进二进制的
             演示码（webauthn.go 的 legacyDemoCode），写成短信会让用户干等一条永远不来的短信。 -->
        <template v-else>
          <h2 class="bd-card__h">二次认证</h2>
          <p class="bd-card__p">为账号 <b>{{ form.username }}</b> 输入演示验证码</p>

          <div class="bd-tip bd-tip--warn">
            <icon-exclamation-circle-fill />
            <span>{{ mfaReason || '该账号未注册 passkey / TOTP，本站回落到演示验证码（123456）——生产环境请在「我的安全」注册 TOTP。' }}</span>
          </div>

          <a-form :model="form" layout="vertical" @submit.prevent>
            <a-form-item field="mfaCode" hide-label>
              <a-input
                v-model="form.mfaCode"
                placeholder="演示验证码（123456）"
                size="large"
                allow-clear
                :max-length="6"
                @keyup.enter="submitMfa"
              >
                <template #prefix><icon-safe /></template>
              </a-input>
            </a-form-item>
          </a-form>

          <a-button
            type="primary"
            long
            size="large"
            :loading="loading"
            class="bd-submit"
            @click="submitMfa"
          >
            验证并登录
          </a-button>
          <a-button type="text" long class="bd-back" @click="backToLogin">
            <template #icon><icon-left /></template>
            返回重新登录
          </a-button>
        </template>

        <p class="bd-demo">
          演示提示：口令 <code class="bd-mono">baidi@123</code>。已注册 passkey / TOTP 的账号登录需
          二次认证；登录后可在 <b>「我的安全」</b> 管理 passkey 与 TOTP 动态口令。
        </p>

        <p class="bd-getcli">
          <router-link class="bd-getcli__link" to="/portal/downloads">
            <icon-download /> 下载桌面 / 移动客户端
          </router-link>
        </p>
      </div>

      <p class="bd-copy">白帝零信任 · ZTNA / SDP Control Center</p>
    </main>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { api, setToken, type PortalLoginResp, type AuthDomainOption, failStatus, failReason } from '@/lib/api';
import { getAssertion, webauthnErrMsg, webauthnSupported } from '@/lib/webauthn';

const router = useRouter();

const step = ref<'login' | 'webauthn' | 'totp' | 'mfa' | 'changepw'>('login');
const loading = ref(false);
const errMsg = ref('');
const mfaReason = ref('');
const ticket = ref(''); // 「口令已验」一次性票据，断言两回合凭它绑定账号
const pwToken = ref(''); // 首登强制改密的 15min 受限令牌（只够调 /auth/password，不入 localStorage）
const pwMsg = ref('');

const form = reactive({ username: '', password: '', mfaCode: '', directory: '' });

/* ── 认证域 ──
   只有配了 ≥2 个外部认证源时后端才回非空列表；单目录部署下这个下拉不出现。 */
const authDomains = ref<AuthDomainOption[]>([]);
async function loadAuthDomains() {
  try {
    const r = await api<{ domains: AuthDomainOption[] }>('/auth/domains');
    authDomains.value = r.domains ?? [];
    // 只有一个候选时直接选中（虽然后端此时本就回空，这里是防御性的）。
    if (authDomains.value.length === 1) form.directory = authDomains.value[0].id;
  } catch {
    authDomains.value = [];
  }
}
const pwForm = reactive({ pw: '', pw2: '' });

/* ── OIDC 登录 ── */
interface OidcProvider { id: string; name: string }
const oidcProviders = ref<OidcProvider[]>([]);

function startOidc(id: string) {
  // 整页跳转到控制面授权端点（302 去 IdP）。相对路径：与部署形态无关。
  window.location.href = `/api/v1/auth/oidc/${encodeURIComponent(id)}/authorize`;
}

/** 回调落地处理。约定见 control/internal/api/oidc_login.go：
 *  oidcGrant  = 60s 单次交接票据 → POST 换会话令牌（8h 令牌绝不出现在 URL 里）
 *  oidcTicket = 认证已过但需 passkey 断言 → 接入既有 webauthn 流程
 *  oidcError  = 人话失败原因 */
async function handleOidcReturn() {
  const qs = new URLSearchParams(window.location.search);
  const grant = qs.get('oidcGrant');
  const mfaT = qs.get('oidcTicket');
  const totpT = qs.get('oidcTotp');
  const oerr = qs.get('oidcError');
  const src = qs.get('oidcSrc') ?? '';
  if (!grant && !mfaT && !totpT && !oerr) return;
  // 先把票据从地址栏擦掉：留着会进书签/分享链接，且刷新会触发一次注定失败的重放。
  window.history.replaceState(null, '', window.location.pathname);
  if (oerr) {
    errMsg.value = (src ? `【${src}】` : '') + oerr;
    return;
  }
  if (mfaT) {
    ticket.value = mfaT;
    mfaReason.value = src ? `已通过 ${src} 认证，请完成 passkey 二次验证` : '请完成 passkey 二次验证';
    form.username = '（企业身份）';
    step.value = 'webauthn';
    void submitWebauthn();
    return;
  }
  if (totpT) {
    ticket.value = totpT;
    mfaReason.value = src ? `已通过 ${src} 认证，请输入 TOTP 动态验证码` : '请输入 TOTP 动态验证码';
    form.username = '（企业身份）';
    form.mfaCode = '';
    step.value = 'totp';
    return;
  }
  if (grant) {
    loading.value = true;
    try {
      const resp = await api<PortalLoginResp>('/auth/oidc/session', {
        method: 'POST', body: JSON.stringify({ ticket: grant })
      });
      if (resp.ok && resp.token) onSuccess(resp);
      else errMsg.value = resp.reason ?? '登录交接失败，请重新发起登录';
    } catch (e) {
      errMsg.value = `登录交接失败：${e instanceof Error ? e.message : e}`;
    } finally {
      loading.value = false;
    }
  }
}

onMounted(() => {
  void loadAuthDomains();
  void handleOidcReturn();
  // 公开清单（无需登录）；拉不到就不渲染入口——没有源时本地口令登录不受影响。
  api<{ providers: OidcProvider[] }>('/auth/oidc/providers')
    .then((r) => { oidcProviders.value = r.providers ?? []; })
    .catch(() => { oidcProviders.value = []; });
});

function onSuccess(resp: PortalLoginResp) {
  // 首登强制改密：服务端只发了受限令牌（业务端点一律 403），转入改密表单
  if (resp.mustChangePassword && resp.token) {
    pwToken.value = resp.token;
    pwForm.pw = '';
    pwForm.pw2 = '';
    pwMsg.value = '';
    step.value = 'changepw';
    return;
  }
  if (resp.token) setToken(resp.token); // 写 localStorage，使 /portal/apps 携带 Bearer
  sessionStorage.setItem(
    'baidi_portal',
    JSON.stringify({ token: resp.token, displayName: resp.displayName ?? form.username })
  );
  Message.success(`欢迎回来，${resp.displayName ?? form.username}`);
  router.push('/portal/apps');
}

async function post(withMfa: boolean): Promise<PortalLoginResp | null> {
  const body: Record<string, string> = { username: form.username, password: form.password };
  if (withMfa) body.mfaCode = form.mfaCode;
  // 认证域：配了多个外部源时必带。不带的话后端会拒绝并回 needDirectory，
  // 而不是挨个去问——挨个问等于把明文口令投递给每一个排在前面的目录服务器。
  if (form.directory) body.directory = form.directory;
  try {
    return await api<PortalLoginResp>('/portal/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  } catch (e) {
    // ★后端在**口令校验之前**就会定性拒绝：lockout.go 的 loginGateLocked 挂在最前面，
    //   回 403 +「登录失败次数过多，已被临时锁定，请约 N 分钟后重试」；认证域没选对时
    //   回的是「配置了多个认证域，请选择」。改造前这里是 bare catch，把这些整句换成
    //   「网络异常或服务不可达，请稍后重试。」——而防爆破的 IP 维默认开着：同一 NAT 出口
    //   有人连错 5 次，其余人都被这句话支去"稍后重试"，每一次重试又在续锁，
    //   门户于是对整个办公室静默地关了 15 分钟，且没有任何一处说得出为什么。
    errMsg.value = failReason(e);
    return null;
  }
}

async function submitLogin() {
  errMsg.value = '';
  if (!form.username.trim() || !form.password) {
    errMsg.value = '请输入用户名与登录口令。';
    return;
  }
  loading.value = true;
  const resp = await post(false);
  loading.value = false;
  if (!resp) return;

  // 认证域未指定（配了多个外部源）：把候选灌进下拉让用户选，而不是让他去猜口令。
  // ★后端此时**没有**去问任何一台目录服务器，口令一台都没发出去。
  if (resp.needDirectory) {
    authDomains.value = resp.domains ?? [];
    errMsg.value = resp.reason ?? '请选择你所属的认证域后重试。';
    return;
  }

  // passkey 二次认证（口令已通过，服务端下发一次性票据）
  if (resp.needWebauthn && resp.ticket) {
    if (!webauthnSupported()) {
      errMsg.value = '当前浏览器不支持 passkey，请更换浏览器或联系管理员。';
      return;
    }
    ticket.value = resp.ticket;
    mfaReason.value = resp.reason ?? '';
    step.value = 'webauthn';
    void submitWebauthn(); // 直接唤起认证器，省去多一次点击
    return;
  }
  // TOTP 动态验证码（口令已通过，已启用 TOTP 的账号强制）
  if (resp.needTotp && resp.ticket) {
    ticket.value = resp.ticket;
    mfaReason.value = resp.reason ?? '';
    form.mfaCode = '';
    step.value = 'totp';
    return;
  }
  // 风险账号尚未注册 passkey/TOTP：不放行，提示先录入
  if (resp.needEnroll) {
    errMsg.value = resp.reason || '该账号须先注册 passkey 或 TOTP 才能接入。';
    return;
  }
  if (resp.needMfa) {
    mfaReason.value = resp.reason ?? '';
    form.mfaCode = '';
    step.value = 'mfa';
    return;
  }
  if (resp.ok && resp.token) {
    onSuccess(resp);
    return;
  }
  errMsg.value = resp.reason || '用户名或口令错误，请重试。';
}

/** passkey 断言两回合：begin 取 challenge → navigator.credentials.get → finish 换会话令牌。 */
async function submitWebauthn() {
  if (!ticket.value) {
    backToLogin();
    return;
  }
  errMsg.value = '';
  loading.value = true;
  try {
    const opts = await api<{ publicKey: Record<string, never> }>('/webauthn/login/begin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ticket: ticket.value })
    });
    const assertion = await getAssertion(opts as never);
    const resp = await api<PortalLoginResp>('/webauthn/login/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...assertion, ticket: ticket.value })
    });
    if (resp.ok && resp.token) {
      onSuccess(resp);
      return;
    }
    mfaReason.value = resp.reason || 'passkey 验证失败，请重试。';
  } catch (e) {
    // 票据过期（3min）→ 退回口令步骤重来
    if (failStatus(e) === 401) {
      errMsg.value = '认证超时，请重新登录。';
      backToLogin();
    } else {
      mfaReason.value = webauthnErrMsg(e);
    }
  } finally {
    loading.value = false;
  }
}

/** TOTP 第二回合：mfa 票据 + 6 位动态验证码换会话令牌（防重放：同码只能成功一次）。 */
async function submitTotp() {
  if (!ticket.value) {
    backToLogin();
    return;
  }
  if (!/^\d{6}$/.test(form.mfaCode.trim())) {
    Message.warning('请输入 6 位数字验证码。');
    return;
  }
  errMsg.value = '';
  loading.value = true;
  try {
    const resp = await api<PortalLoginResp>('/auth/totp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ticket: ticket.value, code: form.mfaCode.trim() })
    });
    if (resp.ok && resp.token) {
      onSuccess(resp);
      return;
    }
    mfaReason.value = resp.reason || '验证码不正确，请重试。';
  } catch (e) {
    // 401 = mfaTicket 过期/失效（那张票只有短时效）；其余一律是这一轮验证码本身的问题。
    // ★判状态码而不是判 message 里有没有「票据」二字——后端换一句文案这条分支就静默失效，
    // 表现为把「认证超时」说成「验证码不正确」，用户会一直重输一个永远不可能对的码。
    if (failStatus(e) === 401) {
      // 票据过期（3min）→ 退回口令步骤重来
      errMsg.value = '认证超时，请重新登录。';
      backToLogin();
    } else {
      mfaReason.value = '验证码不正确或已使用，请输入 App 当前显示的验证码。';
    }
  } finally {
    loading.value = false;
  }
}

async function submitMfa() {
  errMsg.value = '';
  if (!form.mfaCode.trim()) {
    Message.warning('请输入验证码。');
    return;
  }
  loading.value = true;
  const resp = await post(true);
  loading.value = false;
  if (!resp) {
    step.value = 'login';
    return;
  }

  if (resp.ok && resp.token) {
    onSuccess(resp);
    return;
  }
  mfaReason.value = resp.reason || '验证码错误或已失效，请重新获取。';
}

/** 首登强制改密：受限令牌调 /auth/password（不入 localStorage），成功后用新口令自动重新登录。 */
async function submitChangePw() {
  pwMsg.value = '';
  if (pwForm.pw.length < 8) {
    pwMsg.value = '新口令至少 8 位。';
    return;
  }
  if (pwForm.pw === form.password) {
    pwMsg.value = '新口令不得与初始口令相同。';
    return;
  }
  if (pwForm.pw !== pwForm.pw2) {
    pwMsg.value = '两次输入的新口令不一致。';
    return;
  }
  loading.value = true;
  try {
    const resp = await api<{ ok: boolean; reason?: string }>('/auth/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pwToken.value}` },
      body: JSON.stringify({ old: form.password, new: pwForm.pw })
    });
    if (!resp.ok) {
      pwMsg.value = resp.reason || '口令修改失败，请重试。';
      return;
    }
    // 改密成功 → 用新口令自动重新登录换正常会话（有 passkey 的账号会再走一次断言）
    Message.success('口令已修改，正在重新登录…');
    form.password = pwForm.pw;
    pwToken.value = '';
    step.value = 'login';
    await submitLogin();
  } catch (e) {
    // ★同一族的第三处。/auth/password 的拒绝几乎都不是"令牌过期"：最高频的是
    //   400「新口令强度不足：<具体哪一条不达标>。要求：至少 10 位且含大写/小写/数字/
    //   符号中的三类；或 16 位以上的长口令」——首登强制改密是每套标准部署的第一个动作
    //   （BAIDI_SEED_MUST_CHANGE 默认 1），而这里把那句唯一说得出"改成什么样才行"的话
    //   换成了「受限令牌可能已过期，请返回重新登录」：用户返回重登、再次被要求改密、
    //   再撞同一堵墙，来回死循环而屏幕上从没出现过"强度不足"四个字。
    //   （旧口令错误走的是 200 + reason，不经这里；令牌真过期是 401，failReason 照样原样转述。）
    pwMsg.value = failReason(e);
  } finally {
    loading.value = false;
  }
}

function backToLogin() {
  step.value = 'login';
  errMsg.value = '';
  mfaReason.value = '';
  form.mfaCode = '';
  ticket.value = '';
  pwToken.value = '';
  pwForm.pw = '';
  pwForm.pw2 = '';
  pwMsg.value = '';
}
</script>

<style scoped>
.bd-portal {
  display: flex;
  min-height: 100vh;
  background: #fff;
}

/* ───── 左侧品牌区 ───── */
.bd-brand {
  width: 46%;
  max-width: 620px;
  flex: none;
  padding: 48px 56px;
  color: #fff;
  background: linear-gradient(135deg, var(--bd-dark-1), var(--bd-dark-2));
  display: flex;
  flex-direction: column;
  position: relative;
  overflow: hidden;
}
.bd-brand::after {
  content: '';
  position: absolute;
  width: 460px;
  height: 460px;
  right: -160px;
  top: -120px;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(64, 128, 255, .28), transparent 70%);
  pointer-events: none;
}
.bd-brand__top,
.bd-brand__mid,
.bd-brand__foot { position: relative; z-index: 1; }

.bd-brand__logo { display: flex; align-items: center; gap: 13px; }
.bd-brand__mark {
  width: 42px; height: 42px; border-radius: 10px; flex: none;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d));
  display: flex; align-items: center; justify-content: center;
  box-shadow: 0 4px 14px rgba(22, 93, 255, .5);
}
.bd-brand__name { display: flex; flex-direction: column; line-height: 1.25; }
.bd-brand__name b { font-size: 17px; font-weight: 700; letter-spacing: .5px; }
.bd-brand__name i { font-style: normal; font-size: 12px; color: var(--bd-dark-txt); }

.bd-brand__mid { margin-top: auto; margin-bottom: auto; padding: 40px 0; }
.bd-brand__h {
  font-size: 40px; font-weight: 800; line-height: 1.2; letter-spacing: 1px; margin: 0 0 16px;
}
.bd-brand__sub {
  font-size: 15px; line-height: 1.7; color: var(--bd-dark-txt); margin: 0 0 36px; max-width: 380px;
}

.bd-sell { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 18px; }
.bd-sell li { display: flex; align-items: flex-start; gap: 14px; }
.bd-sell__ic {
  width: 38px; height: 38px; border-radius: 9px; flex: none;
  background: rgba(255, 255, 255, .1); border: 1px solid rgba(255, 255, 255, .14);
  display: flex; align-items: center; justify-content: center;
  font-size: 19px; color: #fff;
}
.bd-sell__t { display: flex; flex-direction: column; line-height: 1.4; padding-top: 2px; }
.bd-sell__t b { font-size: 14.5px; font-weight: 600; }
.bd-sell__t i { font-style: normal; font-size: 12.5px; color: var(--bd-dark-txt); margin-top: 3px; }

.bd-stealth {
  display: inline-flex; align-items: center; gap: 9px;
  font-size: 13px; color: var(--bd-dark-txt);
  padding: 8px 14px; border-radius: 999px;
  background: rgba(255, 255, 255, .07); border: 1px solid rgba(255, 255, 255, .12);
}
.bd-stealth__dot {
  width: 8px; height: 8px; border-radius: 50%; background: #23C343;
  box-shadow: 0 0 0 4px rgba(35, 195, 67, .22);
  animation: bd-pulse 2s ease-in-out infinite;
}
@keyframes bd-pulse {
  0%, 100% { box-shadow: 0 0 0 4px rgba(35, 195, 67, .22); }
  50% { box-shadow: 0 0 0 7px rgba(35, 195, 67, .08); }
}

/* ───── 右侧登录区 ───── */
.bd-pane {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 32px;
  background: var(--bd-fill-1);
}
.bd-card {
  width: 100%;
  max-width: 392px;
  background: #fff;
  border: 1px solid var(--bd-border);
  border-radius: var(--bd-radius);
  padding: 38px 40px 30px;
  box-shadow: 0 8px 40px rgba(20, 31, 74, .06);
}
.bd-card__mark {
  width: 48px; height: 48px; border-radius: 12px;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d));
  display: flex; align-items: center; justify-content: center;
  box-shadow: 0 4px 14px rgba(22, 93, 255, .35);
  margin-bottom: 22px;
}
.bd-card__h { font-size: 23px; font-weight: 700; color: var(--bd-t1); margin: 0 0 6px; letter-spacing: .3px; }
.bd-card__p { font-size: 13px; color: var(--bd-t3); margin: 0 0 24px; }
.bd-card__p b { color: var(--bd-t2); font-weight: 600; }

.bd-tip {
  display: flex; align-items: flex-start; gap: 8px;
  font-size: 12.5px; line-height: 1.55; padding: 10px 12px; border-radius: var(--bd-radius-s);
  margin-bottom: 18px;
}
.bd-tip :deep(.arco-icon) { font-size: 15px; flex: none; margin-top: 1px; }
.bd-tip--err { background: var(--bd-tag-red-bg); color: var(--bd-danger); }
.bd-tip--warn { background: var(--bd-tag-gold-bg); color: var(--bd-warning); }

/* passkey 提示卡 */
.bd-pk {
  display: flex; align-items: center; gap: 13px;
  padding: 14px 16px; margin-bottom: 18px;
  border: 1px solid var(--bd-border); border-radius: var(--bd-radius-s);
  background: var(--bd-fill-1);
}
.bd-pk__ic {
  width: 40px; height: 40px; border-radius: 10px; flex: none;
  background: var(--bd-tag-blue-bg); color: var(--bd-primary);
  display: flex; align-items: center; justify-content: center; font-size: 21px;
}
.bd-pk__t { display: flex; flex-direction: column; line-height: 1.45; min-width: 0; }
.bd-pk__t b { font-size: 13.5px; font-weight: 600; color: var(--bd-t1); }
.bd-pk__t i { font-style: normal; font-size: 12px; color: var(--bd-t3); margin-top: 3px; }

.bd-submit { margin-top: 6px; font-weight: 600; letter-spacing: 2px; }
.bd-back { margin-top: 10px; color: var(--bd-t3); }
.bd-back:hover { color: var(--bd-primary); }

.bd-demo {
  margin: 22px 0 0; padding-top: 18px; border-top: 1px solid var(--bd-fill-2);
  font-size: 11.5px; line-height: 1.7; color: var(--bd-t3);
}
.bd-demo code {
  background: var(--bd-fill-2); color: var(--bd-t2);
  padding: 1px 5px; border-radius: 4px; font-size: 11px;
}

.bd-getcli { margin: 14px 0 0; text-align: center; }
.bd-getcli__link {
  display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px;
  color: var(--bd-t3); text-decoration: none; transition: color .15s;
}
.bd-getcli__link:hover { color: var(--bd-primary); }

.bd-copy { margin-top: 26px; font-size: 12px; color: var(--bd-t4); }

@media (max-width: 880px) {
  .bd-brand { display: none; }
}

.bd-oidc__sep { display: flex; align-items: center; gap: 10px; margin: 18px 0 12px; color: var(--bd-t3); font-size: 12px; }
.bd-oidc__sep::before, .bd-oidc__sep::after { content: ''; flex: 1; height: 1px; background: var(--bd-line, rgba(0,0,0,.08)); }
.bd-oidc__btn { margin-bottom: 8px; }

.bd-dirkind { margin-left: 8px; font-size: 11px; color: var(--bd-t3); }
</style>
