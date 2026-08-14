<template>
  <div class="bd-login">
    <div class="bd-login__card">
      <div class="bd-login__brand">
        <span class="bd-login__mark">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
            <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </span>
        <div class="bd-login__title">白帝 · 零信任控制中心</div>
        <div class="bd-login__sub">ZTNA / SDP Control Center · 管理控制台</div>
      </div>

      <!-- 强制改密：初始口令须换掉才发正常会话 -->
      <template v-if="step === 'changepw'">
        <div class="bd-login__pk">
          <icon-lock />
          <span>账号 {{ username }} 正在使用初始口令，须修改后才能进入管理台</span>
        </div>
        <a-input-password v-model="newPw" size="large" placeholder="新口令（至少 8 位，不得与初始口令相同）" class="bd-login__inp" @keyup.enter="submitChangePw">
          <template #prefix><icon-lock /></template>
        </a-input-password>
        <a-input-password v-model="newPw2" size="large" placeholder="再次输入新口令" class="bd-login__inp" @keyup.enter="submitChangePw">
          <template #prefix><icon-lock /></template>
        </a-input-password>
        <div v-if="err" class="bd-login__err"><icon-exclamation-circle-fill /> {{ err }}</div>
        <a-button type="primary" size="large" long :loading="loading" class="bd-login__btn" @click="submitChangePw">修改并登录</a-button>
      </template>

      <template v-else>
        <a-input v-model="username" size="large" placeholder="管理员账号" class="bd-login__inp" @keyup.enter="submit">
          <template #prefix><icon-user /></template>
        </a-input>
        <a-input-password v-model="password" size="large" placeholder="登录口令" class="bd-login__inp" @keyup.enter="submit">
          <template #prefix><icon-lock /></template>
        </a-input-password>

        <div v-if="err" class="bd-login__err"><icon-exclamation-circle-fill /> {{ err }}</div>

        <!-- passkey 二次认证（口令已通过，等待认证器） -->
        <div v-if="step === 'webauthn'" class="bd-login__pk">
          <icon-fingerprint />
          <span>{{ pkMsg || '请用 Touch ID / Windows Hello / 安全密钥完成二次认证' }}</span>
        </div>

        <!-- TOTP 动态验证码（口令已通过，已启用 TOTP 的账号强制） -->
        <template v-if="step === 'totp'">
          <div class="bd-login__pk">
            <icon-mobile />
            <span>{{ pkMsg || '请输入认证器 App 中的 6 位动态验证码' }}</span>
          </div>
          <a-input v-model="totpCode" size="large" placeholder="6 位动态验证码" class="bd-login__inp"
            :max-length="6" @keyup.enter="submitTotp">
            <template #prefix><icon-safe /></template>
          </a-input>
        </template>

        <a-button
          v-if="step === 'webauthn'"
          type="primary" size="large" long :loading="loading" class="bd-login__btn"
          @click="submitWebauthn"
        >使用 passkey 验证</a-button>
        <a-button
          v-else-if="step === 'totp'"
          type="primary" size="large" long :loading="loading" class="bd-login__btn"
          @click="submitTotp"
        >验证并登录</a-button>
        <a-button v-else type="primary" size="large" long :loading="loading" class="bd-login__btn" @click="submit">登 录</a-button>
      </template>

      <div class="bd-login__hint">演示账号 <code>admin</code> · 口令 <code>baidi@123</code></div>
      <div class="bd-login__foot">终端用户请使用 <a @click="$router.push('/portal/login')">应用门户登录</a></div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { api, setToken, type PortalLoginResp } from '@/lib/api';
import { getAssertion, webauthnErrMsg, webauthnSupported } from '@/lib/webauthn';

const router = useRouter();
const username = ref('admin');
const password = ref('');
const loading = ref(false);
const err = ref('');
const step = ref<'login' | 'webauthn' | 'totp' | 'changepw'>('login');
const ticket = ref('');
const pkMsg = ref('');
const totpCode = ref('');
const pwToken = ref(''); // 首登强制改密的 15min 受限令牌（只够调 /auth/password，不入 localStorage）
const newPw = ref('');
const newPw2 = ref('');

/** 登录成功收尾：首登强制改密的受限令牌转入改密表单，正常会话令牌入库进管理台。 */
function finishLogin(r: PortalLoginResp): void {
  if (r.mustChangePassword && r.token) {
    pwToken.value = r.token;
    newPw.value = '';
    newPw2.value = '';
    err.value = '';
    step.value = 'changepw';
    return;
  }
  if (r.token) setToken(r.token);
  router.push('/');
}

async function submit() {
  if (!username.value || !password.value) { err.value = '请输入账号与口令'; return; }
  loading.value = true; err.value = '';
  try {
    const r = await api<PortalLoginResp>('/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username.value, password: password.value })
    });
    // 管理台同样过 passkey 二次因子（已注册 passkey 的 admin 强制断言）
    if (r.needWebauthn && r.ticket) {
      if (!webauthnSupported()) { err.value = '当前浏览器不支持 passkey'; return; }
      ticket.value = r.ticket;
      pkMsg.value = r.reason ?? '';
      step.value = 'webauthn';
      void submitWebauthn();
      return;
    }
    // TOTP 动态验证码（已启用 TOTP 的 admin 强制）
    if (r.needTotp && r.ticket) {
      ticket.value = r.ticket;
      pkMsg.value = r.reason ?? '';
      totpCode.value = '';
      step.value = 'totp';
      return;
    }
    if (r.needEnroll) { err.value = r.reason || '该账号须先注册 passkey 或 TOTP'; return; }
    if (r.ok && r.token) {
      finishLogin(r);
    } else {
      err.value = r.reason || '登录失败';
    }
  } catch {
    err.value = '无法连接控制中心（baidi-control）';
  } finally {
    loading.value = false;
  }
}

/** passkey 断言两回合，成功后换管理台会话令牌。 */
async function submitWebauthn() {
  if (!ticket.value) { step.value = 'login'; return; }
  loading.value = true; err.value = '';
  try {
    const opts = await api<{ publicKey: Record<string, never> }>('/webauthn/login/begin', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ticket: ticket.value })
    });
    const assertion = await getAssertion(opts as never);
    const r = await api<PortalLoginResp>('/webauthn/login/finish', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...assertion, ticket: ticket.value })
    });
    if (r.ok && r.token) {
      finishLogin(r);
      return;
    }
    pkMsg.value = r.reason || 'passkey 验证失败，请重试';
  } catch (e) {
    const msg = String((e as Error)?.message ?? '');
    if (msg.startsWith('401')) {
      err.value = '认证超时，请重新登录';
      step.value = 'login'; ticket.value = '';
    } else {
      pkMsg.value = webauthnErrMsg(e);
    }
  } finally {
    loading.value = false;
  }
}

/** TOTP 第二回合：mfa 票据 + 动态验证码换管理台会话令牌。 */
async function submitTotp() {
  if (!ticket.value) { step.value = 'login'; return; }
  if (!/^\d{6}$/.test(totpCode.value.trim())) { pkMsg.value = '请输入 6 位数字验证码'; return; }
  loading.value = true; err.value = '';
  try {
    const r = await api<PortalLoginResp>('/auth/totp', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ticket: ticket.value, code: totpCode.value.trim() })
    });
    if (r.ok && r.token) {
      finishLogin(r);
      return;
    }
    pkMsg.value = r.reason || '验证码不正确，请重试';
  } catch (e) {
    const msg = String((e as Error)?.message ?? '');
    if (msg.startsWith('401') && msg.includes('票据')) {
      err.value = '认证超时，请重新登录';
      step.value = 'login'; ticket.value = '';
    } else {
      pkMsg.value = '验证码不正确或已使用，请输入 App 当前显示的验证码';
    }
  } finally {
    loading.value = false;
  }
}

/** 首登强制改密：受限令牌调 /auth/password，成功后用新口令自动重新登录。 */
async function submitChangePw() {
  err.value = '';
  if (newPw.value.length < 8) { err.value = '新口令至少 8 位'; return; }
  if (newPw.value === password.value) { err.value = '新口令不得与初始口令相同'; return; }
  if (newPw.value !== newPw2.value) { err.value = '两次输入的新口令不一致'; return; }
  loading.value = true;
  try {
    const r = await api<{ ok: boolean; reason?: string }>('/auth/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pwToken.value}` },
      body: JSON.stringify({ old: password.value, new: newPw.value })
    });
    if (!r.ok) { err.value = r.reason || '口令修改失败，请重试'; return; }
    // 改密成功 → 用新口令自动重新登录换正常会话（有 passkey 的账号会再走一次断言）
    password.value = newPw.value;
    pwToken.value = '';
    step.value = 'login';
    await submit();
  } catch {
    err.value = '口令修改失败（受限令牌可能已过期，请刷新页面重新登录）';
  } finally {
    loading.value = false;
  }
}
</script>

<style scoped>
.bd-login {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: radial-gradient(1200px 600px at 50% -10%, #E8F3FF 0%, var(--bd-fill-1) 55%);
}
.bd-login__card {
  width: 380px; background: #fff; border: 1px solid var(--bd-border); border-radius: 14px;
  padding: 36px 32px 28px; box-shadow: 0 12px 40px rgba(22, 93, 255, .08);
}
.bd-login__brand { text-align: center; margin-bottom: 26px; }
.bd-login__mark {
  width: 46px; height: 46px; border-radius: 12px; display: inline-flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d)); box-shadow: 0 4px 12px rgba(22, 93, 255, .35);
}
.bd-login__title { font-size: 18px; font-weight: 700; margin-top: 14px; color: var(--bd-t1); }
.bd-login__sub { font-size: 12px; color: var(--bd-t3); margin-top: 5px; }
.bd-login__inp { margin-bottom: 14px; }
.bd-login__err { display: flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--bd-danger); margin: -4px 0 12px; }
.bd-login__pk {
  display: flex; align-items: center; gap: 9px; font-size: 12.5px; line-height: 1.6;
  color: var(--bd-t2); background: var(--bd-fill-1); border: 1px solid var(--bd-border);
  border-radius: var(--bd-radius-s); padding: 11px 13px; margin: 2px 0 14px;
}
.bd-login__pk :deep(.arco-icon) { font-size: 18px; color: var(--bd-primary); flex: none; }
.bd-login__btn { margin-top: 4px; height: 42px; font-size: 15px; letter-spacing: 4px; }
.bd-login__hint { text-align: center; font-size: 12px; color: var(--bd-t3); margin-top: 16px; }
.bd-login__hint code, .bd-login__foot a { color: var(--bd-primary); }
.bd-login__hint code { background: var(--bd-primary-1); padding: 1px 6px; border-radius: 4px; font-family: ui-monospace, monospace; }
.bd-login__foot { text-align: center; font-size: 12px; color: var(--bd-t3); margin-top: 10px; }
.bd-login__foot a { cursor: pointer; }
</style>
