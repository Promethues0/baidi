<template>
  <div class="lg">
    <div class="lg__brand">
      <div class="lg__logo"><icon-safe /></div>
      <div class="lg__name">白帝安全接入</div>
      <div class="lg__sub">ZTNA / SDP · 移动终端</div>
    </div>

    <div class="lg__form">
      <div class="lg__f"><icon-user class="lg__ic" /><input v-model="form.username" placeholder="企业账号" autocapitalize="off" autocorrect="off" /></div>
      <div class="lg__f"><icon-lock class="lg__ic" /><input v-model="form.password" type="password" placeholder="登录口令" @keyup.enter="submit" /></div>
      <div v-if="needMfa || needTotp" class="lg__f"><icon-message class="lg__ic" /><input v-model="form.mfaCode" :placeholder="needTotp ? '6 位动态验证码' : '验证码'" inputmode="numeric" maxlength="6" @keyup.enter="submit" /></div>

      <div v-if="needTotp" class="lg__mfa">{{ mfaReason || '该账号已启用 TOTP，请输入认证器 App 的动态验证码' }}</div>
      <div v-else-if="needMfa" class="lg__mfa">{{ mfaReason || '需要二次认证' }}</div>
      <div v-if="err" class="lg__err">{{ err }}</div>

      <button class="m-btn" :disabled="loading" @click="submit">{{ loading ? '登录中…' : '登 录' }}</button>
      <div class="lg__demo">演示 <b>li.fang</b> / <b>baidi@123</b> · passkey 二次认证请用浏览器门户</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue';
import { useRouter } from 'vue-router';
import { api, type PortalLoginResp } from '@/lib/api';
import { login } from '@/lib/store';

const router = useRouter();
const form = reactive({ username: 'li.fang', password: '', mfaCode: '' });
const needMfa = ref(false);
const needTotp = ref(false);
const totpTicket = ref(''); // 「口令已验」一次性票据（3min），TOTP 第二回合凭它绑定账号
const mfaReason = ref('');
const err = ref('');
const loading = ref(false);

async function submit() {
  if (needTotp.value) { await submitTotp(); return; }
  if (!form.username || !form.password) { err.value = '请输入账号与口令'; return; }
  loading.value = true; err.value = '';
  try {
    const r = await api<PortalLoginResp>('/portal/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: form.username, password: form.password, mfaCode: needMfa.value ? form.mfaCode : '' })
    });
    if (r.ok && r.token) {
      login(r.token, r.displayName || form.username);
      router.replace('/connect');
    } else if (r.needTotp && r.ticket) {
      needTotp.value = true; totpTicket.value = r.ticket; mfaReason.value = r.reason || ''; form.mfaCode = ''; err.value = '';
    } else if (r.needWebauthn) {
      err.value = '该账号已启用 passkey：移动客户端无法完成断言，请改用浏览器门户，或在门户「我的安全」改用 TOTP';
    } else if (r.needMfa) {
      needMfa.value = true; mfaReason.value = r.reason || ''; err.value = '';
    } else {
      err.value = r.reason || '登录失败';
    }
  } catch { err.value = '无法连接控制中心（baidi-control）'; } finally { loading.value = false; }
}

/** TOTP 第二回合：票据 + 动态验证码换会话令牌（同码只能成功一次）。 */
async function submitTotp() {
  if (!/^\d{6}$/.test(form.mfaCode.trim())) { err.value = '请输入 6 位数字验证码'; return; }
  loading.value = true; err.value = '';
  try {
    const r = await api<PortalLoginResp>('/auth/totp', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ticket: totpTicket.value, code: form.mfaCode.trim() })
    });
    if (r.ok && r.token) {
      login(r.token, r.displayName || form.username);
      router.replace('/connect');
    } else { err.value = r.reason || '验证码不正确或已使用'; }
  } catch {
    err.value = '验证码不正确或已使用；若停留过久请返回重新登录';
  } finally { loading.value = false; }
}
</script>

<style scoped>
.lg { min-height: 100%; display: flex; flex-direction: column; justify-content: center; padding: 0 26px;
  background: linear-gradient(180deg, #F2F7FF 0%, var(--bd-fill-1) 60%); }
.lg__brand { text-align: center; margin-bottom: 34px; }
.lg__logo { width: 60px; height: 60px; margin: 0 auto 14px; border-radius: 16px; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d)); color: #fff; font-size: 30px;
  box-shadow: 0 8px 22px rgba(22, 93, 255, 0.32); }
.lg__name { font-size: 23px; font-weight: 800; color: var(--bd-t1); letter-spacing: 1px; }
.lg__sub { font-size: 12px; color: var(--bd-t3); margin-top: 5px; }
.lg__f { display: flex; align-items: center; gap: 10px; height: 50px; padding: 0 14px; margin-bottom: 12px;
  background: #fff; border: 1px solid var(--bd-border); border-radius: 12px; }
.lg__ic { color: var(--bd-t3); font-size: 18px; flex: none; }
.lg__f input { flex: 1; border: none; outline: none; background: transparent; font-size: 15px; color: var(--bd-t1); min-width: 0; }
.lg__mfa { font-size: 12px; color: var(--bd-warning); margin: -4px 2px 12px; }
.lg__err { font-size: 13px; color: var(--bd-danger); margin: -4px 2px 12px; }
.lg__demo { text-align: center; font-size: 11px; color: var(--bd-t3); margin-top: 16px; line-height: 1.7; }
.lg__demo b { color: var(--bd-primary); font-weight: 600; }
</style>
