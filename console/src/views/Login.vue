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

      <a-input v-model="username" size="large" placeholder="管理员账号" class="bd-login__inp" @keyup.enter="submit">
        <template #prefix><icon-user /></template>
      </a-input>
      <a-input-password v-model="password" size="large" placeholder="登录口令" class="bd-login__inp" @keyup.enter="submit">
        <template #prefix><icon-lock /></template>
      </a-input-password>

      <div v-if="err" class="bd-login__err"><icon-exclamation-circle-fill /> {{ err }}</div>

      <a-button type="primary" size="large" long :loading="loading" class="bd-login__btn" @click="submit">登 录</a-button>

      <div class="bd-login__hint">演示账号 <code>admin</code> · 口令 <code>baidi@123</code></div>
      <div class="bd-login__foot">终端用户请使用 <a @click="$router.push('/portal/login')">应用门户登录</a></div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { api, setToken, type PortalLoginResp } from '@/lib/api';

const router = useRouter();
const username = ref('admin');
const password = ref('');
const loading = ref(false);
const err = ref('');

async function submit() {
  if (!username.value || !password.value) { err.value = '请输入账号与口令'; return; }
  loading.value = true; err.value = '';
  try {
    const r = await api<PortalLoginResp & { role?: string }>('/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username.value, password: password.value })
    });
    if (r.ok && r.token) {
      setToken(r.token);
      router.push('/');
    } else {
      err.value = r.reason || '登录失败';
    }
  } catch {
    err.value = '无法连接控制中心（baidi-control）';
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
.bd-login__btn { margin-top: 4px; height: 42px; font-size: 15px; letter-spacing: 4px; }
.bd-login__hint { text-align: center; font-size: 12px; color: var(--bd-t3); margin-top: 16px; }
.bd-login__hint code, .bd-login__foot a { color: var(--bd-primary); }
.bd-login__hint code { background: var(--bd-primary-1); padding: 1px 6px; border-radius: 4px; font-family: ui-monospace, monospace; }
.bd-login__foot { text-align: center; font-size: 12px; color: var(--bd-t3); margin-top: 10px; }
.bd-login__foot a { cursor: pointer; }
</style>
