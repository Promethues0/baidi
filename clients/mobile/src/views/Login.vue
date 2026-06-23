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
      <div v-if="needMfa" class="lg__f"><icon-message class="lg__ic" /><input v-model="form.mfaCode" placeholder="短信验证码" inputmode="numeric" @keyup.enter="submit" /></div>

      <div v-if="needMfa" class="lg__mfa">{{ mfaReason || '检测到未授信终端 / 异地登录，需短信二次认证' }}</div>
      <div v-if="err" class="lg__err">{{ err }}</div>

      <button class="m-btn" :disabled="loading" @click="submit">{{ loading ? '登录中…' : '登 录' }}</button>
      <div class="lg__demo">演示 <b>li.ming</b> / <b>baidi@123</b> · 外包账号 <b>ext.zhou</b> 触发验证码 <b>123456</b></div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue';
import { useRouter } from 'vue-router';
import { api, type PortalLoginResp } from '@/lib/api';
import { login } from '@/lib/store';

const router = useRouter();
const form = reactive({ username: 'li.ming', password: '', mfaCode: '' });
const needMfa = ref(false);
const mfaReason = ref('');
const err = ref('');
const loading = ref(false);

async function submit() {
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
    } else if (r.needMfa) {
      needMfa.value = true; mfaReason.value = r.reason || ''; err.value = '';
    } else {
      err.value = r.reason || '登录失败';
    }
  } catch { err.value = '无法连接控制中心（baidi-control）'; } finally { loading.value = false; }
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
