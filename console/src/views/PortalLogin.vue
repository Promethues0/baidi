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
            <span class="bd-sell__t"><b>业务对未授权者隐身</b><i>公网暴露端口 0 · SPA 单包敲门</i></span>
          </li>
          <li>
            <span class="bd-sell__ic"><icon-common /></span>
            <span class="bd-sell__t"><b>免客户端 · 跨平台跨浏览器</b><i>B/S 直达，无需安装任何代理</i></span>
          </li>
        </ul>
      </div>

      <div class="bd-brand__foot">
        <span class="bd-stealth"><span class="bd-stealth__dot" />服务隐身中 · 先认证后连接</span>
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
        </template>

        <!-- 步骤二：二次认证 -->
        <template v-else>
          <h2 class="bd-card__h">二次认证</h2>
          <p class="bd-card__p">为账号 <b>{{ form.username }}</b> 完成短信验证</p>

          <div class="bd-tip bd-tip--warn">
            <icon-exclamation-circle-fill />
            <span>{{ mfaReason || '检测到风险，需短信验证码二次确认身份。' }}</span>
          </div>

          <a-form :model="form" layout="vertical" @submit.prevent>
            <a-form-item field="mfaCode" hide-label>
              <a-input
                v-model="form.mfaCode"
                placeholder="短信验证码"
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
          演示提示：口令 <code class="bd-mono">baidi@123</code>；外包 / 未授信账号（如
          <code class="bd-mono">ext.zhou</code>）将触发短信验证码 <code class="bd-mono">123456</code>。
        </p>
      </div>

      <p class="bd-copy">白帝零信任 · ZTNA / SDP Control Center</p>
    </main>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue';
import { useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { api, setToken, type PortalLoginResp } from '@/lib/api';

const router = useRouter();

const step = ref<'login' | 'mfa'>('login');
const loading = ref(false);
const errMsg = ref('');
const mfaReason = ref('');

const form = reactive({ username: '', password: '', mfaCode: '' });

function onSuccess(resp: PortalLoginResp) {
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
  try {
    return await api<PortalLoginResp>('/portal/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  } catch {
    errMsg.value = '网络异常或服务不可达，请稍后重试。';
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

async function submitMfa() {
  errMsg.value = '';
  if (!form.mfaCode.trim()) {
    Message.warning('请输入短信验证码。');
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

function backToLogin() {
  step.value = 'login';
  errMsg.value = '';
  mfaReason.value = '';
  form.mfaCode = '';
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

.bd-copy { margin-top: 26px; font-size: 12px; color: var(--bd-t4); }

@media (max-width: 880px) {
  .bd-brand { display: none; }
}
</style>
