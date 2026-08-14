<template>
  <div class="bd-portal">
    <PortalBar title="白帝 · 我的安全">
      <button class="bd-pquit" @click="router.push('/portal/apps')">
        <icon-apps /><span>返回应用</span>
      </button>
      <div class="bd-pacct">
        <span class="bd-pacct__av">{{ avatarText }}</span>
        <span class="bd-pacct__name">{{ displayName }}</span>
      </div>
    </PortalBar>

    <main class="bd-pmain">
      <div class="bd-pwrap">
        <div class="bd-phead">
          <div class="bd-phead__l">
            <h1 class="bd-phead__hi">二次认证</h1>
            <p class="bd-phead__sub">
              passkey <b>{{ creds.length }}</b> 个
              <span class="bd-dot">·</span>
              TOTP <b>{{ totp.confirmed ? '已启用' : '未启用' }}</b>
              <span class="bd-dot">·</span>
              <span class="bd-sub2">任一注册后，登录即强制二次认证</span>
            </p>
          </div>
          <a-tag :color="enabled ? 'green' : 'orange'" bordered>
            {{ enabled ? 'WebAuthn 已启用' : 'WebAuthn 未配置' }}
          </a-tag>
        </div>

        <!-- 未配置 RP 的说明（裸 IP 演示站会走到这里） -->
        <div v-if="!enabled && !loading" class="bd-warnbox">
          <icon-exclamation-circle-fill class="bd-warnbox__ic" />
          <div>
            <b>服务端未启用 WebAuthn</b>
            <p>
              passkey 需要服务端配置 <code>BAIDI_WEBAUTHN_RPID</code> /
              <code>BAIDI_WEBAUTHN_ORIGIN</code>，且 RP ID 必须是<b>可注册域名或 localhost</b>——
              浏览器规范不允许用裸 IP 作 RP ID。本站可改用下方的 <b>TOTP 动态口令</b>：
              它不依赖域名，是 IP 部署下的标准二次认证。
            </p>
          </div>
        </div>

        <a-spin :loading="loading" style="display:block">
          <div class="bd-sec">
            <div class="bd-sec__t">
              <icon-safe />我的 passkey
              <div style="flex:1" />
              <button class="bd-addbtn" :disabled="!enabled || registering" @click="register">
                <icon-plus />{{ registering ? '请完成设备验证…' : '添加 passkey' }}
              </button>
            </div>

            <div v-if="!creds.length && !loading" class="bd-empty">
              <icon-fingerprint class="bd-empty__ic" />
              <div class="bd-empty__t">还没有注册 passkey</div>
              <div class="bd-empty__s">
                注册后，登录将使用 Touch ID / Windows Hello / 安全密钥完成抗钓鱼二次认证
              </div>
            </div>

            <div v-else class="bd-clist">
              <div v-for="c in creds" :key="c.id" class="bd-ccard">
                <span class="bd-ccard__ic"><icon-fingerprint /></span>
                <div class="bd-ccard__m">
                  <div class="bd-ccard__name">{{ c.name || 'passkey' }}</div>
                  <div class="bd-ccard__meta bd-mono">
                    注册于 {{ c.createdAt }}
                    <template v-if="c.lastUsedAt"> · 最近使用 {{ c.lastUsedAt }}</template>
                  </div>
                </div>
                <span class="bd-ccard__tag">{{ transportLabel(c.transports) }}</span>
                <button class="bd-del" :disabled="creds.length <= 1" :title="creds.length <= 1 ? '不能删除最后一个 passkey' : '删除'" @click="remove(c)">
                  <icon-delete />
                </button>
              </div>
            </div>
          </div>

          <!-- TOTP 动态口令（RFC 6238）：与 passkey 并列的第二种真二因子 -->
          <div class="bd-sec">
            <div class="bd-sec__t">
              <icon-mobile />TOTP 动态口令
              <a-tag v-if="totp.confirmed" color="green" size="small" bordered>已启用</a-tag>
              <div style="flex:1" />
              <button v-if="!totp.confirmed && !setup" class="bd-addbtn" @click="startTotp">
                <icon-plus />{{ totp.enrolled ? '重新注册' : '启用 TOTP' }}
              </button>
            </div>

            <!-- 空态 / 半截注册 -->
            <div v-if="!totp.confirmed && !setup" class="bd-empty">
              <icon-mobile class="bd-empty__ic" />
              <div class="bd-empty__t">{{ totp.enrolled ? '上次注册未完成确认' : '还没有启用 TOTP' }}</div>
              <div class="bd-empty__s">
                RFC 6238 标准动态验证码，Google / 微软 Authenticator、1Password 等通用；
                不依赖域名，IP 部署也可用。启用后登录将强制要求 6 位动态验证码。
              </div>
            </div>

            <!-- 注册面板：扫码或手输密钥 → 验证码确认（密钥只显示这一次） -->
            <div v-else-if="setup" class="bd-tsetup">
              <div class="bd-tsetup__qr"><img v-if="qrData" :src="qrData" alt="TOTP 注册二维码" /></div>
              <div class="bd-tsetup__m">
                <div class="bd-tsetup__step"><b>1.</b> 用认证器 App 扫码，或手动输入密钥：</div>
                <code class="bd-mono bd-tsetup__sec">{{ setup.secret }}</code>
                <div class="bd-tsetup__step"><b>2.</b> 输入 App 显示的 6 位验证码完成确认（确认前不生效）：</div>
                <div class="bd-tsetup__row">
                  <input v-model="confirmCode" class="bd-tinput bd-mono" maxlength="6" inputmode="numeric"
                    placeholder="000000" @keyup.enter="confirmTotp" />
                  <button class="bd-addbtn" :disabled="confirming" @click="confirmTotp">
                    {{ confirming ? '校验中…' : '确认启用' }}
                  </button>
                  <button class="bd-cancelbtn" @click="cancelSetup">取消</button>
                </div>
                <div class="bd-tsetup__note">密钥只显示这一次；未完成确认可重新注册（旧密钥即作废）。</div>
              </div>
            </div>

            <!-- 已启用：解绑需出示当前验证码（拿到会话 ≠ 拿到认证器） -->
            <div v-else class="bd-clist">
              <div class="bd-ccard">
                <span class="bd-ccard__ic"><icon-mobile /></span>
                <div class="bd-ccard__m">
                  <div class="bd-ccard__name">TOTP 动态口令</div>
                  <div class="bd-ccard__meta bd-mono">
                    启用于 {{ totp.createdAt || '—' }} · 登录强制要求动态验证码
                  </div>
                </div>
                <template v-if="!disarming">
                  <button class="bd-del" title="解绑" @click="disarming = true"><icon-delete /></button>
                </template>
                <template v-else>
                  <input v-model="disableCode" class="bd-tinput bd-mono" maxlength="6" inputmode="numeric"
                    placeholder="当前验证码" @keyup.enter="disableTotp" />
                  <button class="bd-addbtn" @click="disableTotp">确认解绑</button>
                  <button class="bd-cancelbtn" @click="disarming = false; disableCode = ''">取消</button>
                </template>
              </div>
            </div>
          </div>
        </a-spin>
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import QRCode from 'qrcode';
import { api, type WebauthnCredentialsResp, type WebauthnCredential, type TotpStatus, type TotpEnrollResp } from '@/lib/api';
import { createCredential, webauthnErrMsg, webauthnSupported } from '@/lib/webauthn';
import PortalBar from '@/components/PortalBar.vue';

const router = useRouter();
const loading = ref(false);
const registering = ref(false);
const enabled = ref(false);
const displayName = ref('');
const creds = ref<WebauthnCredential[]>([]);

const avatarText = computed(() => (displayName.value || '·').slice(0, 1).toUpperCase());

function transportLabel(raw: string): string {
  try {
    const ts = JSON.parse(raw || '[]') as string[];
    const zh: Record<string, string> = {
      internal: '平台内置', usb: 'USB', nfc: 'NFC', ble: '蓝牙', hybrid: '跨设备'
    };
    return ts.map((t) => zh[t] ?? t).join(' / ') || '未知';
  } catch {
    return '未知';
  }
}

async function load() {
  loading.value = true;
  try {
    const resp = await api<WebauthnCredentialsResp>('/webauthn/credentials');
    creds.value = resp.credentials ?? [];
    enabled.value = !!resp.enabled;
  } catch {
    // 降级：无后端时页面完整可点，不白屏
    creds.value = [];
    enabled.value = false;
  } finally {
    loading.value = false;
  }
}

async function register() {
  if (!webauthnSupported()) {
    Message.error('当前浏览器不支持 passkey');
    return;
  }
  registering.value = true;
  try {
    const opts = await api<{ publicKey: Record<string, never> }>('/webauthn/register/begin', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
    });
    const att = await createCredential(opts as never);
    const name = guessName();
    await api('/webauthn/register/finish', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...att, name })
    });
    Message.success(`passkey「${name}」注册成功，下次登录将用它完成二次认证`);
    await load();
  } catch (e) {
    const msg = String((e as Error)?.message ?? '');
    if (msg.startsWith('409')) Message.error('该认证器已注册过');
    else if (msg.startsWith('503')) Message.error('服务端未配置 WebAuthn');
    else Message.error(webauthnErrMsg(e));
  } finally {
    registering.value = false;
  }
}

/** 按平台猜一个可读别名，省去让用户命名。 */
function guessName(): string {
  const ua = navigator.userAgent;
  if (/Mac/i.test(ua)) return 'Touch ID (macOS)';
  if (/Windows/i.test(ua)) return 'Windows Hello';
  if (/Android/i.test(ua)) return 'Android 设备';
  if (/iPhone|iPad/i.test(ua)) return 'iOS 设备';
  return 'passkey';
}

/* ── TOTP 动态口令 ── */
const totp = ref<TotpStatus>({ enrolled: false, confirmed: false });
const setup = ref<TotpEnrollResp | null>(null); // 密钥只存在于本次会话内存，刷新即不可再见
const qrData = ref('');
const confirmCode = ref('');
const confirming = ref(false);
const disarming = ref(false);
const disableCode = ref('');

async function loadTotp() {
  try {
    totp.value = await api<TotpStatus>('/totp');
  } catch {
    totp.value = { enrolled: false, confirmed: false };
  }
}

async function startTotp() {
  try {
    const r = await api<TotpEnrollResp>('/totp/enroll', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
    });
    setup.value = r;
    confirmCode.value = '';
    qrData.value = await QRCode.toDataURL(r.uri, { width: 168, margin: 1 });
    await loadTotp();
  } catch {
    Message.error('生成密钥失败');
  }
}

async function confirmTotp() {
  if (!/^\d{6}$/.test(confirmCode.value.trim())) {
    Message.error('请输入 6 位数字验证码');
    return;
  }
  confirming.value = true;
  try {
    await api('/totp/confirm', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: confirmCode.value.trim() })
    });
    Message.success('TOTP 已启用，下次登录将要求动态验证码');
    setup.value = null;
    qrData.value = '';
    await loadTotp();
  } catch {
    Message.error('验证码不正确，请确认扫码 / 录入无误后重试');
  } finally {
    confirming.value = false;
  }
}

function cancelSetup() {
  setup.value = null;
  qrData.value = '';
  confirmCode.value = '';
}

async function disableTotp() {
  try {
    await api('/totp/disable', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: disableCode.value.trim() })
    });
    Message.success('TOTP 已解绑');
    disarming.value = false;
    disableCode.value = '';
    await loadTotp();
  } catch {
    Message.error('解绑失败：请输入认证器 App 当前显示的验证码');
  }
}

async function remove(c: WebauthnCredential) {
  try {
    await api(`/webauthn/credentials/${c.id}`, { method: 'DELETE' });
    Message.success(`已删除「${c.name || 'passkey'}」`);
    await load();
  } catch (e) {
    const msg = String((e as Error)?.message ?? '');
    Message.error(msg.startsWith('409') ? '不能删除最后一个 passkey' : '删除失败');
  }
}

onMounted(() => {
  const raw = sessionStorage.getItem('baidi_portal');
  if (!raw) { router.replace('/portal/login'); return; }
  try {
    const s = JSON.parse(raw) as { displayName?: string };
    if (!s.displayName) { router.replace('/portal/login'); return; }
    displayName.value = s.displayName;
  } catch { router.replace('/portal/login'); return; }
  load();
  loadTotp();
});
</script>

<style scoped>
.bd-portal { min-height: 100vh; background: var(--bd-fill-1); display: flex; flex-direction: column; }
.bd-pacct { display: flex; align-items: center; gap: 9px; }
.bd-pacct__av {
  width: 30px; height: 30px; border-radius: 50%; flex: none; color: #fff; font-size: 13px; font-weight: 600;
  background: linear-gradient(135deg, var(--bd-purple), var(--bd-primary));
  display: flex; align-items: center; justify-content: center;
}
.bd-pacct__name { font-size: 13px; font-weight: 600; color: var(--bd-t1); }
.bd-pquit {
  display: inline-flex; align-items: center; gap: 6px; height: 32px; padding: 0 12px;
  border: 1px solid var(--bd-border); background: #fff; border-radius: 7px; cursor: pointer;
  font-size: 13px; color: var(--bd-t2); transition: all .15s;
}
.bd-pquit:hover { border-color: var(--bd-primary); color: var(--bd-primary); }

.bd-pmain { flex: 1; padding: 40px 24px 64px; }
.bd-pwrap { max-width: 900px; margin: 0 auto; }
.bd-phead { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; margin-bottom: 24px; flex-wrap: wrap; }
.bd-phead__hi { margin: 0; font-size: 26px; font-weight: 700; color: var(--bd-t1); letter-spacing: .3px; }
.bd-phead__sub { margin: 8px 0 0; font-size: 14px; color: var(--bd-t3); }
.bd-phead__sub b { color: var(--bd-primary); font-weight: 700; font-size: 15px; }
.bd-phead__sub .bd-dot { margin: 0 8px; color: var(--bd-t4); }
.bd-sub2 { font-size: 13px; }

/* 未配置提示 */
.bd-warnbox {
  display: flex; gap: 12px; padding: 16px 18px; margin-bottom: 24px;
  background: var(--bd-tag-gold-bg); border-radius: var(--bd-radius);
  font-size: 13px; line-height: 1.7; color: var(--bd-t2);
}
.bd-warnbox__ic { color: var(--bd-warning); font-size: 20px; flex: none; margin-top: 2px; }
.bd-warnbox b { color: var(--bd-t1); }
.bd-warnbox p { margin: 6px 0 0; }
.bd-warnbox code {
  background: rgba(0, 0, 0, .05); padding: 1px 5px; border-radius: 4px;
  font-family: ui-monospace, monospace; font-size: 12px;
}

.bd-sec { margin-bottom: 30px; }
.bd-sec__t { display: flex; align-items: center; gap: 8px; font-size: 15px; font-weight: 600; color: var(--bd-t1); margin-bottom: 14px; }
.bd-addbtn {
  display: inline-flex; align-items: center; gap: 6px; height: 34px; padding: 0 14px;
  border: none; border-radius: 8px; background: var(--bd-primary); color: #fff;
  font-size: 13px; font-weight: 500; cursor: pointer; transition: background .15s;
  box-shadow: 0 2px 6px rgba(22, 93, 255, .25);
}
.bd-addbtn:hover:not(:disabled) { background: var(--bd-primary-h); }
.bd-addbtn:disabled { background: var(--bd-fill-3); color: var(--bd-t4); cursor: not-allowed; box-shadow: none; }

/* 凭据卡片 */
.bd-clist { display: flex; flex-direction: column; gap: 12px; }
.bd-ccard {
  display: flex; align-items: center; gap: 14px;
  background: #fff; border: 1px solid var(--bd-border); border-radius: var(--bd-radius);
  padding: 16px 18px;
}
.bd-ccard__ic {
  width: 42px; height: 42px; border-radius: 11px; flex: none;
  background: var(--bd-tag-blue-bg); color: var(--bd-primary);
  display: flex; align-items: center; justify-content: center; font-size: 21px;
}
.bd-ccard__m { flex: 1; min-width: 0; }
.bd-ccard__name { font-size: 14.5px; font-weight: 600; color: var(--bd-t1); }
.bd-ccard__meta { font-size: 12px; color: var(--bd-t3); margin-top: 4px; }
.bd-ccard__tag {
  font-size: 11.5px; font-weight: 500; color: var(--bd-purple);
  background: var(--bd-tag-purple-bg); padding: 4px 10px; border-radius: 6px; white-space: nowrap;
}
/* TOTP 注册面板 */
.bd-tsetup {
  display: flex; gap: 22px; align-items: flex-start;
  background: #fff; border: 1px solid var(--bd-border); border-radius: var(--bd-radius);
  padding: 20px 22px;
}
.bd-tsetup__qr {
  width: 168px; height: 168px; flex: none; border: 1px solid var(--bd-border); border-radius: 10px;
  display: flex; align-items: center; justify-content: center; overflow: hidden; background: #fff;
}
.bd-tsetup__qr img { width: 100%; height: 100%; display: block; }
.bd-tsetup__m { flex: 1; min-width: 0; }
.bd-tsetup__step { font-size: 13px; color: var(--bd-t2); margin-bottom: 8px; line-height: 1.6; }
.bd-tsetup__step b { color: var(--bd-primary); }
.bd-tsetup__sec {
  display: block; background: var(--bd-fill-1); border: 1px dashed var(--bd-border);
  border-radius: 8px; padding: 8px 12px; margin-bottom: 14px;
  font-size: 13px; letter-spacing: 1px; word-break: break-all; color: var(--bd-t1);
}
.bd-tsetup__row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.bd-tsetup__note { font-size: 12px; color: var(--bd-t3); margin-top: 10px; }
.bd-tinput {
  width: 130px; height: 34px; padding: 0 12px; border: 1px solid var(--bd-border);
  border-radius: 8px; font-size: 15px; letter-spacing: 3px; outline: none; color: var(--bd-t1);
}
.bd-tinput:focus { border-color: var(--bd-primary); }
.bd-cancelbtn {
  height: 34px; padding: 0 14px; border: 1px solid var(--bd-border); background: #fff;
  border-radius: 8px; font-size: 13px; color: var(--bd-t2); cursor: pointer; transition: all .15s;
}
.bd-cancelbtn:hover { border-color: var(--bd-primary); color: var(--bd-primary); }

.bd-del {
  width: 32px; height: 32px; flex: none; border: 1px solid var(--bd-border); background: #fff;
  border-radius: 7px; color: var(--bd-t3); cursor: pointer; transition: all .15s;
  display: flex; align-items: center; justify-content: center;
}
.bd-del:hover:not(:disabled) { border-color: var(--bd-danger); color: var(--bd-danger); }
.bd-del:disabled { color: var(--bd-t4); cursor: not-allowed; opacity: .5; }

.bd-empty { text-align: center; padding: 56px 20px; background: #fff; border: 1px solid var(--bd-border); border-radius: var(--bd-radius); }
.bd-empty__ic { font-size: 48px; color: var(--bd-t4); }
.bd-empty__t { margin-top: 14px; font-size: 15px; font-weight: 600; color: var(--bd-t2); }
.bd-empty__s { margin-top: 6px; font-size: 13px; color: var(--bd-t3); }
.bd-mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
