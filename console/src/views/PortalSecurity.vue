<template>
  <div class="bd-portal">
    <PortalBar title="白帝 · 我的安全" :user="displayName">
      <button class="bd-pquit" @click="router.push('/portal/apps')">
        <icon-apps /><span>返回应用</span>
      </button>
    </PortalBar>

    <main class="bd-pmain">
      <div class="bd-pwrap bd-pwrap--narrow">
        <div class="bd-phead">
          <div class="bd-phead__l">
            <h1 class="bd-phead__hi">二次认证</h1>
            <!-- ★读取失败 / 尚未读到时画「—」，不画 0 / 未启用：那两个值只有接口回来才有依据。
                 「passkey 0 个 · TOTP 未启用」在控制面 5xx 时与「用户确实没开二次认证」完全同形，
                 已启用 TOTP 的人会被告知自己没开，进而去重新注册——而重新注册会让正在用的密钥作废。 -->
            <p class="bd-phead__sub">
              <template v-if="credsErr || !loaded">passkey <b>—</b></template>
              <template v-else>passkey <b>{{ creds.length }}</b> 个</template>
              <span class="bd-dot">·</span>
              TOTP <b>{{ totpErr || !totpLoaded ? '—' : (totp.confirmed ? '已启用' : '未启用') }}</b>
              <span class="bd-dot">·</span>
              <span class="bd-sub2">任一注册后，登录即强制二次认证</span>
            </p>
          </div>
          <!-- enabled 来自 /webauthn/credentials 同一份应答：读不到它就判不出服务端配没配 WebAuthn -->
          <a-tag v-if="credsErr || !loaded" color="gray" bordered>
            {{ credsErr ? 'WebAuthn 状态未读取' : 'WebAuthn 状态读取中' }}
          </a-tag>
          <a-tag v-else :color="enabled ? 'green' : 'orange'" bordered>
            {{ enabled ? 'WebAuthn 已启用' : 'WebAuthn 未配置' }}
          </a-tag>
        </div>

        <!-- 读取失败：转述后端原话，并说清两个注册入口为什么停用。
             ★这条与下面两段 tone=danger 的空态是同一件事的两处呈现：这里给原因与重试，
             段内的空态负责把「未读取」与「没有注册 / 未启用」在版式上分开。 -->
        <div v-if="credsErr || totpErr" class="bd-notice bd-notice--danger" role="alert">
          <icon-exclamation-circle-fill />
          <div class="bd-notice__body">
            <b>二次认证状态未读取</b>
            <p class="bd-warnbox__p">
              <template v-if="credsErr">passkey 列表：{{ credsErr }}<br v-if="totpErr" /></template>
              <template v-if="totpErr">TOTP 状态：{{ totpErr }}</template>
              <br />下方显示的不是「没有注册 / 未启用」。
              重试成功之前「添加 passkey」与「启用 TOTP」已置灰：读不到当前状态时重新注册 TOTP，会让正在用的密钥立刻作废。
            </p>
          </div>
          <div class="bd-notice__right">
            <button class="bd-btn bd-btn--sm" :disabled="loading" @click="retry">重试</button>
          </div>
        </div>

        <!-- 未配置 RP 的说明（裸 IP 演示站会走到这里）。★读取失败时不画：enabled=false 那会儿只是没读到，不是「服务端未启用」 -->
        <div v-if="loaded && !credsErr && !enabled" class="bd-notice bd-notice--warn">
          <icon-exclamation-circle-fill />
          <div class="bd-notice__body">
            <b>服务端未启用 WebAuthn</b>
            <p class="bd-warnbox__p">
              passkey 需要服务端配置 <code>BAIDI_WEBAUTHN_RPID</code> /
              <code>BAIDI_WEBAUTHN_ORIGIN</code>，且 RP ID 必须是<b>可注册域名或 localhost</b>——
              浏览器规范不允许用裸 IP 作 RP ID。本站可改用下方的 <b>TOTP 动态口令</b>：
              它不依赖域名，是 IP 部署下的标准二次认证。
            </p>
          </div>
        </div>

        <!-- 两段各自分四态：骨架（接口没回来）/ 未读取（回了但失败）/ 确实没有 / 有。
             ★骨架与未读取按段分开而不共用一个标志：两个接口独立，/totp 慢半拍时 passkey 段不该陪着等，
             /totp 失败时 passkey 段也不该陪着红。「还没有注册」只在自己那段的接口成功回来后才画——那之前是一句没有依据的话。 -->
        <a-spin :loading="loading && loaded" class="bd-pspin">  <!-- 首屏由骨架承担，转圈只给之后的重载 / 重试 -->
          <div class="bd-psec">
            <div class="bd-psec__t">
              <icon-safe />我的 passkey
              <div class="bd-psec__spacer" />
              <button class="bd-btn" :disabled="!loaded || !!credsErr || !enabled || registering"
                :title="credsErr ? 'passkey 列表未读取，重试成功前不可添加' : undefined" @click="register">
                <icon-plus />{{ registering ? '请完成设备验证…' : '添加 passkey' }}
              </button>
            </div>

            <div v-if="!loaded" class="bd-card"><SkeletonBlock kind="card" :rows="2" /></div>

            <div v-else-if="credsErr" class="bd-card">
              <EmptyState size="md" tone="danger" title="passkey 列表未读取"
                :desc="`${credsErr}——这里显示的不是「没有注册」`" />
            </div>

            <div v-else-if="!creds.length && !loading" class="bd-card">
              <EmptyState size="md" title="还没有注册 passkey"
                desc="注册后，登录将使用 Touch ID / Windows Hello / 安全密钥完成抗钓鱼二次认证">
                <template #icon><icon-idcard /></template>
              </EmptyState>
            </div>

            <div v-else class="bd-clist">
              <div v-for="c in creds" :key="c.id" class="bd-card bd-ccard">
                <span class="bd-ccard__ic"><icon-idcard /></span>
                <div class="bd-ccard__m">
                  <div class="bd-ccard__name">{{ c.name || 'passkey' }}</div>
                  <div class="bd-ccard__meta bd-mono">
                    注册于 {{ c.createdAt }}
                    <template v-if="c.lastUsedAt"> · 最近使用 {{ c.lastUsedAt }}</template>
                  </div>
                </div>
                <span class="bd-tg bd-tg--purple">{{ transportLabel(c.transports) }}</span>
                <button class="bd-del" :disabled="creds.length <= 1" :title="creds.length <= 1 ? '不能删除最后一个 passkey' : '删除'"
                  :aria-label="`删除 passkey「${c.name || 'passkey'}」`" @click="remove(c)">
                  <icon-delete />
                </button>
              </div>
            </div>
          </div>

          <!-- TOTP 动态口令（RFC 6238）：与 passkey 并列的第二种真二因子 -->
          <div class="bd-psec">
            <div class="bd-psec__t">
              <icon-mobile />TOTP 动态口令
              <span v-if="totpLoaded && !totpErr && totp.confirmed" class="bd-tg bd-tg--green">已启用</span>
              <div class="bd-psec__spacer" />
              <!-- ★读不到状态时置灰而不是照常亮着：/totp/enroll 对已确认账号是 ON CONFLICT 覆盖 + confirmed=0，
                   一个已启用 TOTP 的用户在这里点一下「启用」，正在用的认证器当场作废，而页面此前全程零报错 -->
              <button v-if="!totp.confirmed && !setup" class="bd-btn" :disabled="!totpLoaded || !!totpErr"
                :title="totpErr ? 'TOTP 状态未读取，重试成功前不可注册' : undefined" @click="startTotp">
                <icon-plus />{{ totp.enrolled ? '重新注册' : '启用 TOTP' }}
              </button>
            </div>

            <!-- 注册面板排第一：密钥只回显这一次，enroll 之后那次 loadTotp 若失败也不能把面板顶掉 -->
            <div v-if="setup" class="bd-card bd-tsetup">
              <div class="bd-tsetup__qr"><img v-if="qrData" :src="qrData" alt="TOTP 注册二维码" /></div>
              <div class="bd-tsetup__m">
                <div class="bd-tsetup__step"><b>1.</b> 用认证器 App 扫码，或手动输入密钥：</div>
                <code class="bd-mono bd-tsetup__sec">{{ setup.secret }}</code>
                <div class="bd-tsetup__step"><b>2.</b> 输入 App 显示的 6 位验证码完成确认（确认前不生效）：</div>
                <div class="bd-tsetup__row">
                  <input v-model="confirmCode" class="bd-tinput bd-mono" maxlength="6" inputmode="numeric"
                    placeholder="000000" aria-label="6 位动态验证码" @keyup.enter="confirmTotp" />
                  <button class="bd-btn" :disabled="confirming" @click="confirmTotp">
                    {{ confirming ? '校验中…' : '确认启用' }}
                  </button>
                  <button class="bd-btn bd-btn--ghost" @click="cancelSetup">取消</button>
                </div>
                <div class="bd-tsetup__note">密钥只显示这一次；未完成确认可重新注册（旧密钥即作废）。</div>
              </div>
            </div>

            <div v-else-if="!totpLoaded" class="bd-card"><SkeletonBlock kind="card" :rows="2" /></div>

            <div v-else-if="totpErr" class="bd-card">
              <EmptyState size="md" tone="danger" title="TOTP 状态未读取"
                :desc="`${totpErr}——这里显示的不是「未启用」`" />
            </div>

            <!-- 空态 / 半截注册 -->
            <div v-else-if="!totp.confirmed" class="bd-card">
              <EmptyState size="md" :title="totp.enrolled ? '上次注册未完成确认' : '还没有启用 TOTP'"
                desc="RFC 6238 标准动态验证码，Google / 微软 Authenticator、1Password 等通用；不依赖域名，IP 部署也可用。启用后登录将强制要求 6 位动态验证码。">
                <template #icon><icon-mobile /></template>
              </EmptyState>
            </div>

            <!-- 已启用：解绑需出示当前验证码（拿到会话 ≠ 拿到认证器） -->
            <div v-else class="bd-clist">
              <div class="bd-card bd-ccard">
                <span class="bd-ccard__ic"><icon-mobile /></span>
                <div class="bd-ccard__m">
                  <div class="bd-ccard__name">TOTP 动态口令</div>
                  <div class="bd-ccard__meta bd-mono">
                    启用于 {{ totp.createdAt || '—' }} · 登录强制要求动态验证码
                  </div>
                </div>
                <template v-if="!disarming">
                  <button class="bd-del" title="解绑" aria-label="解绑 TOTP" @click="disarming = true"><icon-delete /></button>
                </template>
                <template v-else>
                  <input v-model="disableCode" class="bd-tinput bd-mono" maxlength="6" inputmode="numeric"
                    placeholder="当前验证码" aria-label="当前验证码" @keyup.enter="disableTotp" />
                  <button class="bd-btn" @click="disableTotp">确认解绑</button>
                  <button class="bd-btn bd-btn--ghost" @click="disarming = false; disableCode = ''">取消</button>
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
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import QRCode from 'qrcode';
import { api, type WebauthnCredentialsResp, type WebauthnCredential, type TotpStatus, type TotpEnrollResp, failReason, failStatus } from '@/lib/api';
import { createCredential, webauthnErrMsg, webauthnSupported } from '@/lib/webauthn';
import PortalBar from '@/components/PortalBar.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

const router = useRouter();
const loading = ref(false);
const registering = ref(false);
const enabled = ref(false);
const displayName = ref('');
const creds = ref<WebauthnCredential[]>([]);
/** 首屏是否已完成第一次 load()：只决定 passkey 段的骨架何时让位（成功 / 失败都算完成），不改任何数据流。 */
const loaded = ref(false);
/**
 * /webauthn/credentials 最近一次读取失败的后端原话；空 = 上次读取成功。
 * ★失败时 creds / enabled 会被清成 [] / false，但模板每一处都先看这个字段——那两个零值在失败态
 *   不是「没有注册 / 服务端未启用」，是「不知道」。此前 catch 里直接塌成零值且不留痕，控制面 5xx 与
 *   用户确实没开二次认证在这页上完全同形（复现：截图 repro-portal-security/portal-security-fail503）。
 */
const credsErr = ref('');

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
    credsErr.value = '';
  } catch (e) {
    // 读不到就说读不到（转述后端原话），不把上一次的好值留在页面上，也不断言「没有注册」。
    creds.value = [];
    enabled.value = false;
    credsErr.value = failReason(e);
  } finally {
    loading.value = false;
    loaded.value = true;
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
    if (failStatus(e) === 409) Message.error('该认证器已注册过');
    else if (failStatus(e) === 503) Message.error(failReason(e));
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
/** /totp 第一次回来（成功或失败）之前 TOTP 段画骨架——与 loaded 分开：两个接口独立，一个慢不该让另一个陪等。 */
const totpLoaded = ref(false);
/** /totp 最近一次读取失败的后端原话；空 = 上次读取成功。语义同 credsErr：失败态的 {enrolled:false,confirmed:false} 是「不知道」。 */
const totpErr = ref('');

async function loadTotp() {
  try {
    totp.value = await api<TotpStatus>('/totp');
    totpErr.value = '';
  } catch (e) {
    // ★不能塌成「未启用」：模板据此亮出「启用 TOTP」，而 enroll 对已确认账号是覆盖式的（旧密钥立刻作废）。
    totp.value = { enrolled: false, confirmed: false };
    totpErr.value = failReason(e);
  } finally {
    totpLoaded.value = true;
  }
}

/** 重试两个读取（都是幂等 GET）；成功后 credsErr / totpErr 清空，两个注册入口随之恢复。 */
function retry() {
  load();
  loadTotp();
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
  } catch (e) {
    Message.error(`生成密钥失败：${failReason(e)}`);
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
  } catch (e) {
    // ★不能一律断言"验证码不正确"：同一个失败也可能是**同一 30s 步长的码已被用过**
    //   （store.ConsumeTotpCounter 的防重放）、或者进门锁把这次尝试挡了。
    //   把三种原因说成同一种，用户会一遍遍重输一个其实没错的码。
    Message.error(`验证失败：${failReason(e)}`);
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
  } catch (e) {
    Message.error(`解绑失败：${failReason(e)}`);
  }
}

async function remove(c: WebauthnCredential) {
  try {
    await api(`/webauthn/credentials/${c.id}`, { method: 'DELETE' });
    Message.success(`已删除「${c.name || 'passkey'}」`);
    await load();
  } catch (e) {
    Message.error(`删除失败：${failReason(e)}`);
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
/* 本页独有：凭据卡 / TOTP 注册面板 / 验证码输入。门户壳在 PortalBar.vue；按钮 / 标签 / 提示条 / 空态 / 骨架是全局或共享件。 */
.bd-pspin { display: block; }
.bd-sub2 { font-size: var(--bd-fs-md); }
.bd-warnbox__p { margin: 6px 0 0; }

/* 凭据卡片 */
.bd-clist { display: flex; flex-direction: column; gap: var(--bd-sp-3); }
.bd-ccard { display: flex; align-items: center; gap: var(--bd-sp-4); padding: var(--bd-sp-4) var(--bd-sp-5); flex-wrap: wrap; }
.bd-ccard__ic {
  width: 42px; height: 42px; border-radius: var(--bd-radius); flex: none;
  background: var(--bd-tag-blue-bg); color: var(--bd-primary);
  display: flex; align-items: center; justify-content: center; font-size: 21px;
}
.bd-ccard__m { flex: 1; min-width: 0; }
.bd-ccard__name { font-size: var(--bd-fs-base); font-weight: 600; color: var(--bd-t1); }
.bd-ccard__meta { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin-top: var(--bd-sp-1); }

/* TOTP 注册面板 */
.bd-tsetup { display: flex; gap: var(--bd-sp-6); align-items: flex-start; padding: var(--bd-sp-5); flex-wrap: wrap; }
.bd-tsetup__qr {
  width: 168px; height: 168px; flex: none; border: 1px solid var(--bd-border); border-radius: var(--bd-radius);
  display: flex; align-items: center; justify-content: center; overflow: hidden; background: var(--bd-bg-1);
}
.bd-tsetup__qr img { width: 100%; height: 100%; display: block; }
.bd-tsetup__m { flex: 1; min-width: 240px; }
.bd-tsetup__step { font-size: var(--bd-fs-md); color: var(--bd-t2); margin-bottom: var(--bd-sp-2); line-height: var(--bd-lh); }
.bd-tsetup__step b { color: var(--bd-primary); }
.bd-tsetup__sec {
  display: block; background: var(--bd-fill-1); border: 1px dashed var(--bd-border);
  border-radius: var(--bd-radius-s); padding: var(--bd-sp-2) var(--bd-sp-3); margin-bottom: var(--bd-sp-4);
  font-size: var(--bd-fs-md); letter-spacing: 1px; word-break: break-all; color: var(--bd-t1);
}
.bd-tsetup__row { display: flex; gap: var(--bd-sp-2); align-items: center; flex-wrap: wrap; }
.bd-tsetup__note { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin-top: 10px; }
/* 6 位验证码输入：等宽、字距拉开 */
.bd-tinput {
  width: 130px; height: var(--bd-ctl-h-l); padding: 0 var(--bd-sp-3); border: 1px solid var(--bd-border);
  border-radius: var(--bd-radius-s); font-size: 15px; letter-spacing: 3px; outline: none; color: var(--bd-t1); background: var(--bd-bg-1);
  transition: border-color var(--bd-dur-fast) var(--bd-ease), box-shadow var(--bd-dur-base) var(--bd-ease);
}
.bd-tinput:focus { border-color: var(--bd-primary); box-shadow: var(--bd-focus-ring); }

/* 图标按钮：删除 / 解绑 */
.bd-del {
  width: var(--bd-ctl-h); height: var(--bd-ctl-h); flex: none; border: 1px solid var(--bd-border); background: var(--bd-bg-1);
  border-radius: var(--bd-radius-s); color: var(--bd-t3); cursor: pointer;
  transition: border-color var(--bd-dur-fast) var(--bd-ease), color var(--bd-dur-fast) var(--bd-ease);
  display: flex; align-items: center; justify-content: center;
}
.bd-del:hover:not(:disabled) { border-color: var(--bd-danger); color: var(--bd-danger); }
.bd-del:disabled { color: var(--bd-t4); cursor: not-allowed; opacity: .5; }
</style>
