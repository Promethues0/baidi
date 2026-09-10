<template>
  <div class="lg">
    <div class="lg__brand">
      <div class="lg__logo"><icon-safe /></div>
      <div class="lg__name">白帝安全接入</div>
      <div class="lg__sub">ZTNA / SDP · 移动终端</div>
    </div>

    <!--
      首登强制改密（FR-DEPLOY-09）。整块与登录表单互斥：服务端 mustChangeLogin 回的
      ok=true + token 是一张 15min 受限令牌（Use=pwreset），只够调 POST /auth/password，
      拿它进主界面的话应用列表与接入会逐个 403、而界面上一句解释也没有。
      ★端内改密而不是"请去浏览器门户"：受限令牌本来就能调那个端点，而这台手机
      很可能正是因为还没接入才打不开门户。
    -->
    <div v-if="needPwChange" class="lg__form">
      <div class="lg__mustpw">{{ pwReason }}</div>
      <div class="lg__f"><icon-lock class="lg__ic" /><input v-model="pwForm.pw" type="password" placeholder="新口令" @keyup.enter="submitPwChange" /></div>
      <div class="lg__f"><icon-lock class="lg__ic" /><input v-model="pwForm.pw2" type="password" placeholder="再次输入新口令" @keyup.enter="submitPwChange" /></div>
      <div class="lg__rule">{{ PW_RULE_HINT }}</div>
      <div v-if="err" class="lg__err">{{ err }}</div>
      <button class="m-btn" :disabled="loading" @click="submitPwChange">{{ loading ? '提交中…' : '修改并登录' }}</button>
      <button class="lg__back" :disabled="loading" @click="backToLogin">返回重新登录</button>
    </div>

    <div v-else class="lg__form">
      <!-- 认证域：只有配了 ≥2 个外部认证源时才出现（GET /auth/domains 在单源时回空）。
           ★它不是"多一个可选项"——不选的话服务端**拒绝登录**，因为挨个去问等于把
           明文口令投递给排在前面的每一台目录服务器（wave8 行动 12 的核心不变式：
           一次登录只把口令交给一台服务器）。此前移动端没有这个控件，服务端那句
           「请先选择你所属的认证域」只能原样显示成一条错误，而用户**无处可选**——
           任何接了两个及以上外部源的部署，移动端外部目录账号 100% 登不进去。
           本地账号仍能登录（登录链路先查本地哈希），所以管理员自己在手机上试不出来。 -->
      <div v-if="domains.length" class="lg__f">
        <icon-apps class="lg__ic" />
        <select v-model="form.directory" class="lg__sel">
          <option value="">选择你所属的认证域</option>
          <option v-for="d in domains" :key="d.id" :value="d.id">{{ d.name }}（{{ d.kind.toUpperCase() }}）</option>
        </select>
      </div>
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
import { ref, reactive, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { api, failReason, failStatus, type PortalLoginResp, type AuthDomainOption } from '@/lib/api';
import { PW_RULE_HINT, checkNewPassword } from '@/lib/pwchange';
import { login } from '@/lib/store';

const router = useRouter();
const form = reactive({ username: 'li.fang', password: '', mfaCode: '', directory: '' });
/** 可选认证域（只在 ≥2 个外部源时非空）。取不到不阻断登录——单源部署本来就该是空的。 */
const domains = ref<AuthDomainOption[]>([]);
async function loadDomains() {
  try {
    const r = await api<{ domains?: AuthDomainOption[] }>('/auth/domains');
    domains.value = r.domains ?? [];
  } catch { domains.value = []; }
}
onMounted(loadDomains);
const needMfa = ref(false);
const needTotp = ref(false);
const totpTicket = ref(''); // 「口令已验」一次性票据（3min），TOTP 第二回合凭它绑定账号
const mfaReason = ref('');
const err = ref('');
const loading = ref(false);

/* ── 首登强制改密（FR-DEPLOY-09）────────────────────────────────────────────
 * ★受限令牌**不写进 session**（不入 localStorage）：写进去 authed() 立刻为真、
 *   路由守卫放行进主界面，然后应用列表与接入逐个 403——那正是要修掉的形态。
 *   它只活在这个 ref 里，改密成功即丢弃。
 */
const needPwChange = ref(false);
const pwToken = ref('');
const pwReason = ref('');
const pwForm = reactive({ pw: '', pw2: '' });

/** 进入改密步骤。抽出来是因为口令登录与 TOTP 第二回合**两条路**都会走到
 *  （服务端 handlePortalLogin 与 handleTotpLogin 两处都调 mustChangeLogin）。 */
function enterPwChange(r: PortalLoginResp) {
  needPwChange.value = true;
  needTotp.value = false; needMfa.value = false; totpTicket.value = '';
  pwToken.value = r.token || '';
  pwForm.pw = ''; pwForm.pw2 = '';
  // 原样用后端那句：它会点名「旧口令 = 管理员为你设置的**本地**初始口令」，
  // 或在外部认证源认过的那一回合改口成「无需再填写旧口令」。自己编一句必然漏掉其中一种。
  pwReason.value = r.reason || '首次登录须修改初始口令';
  err.value = '';
}

function backToLogin() {
  needPwChange.value = false;
  pwToken.value = ''; pwReason.value = '';
  pwForm.pw = ''; pwForm.pw2 = '';
  err.value = '';
}

/**
 * 提交改密：受限令牌调 POST /auth/password，成功后用**新口令**自动重登换正式会话。
 *
 * ★Authorization 显式带 pwToken：session.token 此刻是空的（受限令牌刻意没入库），
 *   api() 的自动注入拿不到东西，不显式带就是一个必然 401 的请求。
 * ★失败一律 failReason 原样转述：这里最高频的拒绝是 400「新口令强度不足：<哪一条不达标>」，
 *   编一句"请重试"会让人反复撞同一堵墙且屏幕上从没出现过原因。
 */
async function submitPwChange() {
  const bad = checkNewPassword(pwForm.pw, pwForm.pw2, form.password);
  if (bad) { err.value = bad; return; }
  loading.value = true; err.value = '';
  try {
    const r = await api<{ ok: boolean; reason?: string }>('/auth/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pwToken.value}` },
      body: JSON.stringify({ old: form.password, new: pwForm.pw })
    });
    if (!r.ok) { err.value = r.reason || '口令修改失败'; return; }
    // 换新口令重走一遍完整登录：这一次服务端才会发 8h 会话令牌。
    // 有 TOTP 的账号会再要一次动态码（上一个已被消费），submit() 照常把流程引过去。
    form.password = pwForm.pw;
    backToLogin();
    await submit();
  } catch (e) {
    err.value = failReason(e);
  } finally { loading.value = false; }
}

async function submit() {
  if (needTotp.value) { await submitTotp(); return; }
  if (!form.username || !form.password) { err.value = '请输入账号与口令'; return; }
  loading.value = true; err.value = '';
  try {
    const r = await api<PortalLoginResp>('/portal/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: form.username, password: form.password, mfaCode: needMfa.value ? form.mfaCode : '', directory: form.directory })
    });
    // ★这一支必须排在 `r.ok && r.token` 前面：首登强制改密的应答同样带 ok=true + token，
    //   顺序反过来就会拿受限令牌 login() 并跳进主界面，然后每个业务端点 403。
    if (r.mustChangePassword && r.token) {
      enterPwChange(r);
    } else if (r.ok && r.token) {
      login(r.token, r.displayName || form.username);
      router.replace('/connect');
    } else if (r.needTotp && r.ticket) {
      needTotp.value = true; totpTicket.value = r.ticket; mfaReason.value = r.reason || ''; form.mfaCode = ''; err.value = '';
    } else if (r.needWebauthn) {
      err.value = '该账号已启用 passkey：移动客户端无法完成断言，请改用浏览器门户，或在门户「我的安全」改用 TOTP';
    } else if (r.needMfa) {
      needMfa.value = true; mfaReason.value = r.reason || ''; err.value = '';
    } else if (r.needDirectory) {
      // 服务端带回了候选：装进下拉让用户真的能选，而不是把「请先选择认证域」
      // 显示成一条无从执行的错误（此前移动端就是这样）。
      domains.value = r.domains ?? [];
      err.value = domains.value.length
        ? '本系统配置了多个认证域，请在上方选择你所属的认证域后重试'
        : (r.reason || '需要指定认证域，但服务端未返回候选，请联系管理员');
    } else {
      err.value = r.reason || '登录失败';
    }
  } catch (e) {
    // ★后端在**口令校验之前**就会定性拒绝：防爆破锁 403「登录失败次数过多，请约 N 分钟后
    //   重试」、账号被禁用、认证域没选。改造前这里是 bare catch + 一句编造的归因
    //   「无法连接控制中心（baidi-control）」——被锁的人照着去查网络、去重试，
    //   而每重试一次都在续锁，屏幕上从没出现过"已被临时锁定"。
    //   失败一律 failReason 收口：后端说了什么就转述什么，没到后端才说连不上。
    err.value = failReason(e);
  } finally { loading.value = false; }
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
    // 与口令路径同一道判定：handleTotpLogin 同样会走 mustChangeLogin。
    // 少了这一支，开了 TOTP 的新用户就是本波要修的那条死路的另一半。
    if (r.mustChangePassword && r.token) {
      enterPwChange(r);
    } else if (r.ok && r.token) {
      login(r.token, r.displayName || form.username);
      router.replace('/connect');
    } else { err.value = r.reason || '验证码不正确或已使用'; }
  } catch (e) {
    // ★改造前这句把每一种拒绝都说成"验证码不正确"——包括 403 防爆破锁（TOTP 第二回合
    //   同样过 loginGateLocked）与 403「账号已被禁用」。被锁的人于是照着提示一遍遍重输，
    //   每输一次都在续锁。401 要额外**改状态**：票据 3 分钟就过期，得退回口令那一步重来。
    err.value = failReason(e);
    if (failStatus(e) === 401) { needTotp.value = false; totpTicket.value = ''; }
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
/* 首登强制改密：后端原话（点名"本地初始口令"或"无需填写旧口令"）+ 常驻的口令要求 */
.lg__mustpw { font-size: 12.5px; color: var(--bd-warning); background: #FFF7E8;
  border-radius: 10px; padding: 10px 12px; margin-bottom: 12px; line-height: 1.7; }
.lg__rule { font-size: 11.5px; color: var(--bd-t3); line-height: 1.7; margin: -4px 2px 12px; }
.lg__back { width: 100%; margin-top: 10px; height: 40px; border: 1px solid var(--bd-border);
  background: #fff; color: var(--bd-t2); border-radius: 12px; font-size: 14px; }
.lg__err { font-size: 13px; color: var(--bd-danger); margin: -4px 2px 12px; }
.lg__demo { text-align: center; font-size: 11px; color: var(--bd-t3); margin-top: 16px; line-height: 1.7; }
.lg__demo b { color: var(--bd-primary); font-weight: 600; }
.lg__sel { flex: 1; border: none; outline: none; background: transparent; font-size: 15px;
  color: var(--bd-t1); appearance: none; padding: 0; }
</style>
