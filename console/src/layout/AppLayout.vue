<template>
  <div class="bd-shell">
    <!-- 顶栏 -->
    <header class="bd-top">
      <div class="bd-logo">
        <span class="bd-logo__mark">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
            <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </span>
        <span class="bd-logo__txt">
          <b>白帝 · 零信任访问控制中心</b>
          <i>ZTNA / SDP Control Center</i>
        </span>
      </div>
      <span class="bd-top__divider" />
      <nav class="bd-modes">
        <span class="bd-mode on">控制台</span>
        <span class="bd-mode" @click="router.push('/screen')">态势大屏</span>
        <span class="bd-mode" @click="router.push('/diag')">运维诊断</span>
      </nav>
      <div class="bd-top__spacer" />
      <GlobalSearch />
      <NotifyBell />
      <a-dropdown trigger="click" @select="onAcctSelect">
        <div class="bd-acct">
          <span class="bd-acct__av">{{ avatarChar }}</span>
          <!-- ★这两行此前是写死的「安全管理员 / security-admin」。种子 admin 的
               显示名恰好就叫"安全管理员"，于是演示环境里它看起来完全正确——
               而那个账号的角色是**超管**；换审计管理员登录也一字不改。
               现在唯一来源是 GET /auth/me（角色现算，见 lib/me.ts）。 -->
          <span class="bd-acct__txt"><b>{{ meTitle }}</b><i>{{ meSubtitle }}</i></span>
          <icon-down class="bd-acct__out" />
        </div>
        <template #content>
          <!-- 权限键是**执行方真正读的那份**（后端 admin_roles.scope_json），
               不是页面文案。判不出来时如实说不可判定，不写死成任何一个角色。 -->
          <div class="bd-acctcard">
            <div class="bd-acctcard__n">{{ meTitle }}<span>{{ me.sub }}</span></div>
            <template v-if="me.permKnown">
              <div class="bd-acctcard__r">{{ me.roleName }}</div>
              <div class="bd-acctcard__p">
                <span v-for="p in me.perms" :key="p" class="bd-perm">{{ PERM_ZH[p] || p }}</span>
              </div>
              <div v-if="me.scope" class="bd-acctcard__s">{{ me.scope }}</div>
            </template>
            <div v-else class="bd-acctcard__u">
              角色与权限不可判定（未拉到 /auth/me 或后端未升级）——本页不据此收敛任何操作，
              真正的权限闸在服务端。
            </div>
          </div>
          <a-doption value="password"><icon-lock /> 修改口令</a-doption>
          <!-- ★管理台此前**没有任何二次认证入口**：系统管理页专门列了一栏「二次认证」，
               而管理员在整个控制台里找不到地方注册 passkey 或 TOTP——注册页确实存在
               （/portal/security），只是从管理台一个链接都到不了。
               管理台是权限最高面，且它的登录链路本来就过 secondFactor。 -->
          <a-doption value="mfa"><icon-safe /> 二次认证（passkey / TOTP）</a-doption>
          <a-doption value="logout"><icon-export /> 退出登录</a-doption>
        </template>
      </a-dropdown>
    </header>

    <!-- 自助修改口令（校验旧口令，落库改哈希） -->
    <a-modal v-model:visible="pwOpen" title="修改登录口令" :width="440" :footer="false" @close="resetPwForm">
      <div class="bd-pwform">
        <div class="bd-pwform__f"><label>当前口令</label>
          <a-input-password v-model="oldPw" placeholder="请输入当前登录口令" />
        </div>
        <div class="bd-pwform__f"><label>新口令</label>
          <a-input-password v-model="newPw" :placeholder="PW_HINT" />
        </div>
        <div class="bd-pwform__f"><label>确认新口令</label>
          <a-input-password v-model="newPw2" placeholder="再输入一次" @keyup.enter="doChangePw" />
        </div>
        <!-- ★口令要求必须与后端 auth.PasswordWeakness 逐字一致（≥10 位含三类字符，或 ≥16 位长口令）：
             写松了，管理员按提示输入会被后端 400 拒掉；而首登强制改密默认开启，
             这是每一次标准部署的第一个动作。 -->
        <div class="bd-pwform__rule">{{ PW_HINT }}；口令中不得包含账号名，也不得是常见弱口令</div>
        <div v-if="pwErr" class="bd-pwform__err"><icon-exclamation-circle-fill />{{ pwErr }}</div>
        <div class="bd-pwform__foot">
          <button class="bd-mbtn bd-mbtn--ghost" :disabled="changing" @click="pwOpen = false">取消</button>
          <button class="bd-mbtn" :disabled="changing" @click="doChangePw">{{ changing ? '提交中…' : '确认修改' }}</button>
        </div>
      </div>
    </a-modal>

    <div class="bd-body">
      <!-- 侧栏：分组导航 + 底部深色状态卡 -->
      <aside class="bd-side">
        <template v-for="g in NAV" :key="g.label">
          <div class="bd-side__label">{{ g.label }}</div>
          <button
            v-for="leaf in g.children"
            :key="leaf.path"
            class="bd-nav"
            :class="{ on: leaf.path === route.path }"
            @click="go(leaf.path)"
          >
            <component :is="leaf.icon" class="bd-nav__icon" />
            <span class="bd-nav__t">{{ leaf.title }}</span>
            <!-- 角标值来自真实接口（src/lib/badges.ts）：取不到就不渲染，不显示编造值 -->
            <span
              v-if="leaf.badgeKey && badgeCounts[leaf.badgeKey] !== undefined"
              class="bd-nav__badge"
              :class="leaf.badgeKind"
            >{{ badgeCounts[leaf.badgeKey] }}</span>
          </button>
        </template>

        <!-- ★这里曾经写死「系统运行正常 / 集群 HA 双节点活动 / 公网暴露端口 0」，
             三句话没有一句是测出来的：集群根本没部署（System 页与 /diag 都如实回
             「未部署」，侧栏却宣称双节点活动，两处自相矛盾），暴露端口也从未探测。
             常驻在每一页的健康结论最容易被当真，所以改成入口而不是结论——
             真实体检在 /diag，那里有 9 项真探测。 -->
        <RouterLink to="/diag" class="bd-health bd-health--link">
          <div class="bd-health__h"><icon-pulse />运维诊断</div>
          <div class="bd-health__b">集群 / 隐身 / 审计 / 认证源等 9 项实测体检</div>
        </RouterLink>
      </aside>

      <main class="bd-main"><RouterView /></main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { NAV } from '@/nav';
import { api, clearToken } from '@/lib/api';
import { badgeCounts, refreshBadges } from '@/lib/badges';
import { PERM_ZH, avatarChar, me, meSubtitle, meTitle, refreshMe, resetMe } from '@/lib/me';
import GlobalSearch from '@/components/GlobalSearch.vue';
import NotifyBell from '@/components/NotifyBell.vue';

const route = useRoute();
const router = useRouter();

/**
 * 口令要求文案。**唯一来源就是这一句**，弹窗的提示行与输入框占位共用它——
 * 两处各写一遍的话，改了一处忘了另一处，页面就会同时给出两种要求。
 * 内容与后端 auth.PasswordWeakness 的判据逐字对应（≥10 位且三类，或 ≥16 位长口令）。
 */
const PW_HINT = '至少 10 位且含大写/小写/数字/符号中的三类；或 16 位以上的长口令';

// 侧栏角标：进入控制台拉一次，之后每 60s 刷一次，换页时也刷
// （处理完一条告警回到列表，角标要跟着降下来）。
let badgeTimer: number | undefined;
onMounted(() => {
  void refreshBadges();
  // 身份也在这里拉。★角色是**现算**的（后端 currentAdminRoleQuiet），所以它和角标
  // 一样需要周期性刷新：超管把某人降权之后，那个人页面上的角色标签不该一直停在旧值。
  void refreshMe();
  badgeTimer = window.setInterval(() => { void refreshBadges(); void refreshMe(); }, 60_000);
});
onUnmounted(() => { if (badgeTimer) window.clearInterval(badgeTimer); });
watch(() => route.path, () => void refreshBadges());
function go(path: string) { if (path !== route.path) router.push(path); }
function logout() { clearToken(); resetMe(); router.push('/login'); }

// 账户菜单 + 自助改密
const pwOpen = ref(false);
const changing = ref(false);
const oldPw = ref('');
const newPw = ref('');
const newPw2 = ref('');
const pwErr = ref('');

function resetPwForm() { oldPw.value = ''; newPw.value = ''; newPw2.value = ''; pwErr.value = ''; }

function onAcctSelect(v: string | number | Record<string, unknown> | undefined) {
  if (v === 'logout') logout();
  else if (v === 'password') { resetPwForm(); pwOpen.value = true; }
  // 注册/解绑二次认证的页面在门户侧（同一套账号体系，管理员登录同样过 secondFactor）。
  else if (v === 'mfa') router.push('/portal/security');
}

/** 前端预检：**只做后端判据的一个真子集**（长度 + 字符种类这两条客观项）。
 *  弱口令表与"含账号名"两条刻意不在前端复刻——那会变成第二份判据，
 *  与后端一旦对不上，就会出现"前端拦下了后端本来会放行的口令"，
 *  而这种失败在界面上完全看不出是前端多拦的。 */
function localPwProblem(pw: string): string {
  const n = [...pw].length;
  if (n < 10) return '新口令长度不足 10 位';
  if (n >= 16) return '';
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((re) => re.test(pw)).length;
  if (classes < 3) return '字符种类不足（大写/小写/数字/符号 至少三类）';
  return '';
}

async function doChangePw() {
  pwErr.value = '';
  if (!oldPw.value) { pwErr.value = '请输入当前口令'; return; }
  const bad = localPwProblem(newPw.value);
  if (bad) { pwErr.value = `${bad}。要求：${PW_HINT}`; return; }
  if (newPw.value !== newPw2.value) { pwErr.value = '两次输入的新口令不一致'; return; }
  if (newPw.value === oldPw.value) { pwErr.value = '新口令不得与当前口令相同'; return; }
  changing.value = true;
  try {
    const r = await api<{ ok: boolean; reason?: string }>('/auth/password', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old: oldPw.value, new: newPw.value })
    });
    if (r.ok) { Message.success('登录口令已修改'); pwOpen.value = false; resetPwForm(); }
    else pwErr.value = r.reason || '修改失败';
  } catch (e) {
    // ★原样转述后端的失败原因（「新口令强度不足…」「旧口令不正确」「尝试过于频繁」）。
    //   换成「请检查网络或重新登录」是一句错误的归因：真正的原因就在被丢掉的那个字符串里。
    pwErr.value = e instanceof Error ? e.message : '修改失败';
  } finally { changing.value = false; }
}
</script>

<style scoped>
.bd-shell { display: flex; flex-direction: column; height: 100vh; overflow: hidden; }

/* 自助改密弹窗 */
.bd-pwform__f { margin-bottom: 16px; }
.bd-pwform__f > label { display: block; font-size: 13px; font-weight: 500; color: var(--bd-t1); margin-bottom: 7px; }
.bd-pwform__f :deep(.arco-input-wrapper) { width: 100%; }
.bd-pwform__rule { font-size: 11.5px; color: var(--bd-t3); line-height: 1.7; margin-top: -6px; }
.bd-pwform__err {
  display: flex; align-items: flex-start; gap: 6px; margin-top: 12px; padding: 8px 10px;
  background: var(--bd-tag-red-bg); color: var(--bd-danger); border-radius: 7px;
  font-size: 12px; line-height: 1.65;
}
.bd-pwform__foot { display: flex; justify-content: flex-end; gap: 10px; margin-top: 22px; }
.bd-mbtn { height: 34px; padding: 0 18px; border-radius: 8px; border: none; background: var(--bd-primary); color: #fff; font-size: 13px; cursor: pointer; }
.bd-mbtn--ghost { background: var(--bd-fill-2); color: var(--bd-t1); }
.bd-mbtn[disabled] { opacity: .6; cursor: not-allowed; }

/* 顶栏 */
.bd-top {
  height: var(--bd-header-h); flex: none; background: #fff; border-bottom: 1px solid var(--bd-border);
  display: flex; align-items: center; padding: 0 20px; gap: 16px; z-index: 20;
}
.bd-logo { display: flex; align-items: center; gap: 11px; }
.bd-logo__mark {
  width: 30px; height: 30px; border-radius: 7px; flex: none;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d));
  display: flex; align-items: center; justify-content: center; box-shadow: 0 2px 6px rgba(22, 93, 255, .35);
}
.bd-logo__txt { display: flex; flex-direction: column; line-height: 1.15; }
.bd-logo__txt b { font-size: 15px; font-weight: 700; letter-spacing: .3px; }
.bd-logo__txt i { font-style: normal; font-size: 11px; color: var(--bd-t3); }
.bd-top__divider { width: 1px; height: 24px; background: var(--bd-border); margin: 0 4px; }
.bd-modes { display: flex; gap: 2px; }
.bd-mode { font-size: 13px; color: var(--bd-t2); padding: 6px 12px; border-radius: 6px; cursor: pointer; }
.bd-mode:hover { background: var(--bd-fill-2); }
.bd-mode.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }
.bd-top__spacer { flex: 1; }
/* 搜索框与通知铃铛的样式随组件走：components/GlobalSearch.vue、components/NotifyBell.vue */
.bd-acct { display: flex; align-items: center; gap: 9px; cursor: pointer; padding: 3px 6px; border-radius: 8px; }
.bd-acct:hover { background: var(--bd-fill-2); }
.bd-acct__av {
  width: 30px; height: 30px; border-radius: 50%; flex: none; color: #fff; font-size: 12px; font-weight: 600;
  background: linear-gradient(135deg, var(--bd-purple), var(--bd-primary));
  display: flex; align-items: center; justify-content: center;
}
.bd-acct__txt { display: flex; flex-direction: column; line-height: 1.2; }
.bd-acct__txt b { font-size: 13px; font-weight: 600; max-width: 130px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bd-acct__txt i { font-style: normal; font-size: 11px; color: var(--bd-t3); max-width: 130px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* 账户下拉里的身份卡：谁 / 什么角色 / 持有哪些权限键 */
.bd-acctcard { padding: 11px 12px 10px; border-bottom: 1px solid var(--bd-border); min-width: 232px; max-width: 300px; }
.bd-acctcard__n { font-size: 13px; font-weight: 600; color: var(--bd-t1); }
.bd-acctcard__n span { font-weight: 400; font-size: 11px; color: var(--bd-t3); margin-left: 6px; }
.bd-acctcard__r { font-size: 12px; color: var(--bd-primary); margin-top: 5px; font-weight: 500; }
.bd-acctcard__p { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 7px; }
.bd-perm {
  font-size: 11px; padding: 1px 7px; border-radius: 4px;
  background: var(--bd-primary-1); color: var(--bd-primary);
}
.bd-acctcard__s { font-size: 11px; color: var(--bd-t3); margin-top: 7px; line-height: 1.6; }
.bd-acctcard__u { font-size: 11px; color: var(--bd-t3); margin-top: 6px; line-height: 1.7; }

/* 主体 */
.bd-body { display: flex; flex: 1; overflow: hidden; }
.bd-side {
  width: var(--bd-sider-w); flex: none; background: #fff; border-right: 1px solid var(--bd-border);
  padding: 12px 12px 24px; overflow-y: auto;
}
.bd-side__label {
  font-size: 11px; color: var(--bd-t3); font-weight: 600; padding: 0 12px;
  margin: 16px 0 4px; letter-spacing: .5px;
}
.bd-side__label:first-child { margin-top: 6px; }
.bd-nav {
  width: 100%; display: flex; align-items: center; gap: 10px; padding: 0 12px; height: 38px;
  border: none; background: transparent; border-radius: 7px; cursor: pointer; font-size: 13px;
  color: var(--bd-t2); margin-bottom: 2px; transition: background .12s; text-align: left;
}
.bd-nav:hover { background: var(--bd-fill-2); }
.bd-nav.on { background: var(--bd-primary-1); color: var(--bd-primary); font-weight: 500; }
.bd-nav__icon { font-size: 17px; flex: none; }
.bd-nav__t { flex: 1; }
.bd-nav__badge { font-size: 11px; color: var(--bd-t3); font-weight: 500; }
.bd-nav__badge.alert {
  min-width: 16px; height: 16px; padding: 0 5px; background: var(--bd-tag-red-bg); color: var(--bd-danger);
  border-radius: 8px; font-weight: 600; display: flex; align-items: center; justify-content: center;
}

.bd-health {
  margin-top: 20px; padding: 12px; border-radius: 10px; color: #fff;
  background: linear-gradient(135deg, var(--bd-dark-1), var(--bd-dark-2));
}
.bd-health--link { display: block; text-decoration: none; transition: filter .15s; }
.bd-health--link:hover { filter: brightness(1.18); }
.bd-health--link:focus-visible { outline: 2px solid var(--bd-primary); outline-offset: 2px; }
.bd-health__h { display: flex; align-items: center; gap: 7px; font-size: 12px; font-weight: 600; margin-bottom: 6px; }
.bd-health__b { font-size: 11px; color: var(--bd-dark-txt); line-height: 1.7; }
.bd-health__b b { color: #fff; }

.bd-main { flex: 1; overflow-y: auto; background: var(--bd-fill-1); }
</style>
