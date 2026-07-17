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
      <div class="bd-search"><icon-search /><span>搜索用户、应用、策略…</span></div>
      <button class="bd-bell"><icon-notification /><span class="bd-bell__dot">6</span></button>
      <a-dropdown trigger="click" @select="onAcctSelect">
        <div class="bd-acct">
          <span class="bd-acct__av">管</span>
          <span class="bd-acct__txt"><b>安全管理员</b><i>security-admin</i></span>
          <icon-down class="bd-acct__out" />
        </div>
        <template #content>
          <a-doption value="password"><icon-lock /> 修改密码</a-doption>
          <a-doption value="logout"><icon-export /> 退出登录</a-doption>
        </template>
      </a-dropdown>
    </header>

    <!-- 自助修改密码（校验旧口令，落库改哈希） -->
    <a-modal v-model:visible="pwOpen" title="修改登录口令" :width="420" :footer="false">
      <div class="bd-pwform">
        <div class="bd-pwform__f"><label>当前口令</label>
          <a-input-password v-model="oldPw" placeholder="请输入当前登录口令" />
        </div>
        <div class="bd-pwform__f"><label>新口令</label>
          <a-input-password v-model="newPw" placeholder="至少 6 位" @keyup.enter="doChangePw" />
        </div>
        <div class="bd-pwform__foot">
          <button class="bd-mbtn bd-mbtn--ghost" @click="pwOpen = false">取消</button>
          <button class="bd-mbtn" :disabled="changing" @click="doChangePw">确认修改</button>
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
            <span v-if="leaf.badge" class="bd-nav__badge" :class="leaf.badgeKind">{{ leaf.badge }}</span>
          </button>
        </template>

        <div class="bd-health">
          <div class="bd-health__h"><span class="bd-health__dot" />系统运行正常</div>
          <div class="bd-health__b">集群 HA · 双节点活动<br />公网暴露端口 <b>0</b> · SPA 隐身中</div>
        </div>
      </aside>

      <main class="bd-main"><RouterView /></main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { NAV } from '@/nav';
import { api, clearToken } from '@/lib/api';

const route = useRoute();
const router = useRouter();
function go(path: string) { if (path !== route.path) router.push(path); }
function logout() { clearToken(); router.push('/login'); }

// 账户菜单 + 自助改密
const pwOpen = ref(false);
const changing = ref(false);
const oldPw = ref('');
const newPw = ref('');
function onAcctSelect(v: string | number | Record<string, unknown> | undefined) {
  if (v === 'logout') logout();
  else if (v === 'password') { oldPw.value = ''; newPw.value = ''; pwOpen.value = true; }
}
async function doChangePw() {
  if (!oldPw.value) { Message.warning('请输入当前口令'); return; }
  if (newPw.value.length < 6) { Message.warning('新口令至少 6 位'); return; }
  changing.value = true;
  try {
    const r = await api<{ ok: boolean; reason?: string }>('/auth/password', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old: oldPw.value, new: newPw.value })
    });
    if (r.ok) { Message.success('登录口令已修改'); pwOpen.value = false; }
    else Message.error(r.reason || '修改失败');
  } catch { Message.error('修改失败，请检查网络或重新登录'); }
  finally { changing.value = false; }
}
</script>

<style scoped>
.bd-shell { display: flex; flex-direction: column; height: 100vh; overflow: hidden; }

/* 自助改密弹窗 */
.bd-pwform__f { margin-bottom: 16px; }
.bd-pwform__f > label { display: block; font-size: 13px; font-weight: 500; color: var(--bd-t1); margin-bottom: 7px; }
.bd-pwform__f :deep(.arco-input-wrapper) { width: 100%; }
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
.bd-search {
  display: flex; align-items: center; height: 32px; background: var(--bd-fill-2); border-radius: 6px;
  padding: 0 10px; gap: 8px; width: 220px; color: var(--bd-t3); font-size: 13px; cursor: text;
}
.bd-bell {
  position: relative; width: 34px; height: 34px; border: none; background: transparent; border-radius: 8px;
  display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--bd-t2); font-size: 18px;
}
.bd-bell:hover { background: var(--bd-fill-2); }
.bd-bell__dot {
  position: absolute; top: 4px; right: 5px; min-width: 15px; height: 15px; padding: 0 4px;
  background: var(--bd-danger); color: #fff; border-radius: 8px; font-size: 10px; font-weight: 600;
  display: flex; align-items: center; justify-content: center; border: 1.5px solid #fff;
}
.bd-acct { display: flex; align-items: center; gap: 9px; cursor: pointer; padding: 3px 6px; border-radius: 8px; }
.bd-acct:hover { background: var(--bd-fill-2); }
.bd-acct__av {
  width: 30px; height: 30px; border-radius: 50%; flex: none; color: #fff; font-size: 12px; font-weight: 600;
  background: linear-gradient(135deg, var(--bd-purple), var(--bd-primary));
  display: flex; align-items: center; justify-content: center;
}
.bd-acct__txt { display: flex; flex-direction: column; line-height: 1.2; }
.bd-acct__txt b { font-size: 13px; font-weight: 600; }
.bd-acct__txt i { font-style: normal; font-size: 11px; color: var(--bd-t3); }

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
.bd-health__h { display: flex; align-items: center; gap: 7px; font-size: 12px; font-weight: 600; margin-bottom: 6px; }
.bd-health__dot {
  width: 7px; height: 7px; border-radius: 50%; background: #23C343; box-shadow: 0 0 0 3px rgba(35, 195, 67, .25);
}
.bd-health__b { font-size: 11px; color: var(--bd-dark-txt); line-height: 1.7; }
.bd-health__b b { color: #fff; }

.bd-main { flex: 1; overflow-y: auto; background: var(--bd-fill-1); }
</style>
