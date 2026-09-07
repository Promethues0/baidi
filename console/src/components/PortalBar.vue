<!--
  PortalBar · 门户顶栏（品牌 / 标题 / 右侧动作 / 账号）

  为什么把「门户壳」的样式放在这里：门户四页（应用 / 我的申请 / 我的安全 / 下载）各自 scoped 抄了一份
  `.bd-portal / .bd-pmain / .bd-pwrap / .bd-phead* / .bd-pquit / .bd-pacct`，四份之间字号与间距已经不同。
  这些类作用在**页面的模板**上（顶栏按钮是插槽内容、主体在页面里），scoped 样式够不着，
  所以下面第二个 <style> 块刻意**不加 scoped**：门户每一页都必然引入 PortalBar，跟着它加载正好。
  管理台（.bd-page）不使用这些类，不会串。

  ★但 PortalLogin.vue 的根也叫 `.bd-portal`（PortalLogin.vue:2），它不引入本组件、不在「门户四页」之列，
  左品牌区 + 右登录卡的并排布局靠的是 flex 默认的 row。它那份 scoped `.bd-portal` 只声明了
  display / min-height / background 三项——scoped 选择器更特异，也只能盖住自己写了的这三项，
  这里多声明的任何属性都会原样串过去。上一版这里写了 `display: flex; flex-direction: column`，
  用户从任一门户页点「退出」经 router.push 到 /portal/login 时（全局块已随门户页 chunk 常驻文档），
  登录页被画成品牌区在上、登录卡在下，1440×900 下口令框与登录按钮落在首屏之外（2026-09-07 CDP 实测：
  loginBtn.y=969 > 900）；冷启动 / 401 全页刷新路径不受影响，所以此前一直没被看见。
  因此下面的 `.bd-portal` 规则**只声明 PortalLogin 那份也声明了的属性**（min-height / background），
  壳不用 flex 竖排——块级流下 header 在上、main 紧贴其下本来就成立，`.bd-pmain` 也不需要 `flex: 1`
  （它自身无背景，壳与 body 底色同为 fill-1，撑不撑满视口看不出差别）。
  结构性的修法是给壳根类改名（如 .bd-pshell），但那要同时改四页模板，不在本组件范围内。

  `user` 传了就画账号徽章（首字母头像 + 显示名），默认插槽放它左边的动作，#after 放它右边的（如「退出」）。
-->
<template>
  <header class="bd-pbar">
    <div class="bd-plogo">
      <span class="bd-plogo__mark">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none">
          <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" style="fill: var(--bd-on-color)" opacity=".95" />
          <path d="M9 12l2 2 4-4" style="stroke: var(--bd-primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </span>
      <span class="bd-plogo__txt">{{ title }}</span>
    </div>
    <div class="bd-pbar__spacer" />
    <slot />
    <div v-if="user" class="bd-pacct">
      <span class="bd-pacct__av" aria-hidden="true">{{ avatarText }}</span>
      <span class="bd-pacct__name">{{ user }}</span>
    </div>
    <slot name="after" />
  </header>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = defineProps<{
  title: string;
  /** 当前登录用户的显示名；传了就画账号徽章 */
  user?: string;
}>();
const avatarText = computed(() => (props.user || '·').slice(0, 1).toUpperCase());
</script>

<style scoped>
.bd-pbar {
  height: var(--bd-header-h); background: var(--bd-bg-1); border-bottom: 1px solid var(--bd-border);
  display: flex; align-items: center; padding: 0 var(--bd-sp-6); gap: var(--bd-sp-3); position: sticky; top: 0; z-index: var(--bd-z-top);
}
.bd-plogo { display: flex; align-items: center; gap: 10px; }
.bd-plogo__mark {
  width: 30px; height: 30px; border-radius: var(--bd-radius-s); flex: none;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d));
  display: flex; align-items: center; justify-content: center; box-shadow: var(--bd-shadow-primary);
}
.bd-plogo__txt { font-size: 15px; font-weight: 700; letter-spacing: .3px; color: var(--bd-t1); }
.bd-pbar__spacer { flex: 1; }
.bd-pacct { display: flex; align-items: center; gap: 9px; }
.bd-pacct__av {
  width: 30px; height: 30px; border-radius: 50%; flex: none; color: var(--bd-on-color); font-size: var(--bd-fs-md); font-weight: 600;
  background: linear-gradient(135deg, var(--bd-purple), var(--bd-primary));
  display: flex; align-items: center; justify-content: center;
}
.bd-pacct__name { font-size: var(--bd-fs-md); font-weight: 600; color: var(--bd-t1); }
</style>

<!-- 门户壳共享样式（不加 scoped，理由见文件头注释）。页面 <style scoped> 里不要再定义这些类。 -->
<style>
/* ★只许声明 PortalLogin.vue:671 那份 scoped .bd-portal 也声明了的属性（min-height / background）——
   多写一项就会串进登录页（见文件头注释）。壳走块级流：header 在上、main 在下，不需要 flex。 */
.bd-portal { min-height: 100vh; background: var(--bd-fill-1); }
.bd-pmain { padding: var(--bd-sp-8) var(--bd-sp-6) 64px; }
.bd-pwrap { max-width: 1080px; margin: 0 auto; }
.bd-pwrap--narrow { max-width: 900px; }
/* 顶栏里的次级按钮（返回 / 我的申请 / 退出…）：插槽内容，只能从这里给样式 */
.bd-pquit {
  display: inline-flex; align-items: center; gap: 6px; height: var(--bd-ctl-h); padding: 0 var(--bd-sp-3);
  border: 1px solid var(--bd-border); background: var(--bd-bg-1); border-radius: var(--bd-radius-s); cursor: pointer;
  font-size: var(--bd-fs-md); color: var(--bd-t2); font-family: inherit;
  transition: border-color var(--bd-dur-fast) var(--bd-ease), color var(--bd-dur-fast) var(--bd-ease);
}
.bd-pquit:hover { border-color: var(--bd-primary); color: var(--bd-primary); }
/* 页头：问候 / 标题 + 一行统计，右侧可放搜索框或连接标签 */
.bd-phead {
  display: flex; align-items: flex-end; justify-content: space-between; gap: var(--bd-sp-5);
  margin-bottom: var(--bd-sp-6); flex-wrap: wrap;
}
.bd-phead__hi { margin: 0; font-size: 26px; font-weight: 700; color: var(--bd-t1); letter-spacing: .3px; line-height: var(--bd-lh-tight); }
.bd-phead__sub { margin: var(--bd-sp-2) 0 0; font-size: var(--bd-fs-base); color: var(--bd-t3); }
/* b / i 是句中强调的数字（可访问 N 个应用 / 待审批 M 条）。原 15px 与 base 14 / lg 16 等距，取 lg：
   句子本身是 base 14，取 14 就只剩粗体与颜色在强调、数字不再比句子大——而"比句子大一档"正是这两条规则存在的理由。 */
.bd-phead__sub b { color: var(--bd-primary); font-weight: 700; font-size: var(--bd-fs-lg); }
.bd-phead__sub i { color: var(--bd-warning); font-style: normal; font-weight: 700; font-size: var(--bd-fs-lg); }
.bd-phead__sub .bd-dot { margin: 0 var(--bd-sp-2); color: var(--bd-t4); }
/* 区块：标题 + 计数 */
.bd-psec { margin-bottom: var(--bd-sp-7); }
.bd-psec__t { display: flex; align-items: center; gap: var(--bd-sp-2); font-size: 15px; font-weight: 600; color: var(--bd-t1); margin-bottom: var(--bd-sp-4); }
.bd-psec__t em { font-style: normal; font-size: var(--bd-fs-sm); color: var(--bd-t3); font-weight: 400; }
.bd-psec__spacer { flex: 1; }
</style>
