<!--
  PageHeader · 页头（标题 / 副标题 / 连接态标签 / 右侧动作）

  为什么要有它：21 个管理页各自手写 `.bd-page__head` + `<a-tag :color="live ? 'green' : 'orange'">`，
  连接态那枚标签在 24 处各写一遍，离线文案就写出了四种（「降级演示」「后端未连接」
  「未连控制中心」「数据未读取」），标签与按钮的间距也各页不同。页头是每一页的第一眼，
  它的层级与节奏统一了，整站才像一个产品。

  替代了什么形态：
    <div class="bd-page__head"><div><div class="bd-page__title">…</div><div class="bd-page__sub">…</div></div>
      <div class="bd-head__right"><a-tag …>已连 baidi-control</a-tag><button class="bd-btn">…</button></div></div>

  连接态是**三态**：live=true → 绿「已连 baidi-control」；live=false → 橙/红离线文案；
  live 判不出来（不传 / undefined / **null**）→ 不画标签（本页没有"连接"这个概念、
  或者首屏还没探过一次——那一刻既不是"已连"也不是"离线"）。
  离线文案由页面给（offText），因为各页离线时的真实处境不同：有演示数据可降级的说「降级演示」，
  不能编数据的审计页说「数据未读取」——组件不替页面决定这句话。

  ★null 与 undefined 同判，是为了堵一个塌成二值的口子：兄弟组件 StatCard 的契约是
  `value=null → 画「—」`，页面作者照着那条经验写 `const live = ref<boolean | null>(null)`
  时，`live !== undefined` 会判成 true，于是首屏（还没探过后端）当场渲染出一枚橙色
  「降级演示」——把"不知道"画成了"确定离线"，而页面与守卫都不会报任何错。
  判不出来一律不画标签，方向恒定：宁可少一枚标签，不给一个没有依据的结论。
-->
<template>
  <header class="bd-ph">
    <div class="bd-ph__main">
      <div class="bd-ph__titlerow">
        <h1 class="bd-ph__title">{{ title }}</h1>
        <slot name="title-extra" />
      </div>
      <p v-if="subtitle || $slots.subtitle" class="bd-ph__sub"><slot name="subtitle">{{ subtitle }}</slot></p>
    </div>
    <!-- live == null（undefined 或 null）= 判不出来：不画标签。宽松相等是刻意的，见文件头。 -->
    <div v-if="live != null || $slots.default" class="bd-ph__right">
      <!-- data-tone 给机器断言用（CDP 探针只能核文案、核不到 Arco 的颜色类名）：green = 已连，其余 = offColor 原值 -->
      <a-tag v-if="live != null" :color="live ? 'green' : offColor" :data-tone="live ? 'green' : offColor" bordered class="bd-ph__live">
        <template #icon><icon-cloud /></template>
        {{ live ? liveText : offText }}
      </a-tag>
      <slot />
    </div>
    <div v-if="$slots.below" class="bd-ph__below"><slot name="below" /></div>
  </header>
</template>

<script setup lang="ts">
withDefaults(defineProps<{
  /** 页标题（h1，一页只有一个） */
  title: string;
  /** 副标题：一句话说清本页管什么；也可用 #subtitle 插槽放带链接的富文本 */
  subtitle?: string;
  /** 连接态三态。true 已连 / false 离线 / undefined 或 null = 判不出来，不画标签 */
  live?: boolean | null;
  liveText?: string;
  /** 离线时的文案——由页面按自己的真实处境给，组件不猜 */
  offText?: string;
  /** 离线标签颜色：有演示数据可降级用 orange；拉不到就什么都不画的页用 red */
  offColor?: 'orange' | 'red' | 'gray';
}>(), {
  // ★live 的默认值必须显式写成 undefined，哪怕看起来是废话——不写才是有后果的那一半。
  //   `live?: boolean` 编译出的运行期声明是 `{ type: Boolean }`，而 Vue 对 Boolean 型 prop 有
  //   一条 absent-cast：**没有 default 且调用方压根没传这个 prop 时，值被强制成 false**
  //   （resolvePropValue：`if (isAbsent && !hasDefault) value = false`）。
  //   于是 `<PageHeader title="…" />`（本页没有"连接"这个概念的纯静态说明页，正是文件头写的
  //   那一档）拿到的不是 undefined 而是 false，当场画出一枚橙色「降级演示」——一句没有执行方的
  //   状态断言，页面、type-check、check-ui 三处都不会报。
  //   写上 default 之后 hasDefault 为真，absent-cast 这条分支被跳过，值老老实实是 undefined。
  //   （显式传 `:live="undefined"` 本来就绕开了 absent-cast，所以此前只有"整个属性不写"那一档中招，
  //    更难发现。）
  live: undefined,
  liveText: '已连 baidi-control',
  offText: '降级演示',
  offColor: 'orange'
});
</script>

<style scoped>
.bd-ph { display: flex; align-items: flex-start; gap: var(--bd-sp-4); margin-bottom: var(--bd-sp-5); flex-wrap: wrap; }
.bd-ph__main { min-width: 0; flex: 1; }
.bd-ph__titlerow { display: flex; align-items: center; gap: var(--bd-sp-2); }
.bd-ph__title { margin: 0; font-size: var(--bd-fs-xl); font-weight: 700; letter-spacing: .3px; color: var(--bd-t1); line-height: var(--bd-lh-tight); }
.bd-ph__sub { margin: var(--bd-sp-1) 0 0; font-size: var(--bd-fs-md); color: var(--bd-t3); line-height: var(--bd-lh); }
.bd-ph__right { display: flex; align-items: center; gap: var(--bd-sp-2); flex-wrap: wrap; justify-content: flex-end; margin-left: auto; padding-top: 2px; }
.bd-ph__live { flex: none; }
.bd-ph__below { flex-basis: 100%; }
</style>
