<!--
  EmptyState · 空态（图标 / 标题 / 说明 / 主动作），三档尺寸

  为什么要有它：全仓 `.bd-empty` 在 11 个页面里各自定义了 11 次，形态从「一行灰字 28px 内边距」
  （Objects / Ipsec / Policy）到「图标 + 标题 + 两段说明」（Gateway / DeviceStat）不等；
  Apps 页干脆没有空态——筛选到零条时表格只剩表头。空态是用户最常停留的一屏（新装环境
  每一页都是空的），它得回答三件事：这里本该有什么、为什么现在没有、下一步做什么。

  替代了什么形态：
    <td colspan="6" class="bd-empty">暂无对象，点右上「新增对象」创建</td>
    <div class="bd-empty bd-empty--lg"><icon-… /><div>…</div></div>

  三档：sm 嵌在表格行 / 侧栏里（一行图标 + 文字）；md 卡片内默认；lg 整页级（首屏无数据）。
  tone 决定图标色：neutral 灰（确实没有）/ ok 绿（"没有待办"是好事）/ warn 橙（缺配置、缺上报，
  需要动作）/ danger 红（读取失败——这是"拉不到"，不是"没有"，两者必须分开画）。
  ★文案由页面给，组件不带默认标题：一句适用于所有页面的"暂无数据"什么都没说。
-->
<template>
  <div class="bd-es" :class="[`bd-es--${size}`, `bd-es--${tone}`]" role="status">
    <span class="bd-es__ic" aria-hidden="true">
      <slot name="icon">
        <icon-check-circle-fill v-if="tone === 'ok'" />
        <icon-exclamation-circle-fill v-else-if="tone === 'warn' || tone === 'danger'" />
        <icon-empty v-else />
      </slot>
    </span>
    <div class="bd-es__txt">
      <div class="bd-es__t">{{ title }}</div>
      <div v-if="desc || $slots.default" class="bd-es__d"><slot>{{ desc }}</slot></div>
      <div v-if="$slots.action" class="bd-es__act"><slot name="action" /></div>
    </div>
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{
  /** 标题：说"这里本该有什么 / 现在为什么没有"，不写泛泛的"暂无数据" */
  title: string;
  /** 说明：下一步做什么；含链接时用默认插槽 */
  desc?: string;
  size?: 'sm' | 'md' | 'lg';
  tone?: 'neutral' | 'ok' | 'warn' | 'danger';
}>(), { size: 'md', tone: 'neutral' });
</script>

<style scoped>
.bd-es { display: flex; align-items: center; justify-content: center; text-align: center; color: var(--bd-t3); }
.bd-es__ic { display: inline-flex; align-items: center; justify-content: center; flex: none; border-radius: 50%; color: var(--bd-t4); background: var(--bd-fill-2); }
.bd-es--ok .bd-es__ic { color: var(--bd-success); background: var(--bd-success-1); }
.bd-es--warn .bd-es__ic { color: var(--bd-warning); background: var(--bd-warning-1); }
.bd-es--danger .bd-es__ic { color: var(--bd-danger); background: var(--bd-danger-1); }
.bd-es__t { color: var(--bd-t2); font-weight: 600; line-height: var(--bd-lh-tight); }
.bd-es__d { color: var(--bd-t3); line-height: var(--bd-lh-loose); }
.bd-es__d :deep(code) { font-family: var(--bd-font-mono); background: var(--bd-fill-2); padding: 0 5px; border-radius: 3px; }
.bd-es__act { display: flex; justify-content: center; gap: var(--bd-sp-2); }

/* sm：一行式，嵌在表格行 / 侧栏 */
.bd-es--sm { flex-direction: row; gap: var(--bd-sp-2); padding: var(--bd-sp-4) var(--bd-sp-3); text-align: left; justify-content: flex-start; }
.bd-es--sm .bd-es__ic { width: 22px; height: 22px; font-size: 13px; }
.bd-es--sm .bd-es__t { font-size: var(--bd-fs-md); font-weight: 500; }
.bd-es--sm .bd-es__d { font-size: var(--bd-fs-sm); margin-top: 1px; }
.bd-es--sm .bd-es__act { justify-content: flex-start; margin-top: var(--bd-sp-2); }
.bd-es--sm .bd-es__txt { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0 var(--bd-sp-2); }

/* md：卡片 / 表格主体默认 */
.bd-es--md { flex-direction: column; gap: var(--bd-sp-3); padding: var(--bd-sp-8) var(--bd-sp-6); }
.bd-es--md .bd-es__ic { width: 44px; height: 44px; font-size: 22px; }
.bd-es--md .bd-es__t { font-size: var(--bd-fs-base); }
.bd-es--md .bd-es__d { font-size: var(--bd-fs-sm); margin-top: 6px; max-width: 520px; }
.bd-es--md .bd-es__act { margin-top: var(--bd-sp-4); }

/* lg：整页级 */
.bd-es--lg { flex-direction: column; gap: var(--bd-sp-4); padding: 72px var(--bd-sp-6); min-height: 320px; }
.bd-es--lg .bd-es__ic { width: 60px; height: 60px; font-size: 30px; }
.bd-es--lg .bd-es__t { font-size: var(--bd-fs-lg); color: var(--bd-t1); }
.bd-es--lg .bd-es__d { font-size: var(--bd-fs-md); margin-top: var(--bd-sp-2); max-width: 640px; }
.bd-es--lg .bd-es__act { margin-top: var(--bd-sp-5); }
</style>
