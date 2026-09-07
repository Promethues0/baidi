<!--
  SkeletonBlock · 首屏加载骨架（表格 / 卡片 / 统计卡 / 文本）

  为什么要有它：首屏 `onMounted(load)` 到数据回来之间，各页要么空白（Apps：只有表头，
  0.3~1s 后行才跳出来），要么先画演示数据再整屏替换成真数据（Overview：MOCK 的 240 台终端
  一闪而过变成 0 台——那一瞬间显示的是**假数**）。骨架屏把"还没拿到"画成还没拿到，
  既不闪白也不闪假。

  替代了什么形态：什么都没有 / 先渲染 MOCK 再替换 / 一个孤零零的 <a-spin>。

  kind：table（N 行 × M 列）/ card（标题 + 几行）/ stat（KPI 卡：小标签 + 大数字 + 脚注）/ text（几行文字）。
  只做静置占位，不承载任何文字——骨架上写"加载中"会让读屏用户听到一堆重复的字；
  语义靠 aria-busy 与 role=status 给。
-->
<template>
  <div class="bd-sk" :class="`bd-sk--${kind}`" role="status" aria-busy="true" aria-label="加载中">
    <template v-if="kind === 'table'">
      <div class="bd-sk__thead"><span v-for="c in cols" :key="c" class="bd-sk__bar" :style="{ width: colW(c) }" /></div>
      <div v-for="r in rows" :key="r" class="bd-sk__tr">
        <span v-for="c in cols" :key="c" class="bd-sk__bar" :style="{ width: colW(c, r) }" />
      </div>
    </template>
    <template v-else-if="kind === 'stat'">
      <span class="bd-sk__bar" style="width: 36%; height: 12px" />
      <span class="bd-sk__bar" style="width: 48%; height: 30px; margin-top: 12px" />
      <span class="bd-sk__bar" style="width: 70%; height: 10px; margin-top: 14px" />
    </template>
    <template v-else-if="kind === 'card'">
      <span class="bd-sk__bar" style="width: 30%; height: 14px" />
      <span v-for="r in rows" :key="r" class="bd-sk__bar" :style="{ width: lineW(r), height: '10px', marginTop: '14px' }" />
    </template>
    <template v-else>
      <span v-for="r in rows" :key="r" class="bd-sk__bar" :style="{ width: lineW(r), height: '10px', marginTop: r === 1 ? '0' : '12px' }" />
    </template>
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{
  kind?: 'table' | 'card' | 'stat' | 'text';
  /** table 的行数 / card·text 的行数 */
  rows?: number;
  /** table 的列数 */
  cols?: number;
}>(), { kind: 'table', rows: 5, cols: 5 });

/* 列宽按位置给一个稳定的伪随机，让骨架看起来像真表而不是一排等宽方块。 */
const W = [22, 14, 12, 16, 10, 18, 12];
function colW(c: number, r = 0) { return `${W[(c + r) % W.length]}%`; }
function lineW(r: number) { return `${[92, 78, 86, 64, 70][(r - 1) % 5]}%`; }
</script>

<style scoped>
.bd-sk { display: flex; flex-direction: column; }
.bd-sk__bar {
  display: block; height: 12px; border-radius: var(--bd-radius-xs);
  background: linear-gradient(90deg, var(--bd-fill-2) 25%, var(--bd-fill-3) 37%, var(--bd-fill-2) 63%);
  background-size: 400% 100%; animation: bd-sk-shimmer 1.4s var(--bd-ease) infinite;
}
@keyframes bd-sk-shimmer { 0% { background-position: 100% 50%; } 100% { background-position: 0 50%; } }
@media (prefers-reduced-motion: reduce) { .bd-sk__bar { animation: none; } }

.bd-sk--table .bd-sk__thead { display: flex; gap: var(--bd-sp-4); padding: 14px var(--bd-sp-5); background: var(--bd-fill-1); border-bottom: 1px solid var(--bd-border-2); }
.bd-sk--table .bd-sk__thead .bd-sk__bar { height: 10px; opacity: .7; }
.bd-sk--table .bd-sk__tr { display: flex; gap: var(--bd-sp-4); padding: 17px var(--bd-sp-5); border-bottom: 1px solid var(--bd-border-2); }
.bd-sk--table .bd-sk__tr:last-child { border-bottom: none; }
.bd-sk--stat, .bd-sk--card, .bd-sk--text { padding: var(--bd-sp-5); }
</style>
