<!--
  统一的「实时/演示」页头角标（一致性收敛）：替代各页逐字复制的内联 style 双 span。
  全局注册（main.ts），各视图直接 <LiveBadge :live="live" /> 即可，无需 import。
  默认文案「● 实时 / 演示数据」；少数页需保留语义（如仿真器=本地引擎）可传 live-text / mock-text。
-->
<template>
  <span
    class="zl-livebadge zl-badge"
    :class="live ? 'zl-badge--ok' : 'zl-badge--idle'"
  >{{ live ? '● ' + liveText : mockText }}</span>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ live?: boolean; liveText?: string; mockText?: string }>(), {
  live: false,
  liveText: '实时',
  mockText: '演示数据'
});
</script>

<style scoped>
.zl-livebadge {
  margin-left: 10px;
  font-size: 11px;
  vertical-align: middle;
}
</style>
