<template>
  <div class="zl-page">
    <div class="zl-card zl-soon" style="margin-top: 40px;">
      <icon-tool style="font-size: 32px; color: var(--accent);" />
      <div style="font-size: 16px; font-weight: 600; color: var(--ink);">{{ title }}</div>
      <div style="font-size: 13px;">该模块在 M1/M2 里程碑内陆续点亮。当前已可用：概览、统一策略、网关清单、用户管理、统一资源对象、统一事件。</div>
    </div>
  </div>
</template>
<script setup lang="ts">
import { computed } from 'vue';
import { useRoute } from 'vue-router';
const route = useRoute();
const title = computed(() => (route.meta.title as string) || '建设中');
</script>
