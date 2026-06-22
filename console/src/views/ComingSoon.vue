<template>
  <div class="bd-page bd-coming">
    <a-result status="info" :title="title">
      <template #subtitle>
        该模块正按《白帝控制台交互设计规范》建设中 —— 将统一采用<b>创建向导 / 抽屉编辑 / 继承可视化 / 提交影响预览 / 实时态势</b>等交互范式，区别于传统堆表格管理后台。
      </template>
      <template #extra>
        <a-space>
          <a-tag v-if="leafTitle" color="arcoblue" bordered>{{ groupTitle }} · {{ leafTitle }}</a-tag>
          <a-button type="primary" @click="$router.push('/posture/dashboard')">返回安全监控大屏</a-button>
        </a-space>
      </template>
    </a-result>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useRoute } from 'vue-router';
import { locate } from '@/nav';

const route = useRoute();
const loc = computed(() => locate(route.path));
const groupTitle = computed(() => loc.value.group?.title ?? '');
const leafTitle = computed(() => loc.value.leaf?.title ?? '');
const title = computed(() => (leafTitle.value ? `${leafTitle.value}` : '建设中'));
</script>

<style scoped>
.bd-coming { display: flex; align-items: center; justify-content: center; min-height: 60vh; }
</style>
