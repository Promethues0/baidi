<template>
  <div class="bd-page bd-coming">
    <a-result :status="known ? 'info' : '404'" :title="title">
      <template #subtitle>
        <template v-if="known">
          该模块尚未按《白帝控制台交互设计规范》落地。
        </template>
        <template v-else>
          地址 <code>{{ route.path }}</code> 不在控制台的导航里。可能是链接过期、拼写有误，
          或者你手里的这条 URL 来自另一套部署。
        </template>
      </template>
      <template #extra>
        <a-space>
          <a-tag v-if="leafTitle" color="arcoblue" bordered>{{ groupTitle }} · {{ leafTitle }}</a-tag>
          <!-- ★出口按钮必须走 nav.ts 的 FIRST_PATH：这一页同时是 404 兜底，写死一条
               路径一旦失效就会落回通配、也就是这一页自己，点了等于原地打转。 -->
          <a-button type="primary" @click="router.push(FIRST_PATH)">回到安全概览</a-button>
          <a-button @click="router.back()">返回上一页</a-button>
        </a-space>
      </template>
    </a-result>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { FIRST_PATH, locate } from '@/nav';

const route = useRoute();
const router = useRouter();
const loc = computed(() => locate(route.path));
const groupTitle = computed(() => loc.value.group?.label ?? '');
const leafTitle = computed(() => loc.value.leaf?.title ?? '');
/** known=这个路径确实是导航里的一项（只是还没落地）；否则就是一个纯粹找不到的地址。
 *  两者该说的话不一样——把 404 说成"建设中"会让人一直等一个不会来的功能。 */
const known = computed(() => !!loc.value.leaf);
const title = computed(() => (leafTitle.value ? leafTitle.value : '页面不存在'));
</script>

<style scoped>
.bd-coming { display: flex; align-items: center; justify-content: center; min-height: 60vh; }
code { font-family: var(--bd-mono, ui-monospace, SFMono-Regular, Menlo, monospace); font-size: 12.5px; }
</style>
