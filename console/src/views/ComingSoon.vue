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
          <!-- ★出口按钮此前指向 '/posture/dashboard'——一条**不存在的路由**：
               它会落回 `:pathMatch(.*)*` 通配，也就是这一页自己。而这一页同时是
               管理台的 404 兜底页，于是"页面找不到 → 点唯一的按钮 → 还是这一页"。
               现在用 nav.ts 的 FIRST_PATH（导航的真实首页），改导航不会让它再次失效。 -->
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
