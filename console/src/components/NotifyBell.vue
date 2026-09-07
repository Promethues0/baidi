<template>
  <a-trigger v-model:popup-visible="open" trigger="click" position="br" :popup-offset="8" @popup-visible-change="onToggle">
    <button class="bd-bell" :class="{ on: open }" :title="bellTitle" aria-haspopup="menu" :aria-expanded="open">
      <icon-notification />
      <!-- ★角标只在取到真实计数时渲染：取不到就不画（「不知道有几条」≠「有 0 条」），
           为 0 也不画——红点的语义是「有事要办」。 -->
      <span v-if="pending !== undefined && pending > 0" class="bd-bell__dot">{{ pending > 99 ? '99+' : pending }}</span>
    </button>

    <template #content>
      <div class="bd-noti">
        <div class="bd-noti__h">
          <b>待处理告警</b>
          <RouterLink to="/monitor/alerts" class="bd-noti__all" @click="open = false">全部告警</RouterLink>
        </div>

        <div v-if="loading" class="bd-noti__msg">加载中…</div>
        <!-- ★三态必须分得开：加载中 / 取不到 / 确实没有。这里是管理员判断「要不要立刻
             处理」的第一眼，把「没加载出来」画成「一切正常」等于替系统背书。 -->
        <div v-else-if="err" class="bd-noti__msg bd-noti__msg--err">
          <icon-exclamation-circle-fill /> 待处理告警取不到（{{ err }}）——这里显示的**不是**「没有告警」
        </div>
        <div v-else-if="!items.length" class="bd-noti__msg bd-noti__msg--ok">
          <icon-check-circle-fill /> 没有待处理告警
        </div>

        <ul v-else class="bd-noti__list">
          <li v-for="a in items" :key="a.id" class="bd-noti__it" @click="goAlert()">
            <span class="bd-noti__sev" :class="a.severity" />
            <div class="bd-noti__body">
              <div class="bd-noti__t">{{ a.title }}</div>
              <div class="bd-noti__m">{{ catZh(a.category) }} · {{ ago(a.triggeredAt) }}</div>
            </div>
          </li>
        </ul>

        <!-- 列表只展示最近若干条，而角标是全量待处理数：两个数不一样时必须说清，
             否则"红点 12、列表 5 条"看起来像丢了 7 条。 -->
        <div v-if="!err && pending !== undefined && pending > items.length" class="bd-noti__more">
          共 {{ pending }} 条待处理，此处只列最近 {{ items.length }} 条
        </div>
      </div>
    </template>
  </a-trigger>
</template>

<script setup lang="ts">
/**
 * 顶栏通知铃铛。
 *
 * ★角标与侧栏角标同一个数据源（GET /alerts 的 counts.pending），另立一份必然对不上。
 */
import { computed, ref } from 'vue';
import { useRouter } from 'vue-router';
import { api } from '@/lib/api';
import type { Alert, AlertsResp } from '@/lib/api';
import { badgeCounts } from '@/lib/badges';

/** 下拉里最多列几条（角标仍是全量数，差额由 __more 说明）。 */
const MAX_ITEMS = 6;

const router = useRouter();
const open = ref(false);
const loading = ref(false);
const err = ref('');
const items = ref<Alert[]>([]);
const cats = ref<Record<string, string>>({});

/** 角标复用侧栏那份真实计数，不另发一次请求、也不另立一个可能对不上的数。 */
const pending = computed(() => badgeCounts.alerts);

const bellTitle = computed(() =>
  pending.value === undefined ? '待处理告警数取不到' :
  pending.value === 0 ? '没有待处理告警' : `${pending.value} 条待处理告警`);

async function onToggle(v: boolean) {
  if (!v) return;
  loading.value = true; err.value = '';
  try {
    // status/limit 都由后端支持，且后端保证 counts 不受这两者影响（角标要的是全局待办量）。
    const r = await api<AlertsResp>(`/alerts?status=pending&limit=${MAX_ITEMS}`);
    cats.value = r.categories ?? {};
    items.value = (r.alerts ?? []).filter((a) => a.status === 'pending');
  } catch (e) {
    err.value = e instanceof Error ? e.message : '未知错误';
    items.value = [];
  } finally {
    loading.value = false;
  }
}

function catZh(k: string): string { return cats.value[k] || k; }
function goAlert() { open.value = false; router.push('/monitor/alerts'); }

/** 相对时间。秒级 Unix 时间戳；未来时间按"刚刚"处理（服务器/本机时钟偏差）。 */
function ago(ts: number): string {
  const d = Math.floor(Date.now() / 1000) - ts;
  if (d < 60) return '刚刚';
  if (d < 3600) return `${Math.floor(d / 60)} 分钟前`;
  if (d < 86400) return `${Math.floor(d / 3600)} 小时前`;
  return `${Math.floor(d / 86400)} 天前`;
}
</script>

<style scoped>
/* 与 GlobalSearch 同理：铃铛也在顶栏，21 个管理页每页都渲染。尺度全部走 tokens.css。
   保留的裸像素只有版面尺寸（面板宽 340、列表限高 340）与两条 hairline（1px 分隔线、
   角标 1.5px 描边）——描边是把角标从顶栏底色上"抠"出来的一道细边，不属于间距阶梯。 */
.bd-bell {
  position: relative; width: 34px; height: 34px; border: none; background: transparent; border-radius: var(--bd-radius-s);
  display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--bd-t2); font-size: var(--bd-fs-lg);
}
.bd-bell:hover, .bd-bell.on { background: var(--bd-fill-2); }
.bd-bell:focus-visible { outline: var(--bd-focus-outline); outline-offset: 1px; }
/* 角标：实底语义色上的字用 --bd-on-color（不是 --bd-bg-1，那是底色）；
   描边取顶栏底色 --bd-bg-1（AppLayout 的 .bd-top 就是它），角标才像"浮在顶栏上"。 */
.bd-bell__dot {
  position: absolute; top: var(--bd-sp-1); right: var(--bd-sp-1); min-width: 15px; height: 15px; padding: 0 var(--bd-sp-1);
  background: var(--bd-danger); color: var(--bd-on-color); border-radius: var(--bd-radius-pill);
  font-size: var(--bd-fs-xs); font-weight: 600;
  display: flex; align-items: center; justify-content: center; border: 1.5px solid var(--bd-bg-1);
}

.bd-noti {
  width: 340px; background: var(--bd-bg-1); border: 1px solid var(--bd-border); border-radius: var(--bd-radius);
  box-shadow: var(--bd-shadow-2); overflow: hidden;
}
.bd-noti__h {
  display: flex; align-items: center; justify-content: space-between;
  padding: var(--bd-sp-3) var(--bd-sp-4); border-bottom: 1px solid var(--bd-border); font-size: var(--bd-fs-md);
}
.bd-noti__all { font-size: var(--bd-fs-sm); color: var(--bd-primary); text-decoration: none; }
.bd-noti__all:hover { text-decoration: underline; }
.bd-noti__msg { padding: var(--bd-sp-6) var(--bd-sp-4); text-align: center; font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-noti__msg--ok { color: var(--bd-success); }
.bd-noti__msg--err { color: var(--bd-danger); text-align: left; line-height: var(--bd-lh-loose); }
.bd-noti__list { list-style: none; margin: 0; padding: var(--bd-sp-1) 0; max-height: 340px; overflow-y: auto; }
.bd-noti__it { display: flex; gap: var(--bd-sp-2); padding: var(--bd-sp-2) var(--bd-sp-4); cursor: pointer; }
.bd-noti__it:hover { background: var(--bd-fill-1); }
.bd-noti__sev { width: 6px; height: 6px; border-radius: 50%; margin-top: 6px; flex: none; background: var(--bd-t4); }
.bd-noti__sev.warning { background: var(--bd-warning); }
.bd-noti__sev.critical { background: var(--bd-danger); }
.bd-noti__sev.info { background: var(--bd-primary); }
.bd-noti__body { min-width: 0; }
.bd-noti__t { font-size: var(--bd-fs-sm); color: var(--bd-t1); line-height: var(--bd-lh); }
.bd-noti__m { font-size: var(--bd-fs-xs); color: var(--bd-t3); margin-top: var(--bd-sp-1); }
.bd-noti__more {
  padding: var(--bd-sp-2) var(--bd-sp-4); border-top: 1px solid var(--bd-border);
  font-size: var(--bd-fs-xs); color: var(--bd-t3); background: var(--bd-fill-1);
}
</style>
