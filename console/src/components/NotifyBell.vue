<template>
  <a-trigger v-model:popup-visible="open" trigger="click" position="br" :popup-offset="8" @popup-visible-change="onToggle">
    <button class="bd-bell" :class="{ on: open }" :title="bellTitle" aria-haspopup="menu" :aria-expanded="open">
      <icon-notification />
      <!-- ★角标只在**取到真实计数**时渲染。此前这里是写死的 `6`：一个常驻在
           每一页右上角、永远是 6 的红点，与真实待处理数完全同形。
           取不到就不画（"我不知道有几条"≠"有 0 条"），为 0 时也不画红点——
           红点的语义是"有事要办"。 -->
      <span v-if="pending !== undefined && pending > 0" class="bd-bell__dot">{{ pending > 99 ? '99+' : pending }}</span>
    </button>

    <template #content>
      <div class="bd-noti">
        <div class="bd-noti__h">
          <b>待处理告警</b>
          <RouterLink to="/monitor/alerts" class="bd-noti__all" @click="open = false">全部告警</RouterLink>
        </div>

        <div v-if="loading" class="bd-noti__msg">加载中…</div>
        <!-- 三态分得开：加载中 / 取不到 / 确实没有。★"没加载出来"被画成"一切正常"
             正是这个铃铛该避免的事——它是管理员判断"要不要立刻处理"的第一眼。 -->
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
 * ★改造前：`<button class="bd-bell"><icon-notification /><span class="bd-bell__dot">6</span></button>`
 * ——红点写死 6，按钮没有任何 click handler。它与侧栏那两个已经被修过的写死角标
 * （'10' / '2'，见 nav.ts 顶部那段注释）是同一族缺陷，只是当时没有一起修：
 * 纪律只做了一半，而漏掉的这一半恰恰在最显眼的位置。
 *
 * 现在数据源与侧栏角标同一个（GET /alerts 的 counts.pending），两处不会打架。
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
.bd-bell {
  position: relative; width: 34px; height: 34px; border: none; background: transparent; border-radius: 8px;
  display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--bd-t2); font-size: 18px;
}
.bd-bell:hover, .bd-bell.on { background: var(--bd-fill-2); }
.bd-bell:focus-visible { outline: 2px solid var(--bd-primary); outline-offset: 1px; }
.bd-bell__dot {
  position: absolute; top: 4px; right: 5px; min-width: 15px; height: 15px; padding: 0 4px;
  background: var(--bd-danger); color: #fff; border-radius: 8px; font-size: 10px; font-weight: 600;
  display: flex; align-items: center; justify-content: center; border: 1.5px solid #fff;
}

.bd-noti {
  width: 340px; background: #fff; border: 1px solid var(--bd-border); border-radius: 10px;
  box-shadow: 0 6px 24px rgba(0, 0, 0, .1); overflow: hidden;
}
.bd-noti__h {
  display: flex; align-items: center; justify-content: space-between;
  padding: 11px 14px; border-bottom: 1px solid var(--bd-border); font-size: 13px;
}
.bd-noti__all { font-size: 12px; color: var(--bd-primary); text-decoration: none; }
.bd-noti__all:hover { text-decoration: underline; }
.bd-noti__msg { padding: 22px 14px; text-align: center; font-size: 12.5px; color: var(--bd-t3); }
.bd-noti__msg--ok { color: var(--bd-success); }
.bd-noti__msg--err { color: var(--bd-danger); text-align: left; line-height: 1.7; }
.bd-noti__list { list-style: none; margin: 0; padding: 4px 0; max-height: 340px; overflow-y: auto; }
.bd-noti__it { display: flex; gap: 9px; padding: 9px 14px; cursor: pointer; }
.bd-noti__it:hover { background: var(--bd-fill-1); }
.bd-noti__sev { width: 6px; height: 6px; border-radius: 50%; margin-top: 6px; flex: none; background: var(--bd-t4); }
.bd-noti__sev.warning { background: var(--bd-warning); }
.bd-noti__sev.critical { background: var(--bd-danger); }
.bd-noti__sev.info { background: var(--bd-primary); }
.bd-noti__body { min-width: 0; }
.bd-noti__t { font-size: 12.5px; color: var(--bd-t1); line-height: 1.5; }
.bd-noti__m { font-size: 11px; color: var(--bd-t3); margin-top: 3px; }
.bd-noti__more {
  padding: 8px 14px; border-top: 1px solid var(--bd-border);
  font-size: 11px; color: var(--bd-t3); background: var(--bd-fill-1);
}
</style>
