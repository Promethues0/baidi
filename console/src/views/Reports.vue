<template>
  <div class="bd-page">
    <PageHeader title="运营报表" subtitle="审计与告警的窗口聚合 · 每个数字都能指回 audit_log / alerts 里具体的行"
      :live="live" off-text="数据未读取" off-color="red">
      <a-radio-group v-model="days" type="button" size="small" @change="load">
        <a-radio value="7">7 天</a-radio>
        <a-radio value="30">30 天</a-radio>
      </a-radio-group>
      <a-button :loading="loading" @click="load">
        <template #icon><icon-refresh /></template>刷新
      </a-button>
    </PageHeader>

    <!--
      ★与设备状态/业务告警同一条例外纪律：这一页**没有降级演示数据**。
      报表的意义是"这段时间真实发生了什么"——编一份好看的占位报表，
      读者无从分辨它是真实聚合还是演示，而拿着编造的报表做汇报是最坏的误导。
      连不上（或权限不够——报表归审计权）就如实说。
    -->
    <div v-if="err" class="bd-notice bd-notice--danger">
      <icon-exclamation-circle-fill />
      <span>无法读取运营报表：{{ err }}。本页不提供演示数据——编造的报表无法与真实聚合区分。（报表归审计权限：security / system 管理员按三权分立读不到聚合过的审计正文）</span>
    </div>

    <!-- 首屏骨架：第一次 load() 回来之前不画空白卡，也不编任何数字。 -->
    <template v-else-if="!loaded">
      <div class="rp-cards">
        <div v-for="i in 5" :key="i" class="bd-card"><SkeletonBlock kind="stat" /></div>
      </div>
      <div class="bd-tablecard"><SkeletonBlock kind="table" :rows="7" :cols="9" /></div>
    </template>

    <template v-else-if="rep">
      <div v-if="rep.truncated" class="bd-notice bd-notice--warn">
        <icon-info-circle />
        <span>请求窗口已按审计留存策略截断到最近 {{ rep.days }} 天：更早的审计已被清理，补 0 会把"数据没了"伪装成"什么都没发生"。</span>
      </div>

      <!-- 合计卡 -->
      <div class="rp-cards">
        <StatCard label="审计条目" :value="fmt(rep.totals.entries)" :foot="`${rep.since} 起`" />
        <StatCard label="活跃账号" :value="fmt(rep.totals.activeAccounts)" foot="至少成功登录一次" />
        <!-- 成功 / 失败并排：主数是成功数（绿），单位位放失败数（红，见 .rp-dual）——
             两个数都是窗口内真实计数，不是比例。 -->
        <StatCard class="rp-dual" label="认证 成功 / 失败" :value="fmt(rep.totals.authOk)" :unit="`/ ${fmt(rep.totals.authFail)}`" tone="success" />
        <StatCard class="rp-dual" label="访问 放行 / 拒绝" :value="fmt(rep.totals.accessAllow)" :unit="`/ ${fmt(rep.totals.accessDeny)}`" tone="success" />
        <StatCard label="业务告警" :value="fmt(rep.alerts.total)" :foot="sevBrief">
          <template v-if="rep.alerts.pending" #badge><span class="bd-tg bd-tg--gold">待处理 {{ rep.alerts.pending }}</span></template>
        </StatCard>
      </div>

      <!-- 逐日表：审计是全量台账，零日如实显示 0（与采样类页面"空桶断线"相反，口径见后端注释） -->
      <div class="bd-tablecard">
        <div class="bd-card__h">逐日明细</div>
        <div class="bd-tablewrap">
          <table class="bd-table bd-table--zebra">
            <thead>
              <tr>
                <th>日期</th><th>认证成功</th><th>认证失败</th><th>访问放行</th><th>访问拒绝</th>
                <th>管理操作</th><th>安全事件</th><th>全部条目</th><th style="width: 30%">相对量</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="d in rep.daily" :key="d.date">
                <td class="bd-mono">{{ d.date }}</td>
                <td>{{ d.authOk || '·' }}</td>
                <td :class="{ 'rp-neg': d.authFail }">{{ d.authFail || '·' }}</td>
                <td>{{ d.accessAllow || '·' }}</td>
                <td :class="{ 'rp-neg': d.accessDeny }">{{ d.accessDeny || '·' }}</td>
                <td>{{ d.adminOps || '·' }}</td>
                <td :class="{ 'rp-warn': d.security }">{{ d.security || '·' }}</td>
                <td><b>{{ d.total }}</b></td>
                <td>
                  <div class="rp-bar"><div class="rp-bar__fill" :style="{ width: barW(d.total) }" /></div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="rp-two">
        <div class="bd-card">
          <div class="bd-card__h">登录最多的账号</div>
          <div class="bd-card__b">
            <EmptyState v-if="!rep.topLogin.length" size="sm" title="窗口内没有成功登录记录" />
            <div v-for="kv in rep.topLogin" :key="'l' + kv.name" class="rp-row">
              <span class="bd-mono">{{ kv.name }}</span>
              <span class="rp-row__n">{{ kv.value }}</span>
            </div>
          </div>
        </div>
        <div class="bd-card">
          <div class="bd-card__h">被拒最多的账号（deny + fail）</div>
          <div class="bd-card__b">
            <EmptyState v-if="!rep.topDenied.length" size="sm" tone="ok" title="窗口内没有拒绝/失败记录" />
            <div v-for="kv in rep.topDenied" :key="'d' + kv.name" class="rp-row">
              <span class="bd-mono">{{ kv.name }}</span>
              <span class="rp-row__n rp-neg">{{ kv.value }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="bd-notice bd-notice--plain rp-foot">
        <icon-info-circle />
        <span>需要逐条明细或对外取证时用审计中心的 CSV 导出（带防篡改链 seq/mac）；本页只做聚合，不替代导出。</span>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { api, type OpsReport } from '@/lib/api';
import PageHeader from '@/components/PageHeader.vue';
import StatCard from '@/components/StatCard.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

const days = ref<'7' | '30'>('7');
const rep = ref<OpsReport | null>(null);
/* 连接态三态：undefined = 首轮读取还没回来，页头不画连接标签。
 * ★不能写 ref(false)：那会让红色「数据未读取」在第一次请求回来之前就画出来——
 *   它宣告的是一件**还没发生**的事，慢网 / 大表下能持续好几秒，与「真的读失败了」完全同形。
 * 落定点：load() 的 try 尾（true）与 catch（false）。两条路径都必须落定，漏一条标签就永远不画（比误报更难发现）。 */
const live = ref<boolean | undefined>(undefined);
const loading = ref(false);
const err = ref('');
/** 首屏是否已完成一次加载（成功或失败都算）——只决定骨架屏何时让位，不改任何数据流。 */
const loaded = ref(false);

const sevZh: Record<string, string> = { critical: '严重', warning: '警告', info: '提示' };
const sevBrief = computed(() =>
  (rep.value?.alerts.bySeverity ?? []).map((s) => `${sevZh[s.name] ?? s.name} ${s.value}`).join(' · ')
);

const maxTotal = computed(() => Math.max(1, ...(rep.value?.daily ?? []).map((d) => d.total)));
function barW(n: number) { return `${Math.round((n / maxTotal.value) * 100)}%`; }
function fmt(n: number) { return n.toLocaleString('en-US'); }

async function load() {
  loading.value = true;
  try {
    rep.value = await api<OpsReport>(`/audit/report?days=${days.value}`);
    live.value = true;
    err.value = '';
  } catch (e) {
    live.value = false;
    err.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
    loaded.value = true;
  }
}
onMounted(load);
</script>

<style scoped>
/* 本页独有：五张合计卡的排布、逐日相对量条、两列榜单。KPI 卡 / 卡片头 / 空态 / 提示条都在共享件里。 */
.rp-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: var(--bd-sp-4); margin-bottom: var(--bd-sp-4); }
/* 「成功 / 失败」双数卡：单位位承载的是失败计数，用语义红把它与普通单位区分开。 */
.rp-dual :deep(.bd-stat__unit) { color: var(--bd-danger); font-weight: 600; }
.rp-two { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--bd-sp-4); margin-top: var(--bd-sp-4); }
@media (max-width: 960px) { .rp-two { grid-template-columns: 1fr; } }
.rp-row { display: flex; justify-content: space-between; padding: 6px 2px; border-bottom: 1px dashed var(--bd-border-2); font-size: var(--bd-fs-md); }
.rp-row:last-child { border-bottom: none; }
.rp-row__n { font-weight: 600; color: var(--bd-t1); }
.rp-neg { color: var(--bd-danger); }
.rp-warn { color: var(--bd-warning); }
.bd-tablewrap { overflow-x: auto; }
.rp-bar { height: 8px; border-radius: var(--bd-radius-xs); background: var(--bd-fill-2); overflow: hidden; }
.rp-bar__fill { height: 100%; border-radius: var(--bd-radius-xs); background: var(--bd-primary); opacity: .75; transition: width var(--bd-dur-slow) var(--bd-ease); }
.rp-foot { margin: var(--bd-sp-4) 0 0; }
</style>
