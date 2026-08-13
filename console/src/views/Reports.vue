<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">运营报表</div>
        <div class="bd-page__sub">审计与告警的窗口聚合 · 每个数字都能指回 audit_log / alerts 里具体的行</div>
      </div>
      <div class="bd-head__right">
        <a-radio-group v-model="days" type="button" size="small" @change="load">
          <a-radio value="7">7 天</a-radio>
          <a-radio value="30">30 天</a-radio>
        </a-radio-group>
        <a-tag :color="live ? 'green' : 'red'" bordered>
          <template #icon><icon-cloud /></template>
          {{ live ? '已连 baidi-control' : '未连控制面' }}
        </a-tag>
        <a-button :loading="loading" @click="load">
          <template #icon><icon-refresh /></template>刷新
        </a-button>
      </div>
    </div>

    <!--
      ★与设备状态/业务告警同一条例外纪律：这一页**没有降级演示数据**。
      报表的意义是"这段时间真实发生了什么"——编一份好看的占位报表，
      读者无从分辨它是真实聚合还是演示，而拿着编造的报表做汇报是最坏的误导。
      连不上（或权限不够——报表归审计权）就如实说。
    -->
    <div v-if="err" class="bd-tip bd-tip--err">
      <icon-exclamation-circle-fill class="bd-tip__ic" />
      <span>无法读取运营报表：{{ err }}。本页不提供演示数据——编造的报表无法与真实聚合区分。（报表归审计权限：security / system 管理员按三权分立读不到聚合过的审计正文）</span>
    </div>

    <template v-else-if="rep">
      <div v-if="rep.truncated" class="bd-tip">
        <icon-info-circle class="bd-tip__ic" />
        <span>请求窗口已按审计留存策略截断到最近 {{ rep.days }} 天：更早的审计已被清理，补 0 会把"数据没了"伪装成"什么都没发生"。</span>
      </div>

      <!-- 合计卡 -->
      <div class="rp-cards">
        <div class="bd-card rp-card">
          <div class="rp-card__v">{{ fmt(rep.totals.entries) }}</div>
          <div class="rp-card__k">审计条目（{{ rep.since }} 起）</div>
        </div>
        <div class="bd-card rp-card">
          <div class="rp-card__v">{{ fmt(rep.totals.activeAccounts) }}</div>
          <div class="rp-card__k">活跃账号（至少成功登录一次）</div>
        </div>
        <div class="bd-card rp-card">
          <div class="rp-card__v">
            <span style="color: var(--bd-success)">{{ fmt(rep.totals.authOk) }}</span>
            <span class="rp-card__sep">/</span>
            <span style="color: var(--bd-danger)">{{ fmt(rep.totals.authFail) }}</span>
          </div>
          <div class="rp-card__k">认证 成功 / 失败</div>
        </div>
        <div class="bd-card rp-card">
          <div class="rp-card__v">
            <span style="color: var(--bd-success)">{{ fmt(rep.totals.accessAllow) }}</span>
            <span class="rp-card__sep">/</span>
            <span style="color: var(--bd-danger)">{{ fmt(rep.totals.accessDeny) }}</span>
          </div>
          <div class="rp-card__k">访问 放行 / 拒绝</div>
        </div>
        <div class="bd-card rp-card">
          <div class="rp-card__v">{{ fmt(rep.alerts.total) }}<span v-if="rep.alerts.pending" class="rp-card__pend">待处理 {{ rep.alerts.pending }}</span></div>
          <div class="rp-card__k">业务告警（{{ sevBrief }}）</div>
        </div>
      </div>

      <!-- 逐日表：审计是全量台账，零日如实显示 0（与采样类页面"空桶断线"相反，口径见后端注释） -->
      <div class="bd-card">
        <div class="bd-card__title">逐日明细</div>
        <div class="bd-tablewrap">
          <table class="bd-table">
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
                <td :style="d.authFail ? 'color: var(--bd-danger)' : ''">{{ d.authFail || '·' }}</td>
                <td>{{ d.accessAllow || '·' }}</td>
                <td :style="d.accessDeny ? 'color: var(--bd-danger)' : ''">{{ d.accessDeny || '·' }}</td>
                <td>{{ d.adminOps || '·' }}</td>
                <td :style="d.security ? 'color: var(--bd-warning)' : ''">{{ d.security || '·' }}</td>
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
          <div class="bd-card__title">登录最多的账号</div>
          <div v-if="!rep.topLogin.length" class="bd-empty">窗口内没有成功登录记录</div>
          <div v-for="kv in rep.topLogin" :key="'l' + kv.name" class="rp-row">
            <span class="bd-mono">{{ kv.name }}</span>
            <span class="rp-row__n">{{ kv.value }}</span>
          </div>
        </div>
        <div class="bd-card">
          <div class="bd-card__title">被拒最多的账号（deny + fail）</div>
          <div v-if="!rep.topDenied.length" class="bd-empty">窗口内没有拒绝/失败记录</div>
          <div v-for="kv in rep.topDenied" :key="'d' + kv.name" class="rp-row">
            <span class="bd-mono">{{ kv.name }}</span>
            <span class="rp-row__n" style="color: var(--bd-danger)">{{ kv.value }}</span>
          </div>
        </div>
      </div>

      <div class="bd-page__foot">
        需要逐条明细或对外取证时用审计中心的 CSV 导出（带防篡改链 seq/mac）；本页只做聚合，不替代导出。
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { api, type OpsReport } from '@/lib/api';

const days = ref<'7' | '30'>('7');
const rep = ref<OpsReport | null>(null);
const live = ref(false);
const loading = ref(false);
const err = ref('');

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
  }
}
onMounted(load);
</script>

<style scoped>
.rp-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 12px; }
.rp-card { padding: 14px 16px; }
.rp-card__v { font-size: 22px; font-weight: 600; color: var(--bd-t1); }
.rp-card__sep { margin: 0 4px; color: var(--bd-t3); font-weight: 400; }
.rp-card__pend { margin-left: 8px; font-size: 12px; font-weight: 500; color: var(--bd-warning); }
.rp-card__k { margin-top: 4px; font-size: 12px; color: var(--bd-t3); }
.rp-two { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px; }
.rp-row { display: flex; justify-content: space-between; padding: 6px 2px; border-bottom: 1px dashed var(--bd-line); font-size: 13px; }
.rp-row:last-child { border-bottom: none; }
.rp-row__n { font-weight: 600; color: var(--bd-t1); }
.rp-bar { height: 8px; border-radius: 4px; background: var(--bd-fill1, rgba(0, 0, 0, 0.04)); overflow: hidden; }
.rp-bar__fill { height: 100%; border-radius: 4px; background: var(--bd-primary, #165dff); opacity: 0.75; }
.bd-page__foot { margin-top: 12px; font-size: 12px; color: var(--bd-t3); }
</style>
