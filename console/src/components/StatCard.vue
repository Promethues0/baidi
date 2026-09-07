<!--
  StatCard · KPI 统计卡（标签 / 数值 / 单位 / 趋势 / 说明）

  为什么要有它：Overview 的 `.bd-kpi`、Online 的四张会话卡、Audit 的 `.bd-mcard`、Alerts 的三个数、
  Users 的 `.bd-agg` 各是一套字号（30 / 28 / 26 / 20）与一套颜色写法（inline 十六进制居多）。
  KPI 是管理员一眼要读的数，数值与说明的层级、语义色的用法必须全站一个样。

  替代了什么形态：
    <a-card class="bd-kpi"><div class="bd-kpi__label">…</div><div class="bd-kpi__value">…</div><div class="bd-kpi__foot">…</div></a-card>
    <div class="bd-mcard"><div class="bd-mcard__num" :style="{ color: '#F53F3F' }">…</div></div>

  ★三态：value 为 null / undefined = **不可判定**，渲染成灰细的「—」并把 unknownText 当脚注——
  绝不塌成 0。这是本项目的硬纪律（Overview 在线会话 / Users 在线态 / DeviceStat 指标都吃过这个亏）。
  ★趋势（trend）只在页面**真有历史数据**时传；组件不会为没有 trend 的卡画一个箭头。
  ★选中态（active）：KPI 卡兼作筛选入口时，当前生效的那张由 :active 点亮（主色描边），样式在组件里，页面不再 scoped 一份。
  语义色只走 tone，不接受十六进制。
-->
<template>
  <div class="bd-stat" :class="[`bd-stat--${tone}`, { 'bd-stat--unknown': isUnknown, 'bd-stat--click': clickable, 'is-on': active }]">
    <div class="bd-stat__top">
      <span class="bd-stat__label">{{ label }}</span>
      <span v-if="$slots.badge" class="bd-stat__badge"><slot name="badge" /></span>
    </div>
    <div class="bd-stat__row">
      <span class="bd-stat__value" :class="{ 'bd-unknown': isUnknown }">{{ isUnknown ? '—' : value }}</span>
      <span v-if="unit && !isUnknown" class="bd-stat__unit">{{ unit }}</span>
      <span v-if="trend && !isUnknown" class="bd-stat__trend" :class="`bd-stat__trend--${trend.dir}`">
        <icon-arrow-rise v-if="trend.dir === 'up'" />
        <icon-arrow-fall v-else-if="trend.dir === 'down'" />
        <icon-minus v-else />
        {{ trend.text }}
      </span>
    </div>
    <div v-if="$slots.extra" class="bd-stat__extra"><slot name="extra" /></div>
    <div v-if="footText || $slots.foot" class="bd-stat__foot"><slot name="foot">{{ footText }}</slot></div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = withDefaults(defineProps<{
  label: string;
  /** 数值。null / undefined = 不可判定（画「—」，不画 0） */
  value?: number | string | null;
  unit?: string;
  /** 一句说明（口径 / 组成），不可判定时被 unknownText 取代 */
  foot?: string;
  /** 不可判定时的脚注：说清为什么判不出来（"无网关上报心跳"），别留空 */
  unknownText?: string;
  /** 语义色：只影响数值颜色 */
  tone?: 'default' | 'primary' | 'success' | 'warning' | 'danger';
  /** 趋势——只在页面真有历史数据时传 */
  trend?: { dir: 'up' | 'down' | 'flat'; text: string };
  /** 可点（作为筛选入口时）：给 hover 抬升与手型光标；点击事件由父级 @click 绑到根元素 */
  clickable?: boolean;
  /** 选中态（作为筛选入口且当前正按它筛时）：主色描边。★此前 Alerts / Online / UserState 三页各 scoped 一份 `> .is-on`，
   *  StatCard 自己没有这个态——选中的样子该由组件定，页面只说"选中了没有"。 */
  active?: boolean;
}>(), { tone: 'default', clickable: false, active: false });

const isUnknown = computed(() => props.value === null || props.value === undefined);
const footText = computed(() => (isUnknown.value ? (props.unknownText || props.foot) : props.foot));
</script>

<style scoped>
.bd-stat {
  background: var(--bd-bg-1); border: 1px solid var(--bd-border); border-radius: var(--bd-radius);
  box-shadow: var(--bd-shadow-1); padding: var(--bd-sp-4) var(--bd-sp-5); min-height: 112px;
  display: flex; flex-direction: column;
  transition: box-shadow var(--bd-dur-base) var(--bd-ease), border-color var(--bd-dur-base) var(--bd-ease);
}
.bd-stat--click { cursor: pointer; }
.bd-stat--click:hover { box-shadow: var(--bd-shadow-2); border-color: var(--bd-primary-b); }
/* 选中态：主色描边（inset 一圈，不改变盒尺寸）；hover 时仍保持描边，别让抬升阴影把"当前筛选"盖掉 */
.bd-stat.is-on, .bd-stat--click.is-on:hover { border-color: var(--bd-primary); box-shadow: inset 0 0 0 1px var(--bd-primary); }
.bd-stat__top { display: flex; align-items: center; gap: var(--bd-sp-2); }
.bd-stat__label { font-size: var(--bd-fs-md); color: var(--bd-t3); line-height: var(--bd-lh); }
.bd-stat__badge { margin-left: auto; }
.bd-stat__row { display: flex; align-items: baseline; gap: 6px; margin-top: 6px; }
.bd-stat__value { font-size: var(--bd-fs-2xl); font-weight: 700; line-height: 1.2; color: var(--bd-t1); letter-spacing: -.2px; }
.bd-stat--primary .bd-stat__value { color: var(--bd-primary); }
.bd-stat--success .bd-stat__value { color: var(--bd-success); }
.bd-stat--warning .bd-stat__value { color: var(--bd-warning); }
.bd-stat--danger .bd-stat__value { color: var(--bd-danger); }
.bd-stat__unit { font-size: 15px; font-weight: 400; color: var(--bd-t3); }
.bd-stat__trend { margin-left: auto; display: inline-flex; align-items: center; gap: 2px; font-size: var(--bd-fs-sm); font-weight: 500; color: var(--bd-t3); }
.bd-stat__trend--up { color: var(--bd-danger); }
.bd-stat__trend--down { color: var(--bd-success); }
.bd-stat__extra { margin-top: var(--bd-sp-2); }
.bd-stat__foot { margin-top: auto; padding-top: var(--bd-sp-2); font-size: var(--bd-fs-sm); color: var(--bd-t3); line-height: var(--bd-lh); }
.bd-stat--unknown .bd-stat__foot { color: var(--bd-t3); }
</style>
