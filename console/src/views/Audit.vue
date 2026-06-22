<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">审计中心</div>
        <div class="bd-page__sub">全链路留痕 · 跨设备查询 · 合规出口</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <button class="bd-btn" @click="openWizard"><icon-search />高级查询与导出</button>
        <button class="bd-btn bd-btn--ghost" @click="cfg = true"><icon-settings />日志配置</button>
      </div>
    </div>

    <!-- P10 聚合头 -->
    <div class="bd-aggrow">
      <!-- 四个分类计数卡 -->
      <div v-for="c in catCards" :key="c.key" class="bd-card bd-mcard">
        <div class="bd-mcard__top">
          <span class="bd-mcard__dot" :style="{ background: c.color }" />
          <span class="bd-mcard__label">{{ c.label }}</span>
        </div>
        <div class="bd-mcard__num" :style="{ color: c.color }">{{ fmtNum(c.value) }}</div>
        <div class="bd-mcard__sub">条 · 累计留痕</div>
      </div>

      <!-- 今日总量卡 -->
      <div class="bd-card bd-mcard bd-mcard--total">
        <div class="bd-mcard__top">
          <icon-clock-circle class="bd-mcard__ic" />
          <span class="bd-mcard__label">今日总量</span>
        </div>
        <div class="bd-mcard__num">{{ fmtNum(bundle.todayTotal) }}</div>
        <div class="bd-mcard__sub">条 · 较昨日 <span style="color: var(--bd-success)">+6.2%</span></div>
      </div>

      <!-- 磁盘水位卡 -->
      <div class="bd-card bd-mcard bd-disk">
        <div class="bd-mcard__top">
          <icon-storage class="bd-mcard__ic" />
          <span class="bd-mcard__label">磁盘水位</span>
          <span class="bd-disk__tag" :style="{ color: diskColor, background: diskColor + '14' }">{{ diskLabel }}</span>
        </div>
        <div class="bd-disk__main">
          <b :style="{ color: diskColor }">{{ bundle.disk.usedPct }}%</b>
          <span class="bd-disk__cap">/ {{ bundle.disk.totalGB }} GB</span>
        </div>
        <div class="bd-disk__track"><span class="bd-disk__fill" :style="{ width: bundle.disk.usedPct + '%', background: diskColor }" /></div>
        <div class="bd-mcard__sub">保留 {{ bundle.disk.retainDays }} 天 · 滚动清理</div>
      </div>
    </div>

    <!-- 日志表 -->
    <div class="bd-tablecard">
      <div class="bd-toolbar">
        <!-- 类别筛选 pill -->
        <div class="bd-pillrow">
          <span v-for="f in catFilters" :key="f.key" class="bd-pill2" :class="{ on: catSel === f.key }" @click="catSel = f.key">{{ f.label }}</span>
        </div>
        <div style="flex: 1" />
        <!-- 时间快选 pill -->
        <div class="bd-pillrow">
          <span v-for="t in timeFilters" :key="t.key" class="bd-pill2 bd-pill2--time" :class="{ on: timeSel === t.key }" @click="timeSel = t.key">{{ t.label }}</span>
        </div>
      </div>
      <table class="bd-table">
        <thead>
          <tr><th>时间</th><th>类别</th><th>用户</th><th>源 IP</th><th>事件</th><th class="r">判定</th></tr>
        </thead>
        <tbody>
          <tr v-for="(e, i) in shownLogs" :key="i">
            <td class="bd-mono">{{ e.time }}</td>
            <td><span class="bd-tg" :style="tagStyle(catMeta(e.category).color)">{{ catMeta(e.category).label }}</span></td>
            <td>{{ e.user }}</td>
            <td class="bd-mono">{{ e.srcIp }}</td>
            <td>{{ e.event }}</td>
            <td class="r"><span class="bd-tg" :style="tagStyle(verdictColor(e.verdict))">{{ verdictLabel(e.verdict) }}</span></td>
          </tr>
          <tr v-if="!shownLogs.length"><td colspan="6" style="text-align: center; color: var(--bd-t3); padding: 40px 0">当前筛选无匹配日志</td></tr>
        </tbody>
      </table>
      <div class="bd-pager">共 {{ shownLogs.length }} 条记录 · 时间范围「{{ timeFilters.find(t => t.key === timeSel)?.label }}」</div>
    </div>

    <!-- 高级导出向导 -->
    <a-modal v-model:visible="wiz.open" :width="640" :footer="false" title="高级查询与导出" unmount-on-close>
      <!-- 步进指示 -->
      <div class="bd-steps">
        <div v-for="(s, i) in stepLabels" :key="i" class="bd-step" :class="{ on: wiz.step === i, done: wiz.step > i }">
          <span class="bd-step__n">{{ wiz.step > i ? '✓' : i + 1 }}</span>{{ s }}
          <icon-right v-if="i < stepLabels.length - 1" class="bd-step__arr" />
        </div>
      </div>

      <!-- 步骤 1：搜索模式（分支点） -->
      <div v-if="wiz.step === 0" class="bd-wbody">
        <div class="bd-wtitle">选择搜索模式</div>
        <div class="bd-wdesc">先确定模式，下一步将按所选模式动态加载对应查询字段。</div>
        <div class="bd-modes">
          <button class="bd-mode" :class="{ on: wiz.mode === 'precise' }" @click="wiz.mode = 'precise'">
            <icon-search class="bd-mode__ic" />
            <b>日志精准搜索</b>
            <i>按账号 / 设备四元组 / 源 IP 锁定具体行为链路</i>
          </button>
          <button class="bd-mode" :class="{ on: wiz.mode === 'bulk' }" @click="wiz.mode = 'bulk'">
            <icon-archive class="bd-mode__ic" />
            <b>常见日志全量导出</b>
            <i>按日志类型批量导出系统 / 监控 / 扫描 / 安全日志</i>
          </button>
        </div>
      </div>

      <!-- 步骤 2：按模式分支 -->
      <div v-else-if="wiz.step === 1" class="bd-wbody">
        <!-- 精准分支 -->
        <template v-if="wiz.mode === 'precise'">
          <div class="bd-wtitle">精准搜索场景</div>
          <div class="bd-wdesc">选择分析场景，下方将加载对应输入字段。</div>
          <a-radio-group v-model="wiz.scene" direction="vertical" class="bd-scenes">
            <a-radio value="account">账号分析<i class="bd-scene__h">按用户名追溯该账号全部访问 / 认证记录</i></a-radio>
            <a-radio value="outbound">设备出向行为<i class="bd-scene__h">按四元组（源/目的 IP·端口）分析终端外联</i></a-radio>
            <a-radio value="inbound">设备入向行为<i class="bd-scene__h">按源 IP 分析对终端 / 资源的访问来源</i></a-radio>
          </a-radio-group>
          <div class="bd-field">
            <label v-if="wiz.scene === 'account'">用户名</label>
            <label v-else-if="wiz.scene === 'outbound'">四元组</label>
            <label v-else>源 IP</label>
            <a-input v-if="wiz.scene === 'account'" v-model="wiz.account" placeholder="如 zhangsan / zhangsan@corp" allow-clear />
            <a-input v-else-if="wiz.scene === 'outbound'" v-model="wiz.quad" placeholder="如 10.1.2.3:50321 → 203.0.113.8:443" allow-clear />
            <a-input v-else v-model="wiz.srcIp" placeholder="如 192.168.10.24" allow-clear />
          </div>
        </template>

        <!-- 全量分支 -->
        <template v-else>
          <div class="bd-wtitle">日志类型（可多选）</div>
          <div class="bd-wdesc">勾选需要全量导出的日志类型。</div>
          <a-checkbox-group v-model="wiz.bulkTypes" class="bd-checks">
            <a-checkbox v-for="t in bulkTypeOpts" :key="t.value" :value="t.value">
              <b>{{ t.label }}</b><i class="bd-scene__h">{{ t.desc }}</i>
            </a-checkbox>
          </a-checkbox-group>
        </template>
      </div>

      <!-- 步骤 3：设备 + 时间 + 导出 -->
      <div v-else class="bd-wbody">
        <div class="bd-wtitle">导出范围与确认</div>
        <div class="bd-field">
          <label>设备（可多选）</label>
          <a-select v-model="wiz.devices" multiple placeholder="选择目标设备" allow-clear>
            <a-option v-for="d in deviceOpts" :key="d" :value="d">{{ d }}</a-option>
          </a-select>
        </div>
        <div class="bd-field">
          <label>时间范围</label>
          <a-range-picker v-model="wiz.range" show-time style="width: 100%" />
        </div>
        <div class="bd-recap">
          <icon-info-circle />
          模式「<b>{{ wiz.mode === 'precise' ? '日志精准搜索' : '常见日志全量导出' }}</b>」 ·
          <template v-if="wiz.mode === 'precise'">场景「{{ sceneLabel }}」</template>
          <template v-else>{{ wiz.bulkTypes.length }} 类日志</template>
          · {{ wiz.devices.length || '全部' }} 台设备
        </div>
      </div>

      <!-- 步进按钮 + 门禁 -->
      <div class="bd-wfoot">
        <button v-if="wiz.step > 0" class="bd-btn bd-btn--ghost" @click="wiz.step--">上一步</button>
        <div style="flex: 1" />
        <button v-if="wiz.step < 2" class="bd-btn" :disabled="!canNext" :style="{ opacity: canNext ? 1 : 0.5 }" @click="wiz.step++">下一步</button>
        <button v-else class="bd-btn" @click="doExport"><icon-download />导出</button>
      </div>
    </a-modal>

    <!-- 日志配置 -->
    <a-modal v-model:visible="cfg" :width="460" title="日志配置" @ok="cfg = false" ok-text="保存" cancel-text="取消">
      <div class="bd-cfg">
        <div class="bd-cfgrow"><span>访问决策日志留痕</span><a-switch v-model="cfgVals.access" size="small" /></div>
        <div class="bd-cfgrow"><span>登录认证日志留痕</span><a-switch v-model="cfgVals.auth" size="small" /></div>
        <div class="bd-cfgrow"><span>管理操作日志留痕</span><a-switch v-model="cfgVals.admin" size="small" /></div>
        <div class="bd-cfgrow"><span>安全事件日志留痕</span><a-switch v-model="cfgVals.security" size="small" /></div>
        <div class="bd-cfgrow"><span>日志保留天数</span><a-input-number v-model="cfgVals.retain" :min="7" :max="365" size="small" style="width: 110px" /></div>
        <div class="bd-cfgrow"><span>合规出口（Syslog 转发）</span><a-switch v-model="cfgVals.syslog" size="small" /></div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type AuditBundle, type AuditEntry, type KV } from '@/lib/api';

const live = ref(false);
const cfg = ref(false);
const cfgVals = reactive({ access: true, auth: true, admin: true, security: true, retain: 90, syslog: false });

/* ── mock fallback（结构同 store.AuditBundle）── */
const MOCK: AuditBundle = {
  categories: [
    { name: '访问决策', value: 184320 },
    { name: '登录认证', value: 96240 },
    { name: '管理操作', value: 12880 },
    { name: '安全事件', value: 2360 }
  ],
  todayTotal: 8642,
  disk: { usedPct: 72, totalGB: 512, retainDays: 90 },
  logs: [
    { time: '2026-06-22 14:32:08', category: 'access', user: '张伟', srcIp: '192.168.10.24', event: '访问内部应用「OA 协同」', verdict: 'allow' },
    { time: '2026-06-22 14:31:55', category: 'auth', user: '李娜', srcIp: '10.1.2.33', event: '客户端登录 · 设备指纹校验', verdict: 'mfa' },
    { time: '2026-06-22 14:30:42', category: 'access', user: '王强', srcIp: '203.0.113.8', event: '访问「财务系统」未授权资源', verdict: 'deny' },
    { time: '2026-06-22 14:29:17', category: 'security', user: '系统', srcIp: '192.168.10.99', event: '检测到异常端口扫描行为', verdict: 'fail' },
    { time: '2026-06-22 14:28:03', category: 'admin', user: 'admin', srcIp: '10.0.0.2', event: '修改全局策略「禁止浏览器登录」', verdict: 'ok' },
    { time: '2026-06-22 14:26:41', category: 'auth', user: '赵敏', srcIp: '172.16.4.18', event: '短信验证码二次认证', verdict: 'ok' },
    { time: '2026-06-22 14:25:12', category: 'access', user: '刘洋', srcIp: '192.168.20.7', event: '访问隧道应用「研发 Git」', verdict: 'allow' },
    { time: '2026-06-22 14:23:58', category: 'security', user: '陈静', srcIp: '198.51.100.5', event: '连续密码错误触发 IP 锁定', verdict: 'deny' },
    { time: '2026-06-22 14:22:30', category: 'admin', user: 'admin', srcIp: '10.0.0.2', event: '新增访问者「外包-周磊」', verdict: 'ok' },
    { time: '2026-06-22 14:20:11', category: 'auth', user: '孙浩', srcIp: '10.1.5.66', event: '浏览器登录被客户端强管控拦截', verdict: 'fail' }
  ]
};
const bundle = ref<AuditBundle>(MOCK);

/* ── P10 分类卡 ── */
const CAT_COLOR: Record<string, string> = { '访问决策': '#165DFF', '登录认证': '#722ED1', '管理操作': '#00B42A', '安全事件': '#FF7D00' };
const catCards = computed(() =>
  bundle.value.categories.map((c: KV) => ({ key: c.name, label: c.name, value: c.value, color: CAT_COLOR[c.name] ?? '#165DFF' }))
);
function fmtNum(n: number) { return n.toLocaleString('en-US'); }

/* ── 磁盘水位上色 ── */
const diskColor = computed(() => {
  const p = bundle.value.disk.usedPct;
  return p >= 80 ? 'var(--bd-danger)' : p >= 60 ? 'var(--bd-warning)' : 'var(--bd-success)';
});
const diskLabel = computed(() => {
  const p = bundle.value.disk.usedPct;
  return p >= 80 ? '偏高' : p >= 60 ? '关注' : '健康';
});

/* ── 日志表筛选 ── */
const catFilters = [
  { key: 'all', label: '全部' }, { key: 'access', label: '访问' }, { key: 'auth', label: '认证' },
  { key: 'admin', label: '管理' }, { key: 'security', label: '安全' }
];
const timeFilters = [{ key: 'today', label: '今天' }, { key: '7d', label: '7 天' }, { key: '30d', label: '30 天' }];
const catSel = ref('all');
const timeSel = ref('today');
const shownLogs = computed<AuditEntry[]>(() =>
  catSel.value === 'all' ? bundle.value.logs : bundle.value.logs.filter((l) => l.category === catSel.value)
);

function catMeta(c: AuditEntry['category']) {
  return {
    access: { label: '访问决策', color: '#165DFF' },
    auth: { label: '登录认证', color: '#722ED1' },
    admin: { label: '管理操作', color: '#00B42A' },
    security: { label: '安全事件', color: '#FF7D00' }
  }[c];
}
function verdictColor(v: AuditEntry['verdict']) {
  if (v === 'allow' || v === 'ok') return '#00B42A';
  if (v === 'deny' || v === 'fail') return '#F53F3F';
  return '#FF7D00'; // mfa
}
function verdictLabel(v: AuditEntry['verdict']) {
  return { allow: '放行', deny: '拒绝', mfa: '二次认证', ok: '成功', fail: '失败' }[v];
}
function tagStyle(color: string) { return { color, background: color + '14' }; }

/* ── 高级导出向导 ── */
const stepLabels = ['搜索模式', '查询字段', '范围与导出'];
const wiz = reactive({
  open: false,
  step: 0,
  mode: '' as '' | 'precise' | 'bulk',
  scene: 'account' as 'account' | 'outbound' | 'inbound',
  account: '', quad: '', srcIp: '',
  bulkTypes: [] as string[],
  devices: [] as string[],
  range: [] as string[]
});
const bulkTypeOpts = [
  { value: 'service', label: '系统服务', desc: '服务启停 / 进程守护 / 配置变更' },
  { value: 'monitor', label: '系统监控', desc: 'CPU / 内存 / 隧道吞吐指标' },
  { value: 'scan', label: '文件扫描', desc: '终端文件完整性与病毒扫描' },
  { value: 'safe', label: '系统安全', desc: '入侵检测 / 暴破防护 / 异常告警' }
];
const deviceOpts = ['网关-华东-01', '网关-华东-02', '网关-华南-01', '终端-WIN-张伟', '终端-MAC-李娜'];
const sceneLabel = computed(() => ({ account: '账号分析', outbound: '设备出向行为', inbound: '设备入向行为' }[wiz.scene]));

function openWizard() {
  wiz.open = true; wiz.step = 0; wiz.mode = '';
  wiz.scene = 'account'; wiz.account = ''; wiz.quad = ''; wiz.srcIp = '';
  wiz.bulkTypes = []; wiz.devices = []; wiz.range = [];
}

/* 门禁：未选模式不可下一步；第二步精准需填字段 / 全量需勾类型 */
const canNext = computed(() => {
  if (wiz.step === 0) return !!wiz.mode;
  if (wiz.step === 1) {
    if (wiz.mode === 'precise') {
      const v = wiz.scene === 'account' ? wiz.account : wiz.scene === 'outbound' ? wiz.quad : wiz.srcIp;
      return !!v.trim();
    }
    return wiz.bulkTypes.length > 0;
  }
  return true;
});

function doExport() {
  wiz.open = false;
  Message.success('导出任务已创建');
}

/* ── 拉取 ── */
onMounted(async () => {
  try {
    const b = await api<AuditBundle>('/audit');
    bundle.value = b; live.value = true;
  } catch { live.value = false; }
});
</script>

<style scoped>
/* ── P10 聚合头 ── */
.bd-aggrow { display: flex; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
.bd-mcard { flex: 1; min-width: 168px; padding: 16px 18px; }
.bd-mcard__top { display: flex; align-items: center; gap: 8px; }
.bd-mcard__dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }
.bd-mcard__ic { font-size: 15px; color: var(--bd-t3); }
.bd-mcard__label { font-size: 12.5px; color: var(--bd-t3); font-weight: 500; }
.bd-mcard__num { font-size: 26px; font-weight: 700; color: var(--bd-t1); margin: 8px 0 2px; letter-spacing: .3px; }
.bd-mcard__sub { font-size: 11.5px; color: var(--bd-t3); }
.bd-mcard--total { background: linear-gradient(135deg, var(--bd-primary-1), #fff); }

/* 磁盘水位卡 */
.bd-disk { min-width: 210px; }
.bd-disk__tag { font-size: 11px; padding: 1px 7px; border-radius: 4px; font-weight: 500; margin-left: auto; }
.bd-disk__main { display: flex; align-items: baseline; gap: 6px; margin: 8px 0 8px; }
.bd-disk__main b { font-size: 26px; font-weight: 700; }
.bd-disk__cap { font-size: 13px; color: var(--bd-t3); }
.bd-disk__track { height: 8px; background: var(--bd-fill-2); border-radius: 6px; overflow: hidden; margin-bottom: 8px; }
.bd-disk__fill { display: block; height: 100%; border-radius: 6px; transition: width .3s; }

/* ── 日志表筛选 pill ── */
.bd-pillrow { display: flex; gap: 6px; }
.bd-pill2 { font-size: 12.5px; color: var(--bd-t2); padding: 5px 13px; border-radius: 14px; cursor: pointer; background: var(--bd-fill-1); border: 1px solid transparent; transition: all .12s; }
.bd-pill2:hover { background: var(--bd-fill-2); }
.bd-pill2.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); border-color: var(--bd-primary-b); }
.bd-pill2--time.on { color: var(--bd-primary); }

/* ── 向导 ── */
.bd-steps { display: flex; align-items: center; gap: 6px; padding: 4px 0 18px; border-bottom: 1px solid var(--bd-fill-2); margin-bottom: 18px; }
.bd-step { display: flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--bd-t3); }
.bd-step__n { width: 20px; height: 20px; border-radius: 50%; background: var(--bd-fill-2); color: var(--bd-t3); font-size: 11px; display: inline-flex; align-items: center; justify-content: center; font-weight: 600; flex: none; }
.bd-step.on { color: var(--bd-t1); font-weight: 600; }
.bd-step.on .bd-step__n { background: var(--bd-primary); color: #fff; }
.bd-step.done .bd-step__n { background: var(--bd-success); color: #fff; }
.bd-step__arr { color: var(--bd-t4); font-size: 13px; margin: 0 2px; }

.bd-wbody { min-height: 220px; }
.bd-wtitle { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-wdesc { font-size: 12.5px; color: var(--bd-t3); margin: 4px 0 16px; }

/* 模式分支卡 */
.bd-modes { display: flex; gap: 14px; }
.bd-mode { flex: 1; text-align: left; background: #fff; border: 1.5px solid var(--bd-border); border-radius: var(--bd-radius); padding: 18px 16px; cursor: pointer; transition: all .15s; display: flex; flex-direction: column; gap: 4px; }
.bd-mode:hover { border-color: var(--bd-primary-b); }
.bd-mode.on { border-color: var(--bd-primary); background: var(--bd-primary-1); box-shadow: 0 2px 10px rgba(22, 93, 255, .12); }
.bd-mode__ic { font-size: 22px; color: var(--bd-primary); margin-bottom: 6px; }
.bd-mode b { font-size: 14px; color: var(--bd-t1); }
.bd-mode i { font-style: normal; font-size: 12px; color: var(--bd-t3); line-height: 1.5; }

/* 场景单选 / 字段 */
.bd-scenes { display: flex; flex-direction: column; gap: 4px; margin-bottom: 14px; }
.bd-scene__h { display: block; font-style: normal; font-size: 11.5px; color: var(--bd-t3); margin-top: 2px; }
.bd-checks { display: flex; flex-direction: column; gap: 10px; }
.bd-checks b { font-size: 13px; color: var(--bd-t1); font-weight: 500; }
.bd-field { margin-top: 14px; }
.bd-field label { display: block; font-size: 12.5px; color: var(--bd-t2); font-weight: 500; margin-bottom: 8px; }

.bd-recap { margin-top: 16px; display: flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--bd-t2); background: var(--bd-tag-blue-bg); border: 1px solid var(--bd-primary-b); border-radius: 8px; padding: 10px 13px; line-height: 1.6; }
.bd-recap b { color: var(--bd-primary); }

.bd-wfoot { display: flex; align-items: center; gap: 10px; margin-top: 22px; padding-top: 16px; border-top: 1px solid var(--bd-fill-2); }
.bd-btn[disabled] { cursor: not-allowed; }

/* 日志配置 */
.bd-cfg { display: flex; flex-direction: column; }
.bd-cfgrow { display: flex; align-items: center; justify-content: space-between; padding: 11px 0; border-bottom: 1px solid var(--bd-fill-1); font-size: 13px; color: var(--bd-t1); }
.bd-cfgrow:last-child { border-bottom: none; }
</style>
