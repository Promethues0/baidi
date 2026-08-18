<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">策略管理</div>
        <div class="bd-page__sub">接入策略（同时在线设备上限 / 接入超时注销）+ 全局防爆破 · 每一项都有真实执行方</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'access' }" @click="tab = 'access'">接入策略</span>
      <span class="bd-tab" :class="{ on: tab === 'global' }" @click="tab = 'global'">全局策略</span>
    </div>

    <!-- ============ 接入策略（FR-POLICY-29/30，真接进敲门令牌）============ -->
    <div v-show="tab === 'access'" class="bd-acc">
      <div class="bd-card bd-note">
        <icon-info-circle />
        <div>
          这两条规则的执行点是<b>敲门令牌</b>（客户端每 15 秒回控制面续一次）：改动最迟在一个保活周期内生效，
          被拒的终端会收到写明原因的提示。<b>不涉及</b>按组织/用户组分级——本版本的接入策略是全局的，
          PRD 的策略继承（FR-POLICY-02~05）未实现，见下方「本版本未实现」。
        </div>
      </div>

      <div v-if="!live" class="bd-card bd-warn">
        <icon-exclamation-circle-fill />
        <div>未连上 baidi-control，下面显示的是本地默认值，改动不会保存。</div>
      </div>
      <div v-else-if="!resp.storeReady" class="bd-card bd-warn">
        <icon-exclamation-circle-fill />
        <div>当前存储后端不支持接入会话记账，这两条规则<b>整块不生效</b>（需 SQLite 后端）。</div>
      </div>

      <!-- 规则一：同时在线设备上限 -->
      <div class="bd-card bd-rule">
        <div class="bd-rule__h">
          <div>
            <div class="bd-rule__t">同时在线设备上限<span class="bd-fr">FR-POLICY-29</span></div>
            <div class="bd-rule__d">
              同一账号能同时接入的终端台数（0~1000）。名额<b>先到先得</b>：调小上限后，最晚接入的那几台会在
              一个保活周期内被挤掉。判据是「最近 {{ resp.onlineWindowSec }} 秒内还在续敲门令牌」。
            </div>
          </div>
          <a-switch v-model="p.deviceLimitEnabled" size="small" @change="save" />
        </div>
        <template v-if="p.deviceLimitEnabled">
          <div class="bd-row">
            <div class="bd-row__main">
              <div class="bd-row__label">
                上限台数
                <span v-if="p.maxDevices === 0" class="bd-risk">= 禁止接入</span>
              </div>
              <div class="bd-row__desc">
                {{ p.maxDevices === 0
                  ? 'PRD 原文：0 表示禁止登录。当前配置会拒绝该系统内所有终端的接入请求。'
                  : '超出上限的终端取不到敲门令牌，隧道在 30 秒内自然关闭。' }}
              </div>
            </div>
            <a-input-number v-model="p.maxDevices" :min="0" :max="1000" size="small" style="width: 96px" @change="save" />
            <span class="bd-row__unit">台</span>
          </div>
          <div class="bd-row">
            <div class="bd-row__main">
              <div class="bd-row__label">区分 PC 与移动端分别计数</div>
              <div class="bd-row__desc">
                平台取自终端的 posture 上报（<b>不是</b>客户端在敲门请求里自报——那等于让被判定方自己挑名额）；
                从未上报过 posture 的终端按 PC 计。
              </div>
            </div>
            <a-switch v-model="p.splitPlatform" size="small" @change="save" />
          </div>
          <div v-if="p.splitPlatform" class="bd-row">
            <div class="bd-row__main">
              <div class="bd-row__label">移动端上限</div>
              <div class="bd-row__desc">iOS / Android / HarmonyOS 单独一份名额，与 PC 互不挤占。</div>
            </div>
            <a-input-number v-model="p.maxDevicesMobile" :min="0" :max="1000" size="small" style="width: 96px" @change="save" />
            <span class="bd-row__unit">台</span>
          </div>
        </template>
      </div>

      <!-- 规则二：接入超时注销 -->
      <div class="bd-card bd-rule">
        <div class="bd-rule__h">
          <div>
            <div class="bd-rule__t">接入超时注销<span class="bd-fr">FR-POLICY-30</span></div>
            <div class="bd-rule__d">
              连续无<b>业务流量</b>超过时长即注销接入，须重新登录。判据来自网关的逐会话回执，
              <b>不是</b>敲门保活——客户端不退出就会一直敲门，拿保活当活跃的话这条规则永远不会触发。
            </div>
          </div>
          <a-switch v-model="p.idleEnabled" size="small" @change="save" />
        </div>
        <div v-if="p.idleEnabled && live && resp.storeReady && !resp.idleReady" class="bd-inline-warn">
          <icon-exclamation-circle-fill />
          <span>
            目前<b>没有任何网关</b>报过业务活跃时刻（需网关升级到带 <code>lastActive</code> 回执的版本）。
            在此之前这条规则<b>不会注销任何人</b>——判据缺席时一律放行，绝不拿「探不到」当「没有流量」。
          </span>
        </div>
        <template v-if="p.idleEnabled">
          <div class="bd-row">
            <div class="bd-row__main">
              <div class="bd-row__label">无流量时长</div>
              <div class="bd-row__desc">5 分钟 ~ 365 天（PRD 范围）。PC 端「无键鼠操作」未实现——控制面拿不到终端输入事件。</div>
            </div>
            <a-input-number v-model="p.idleMinutes" :min="5" :max="525600" size="small" style="width: 116px" @change="save" />
            <span class="bd-row__unit">分钟</span>
          </div>
        </template>
      </div>

      <!-- 当前接入会话（这两条规则的判定材料，逐条摆出来） -->
      <div class="bd-card">
        <div class="bd-sec__h plain">
          当前接入会话
          <span class="bd-cnt">{{ sessions.length }} 条</span>
        </div>
        <a-table :data="sessions" :pagination="false" size="small" :bordered="false">
          <template #columns>
            <a-table-column title="账号" data-index="account" :width="130" />
            <a-table-column title="终端指纹" :width="150">
              <template #cell="{ record }">
                <span class="bd-mono" :title="record.fingerprint">{{ shortFp(record.fingerprint) }}</span>
              </template>
            </a-table-column>
            <a-table-column title="平台" :width="110">
              <template #cell="{ record }">
                <span :class="{ 'bd-dim': !record.platform }">{{ record.platform || '不可判定' }}</span>
                <span v-if="p.splitPlatform" class="bd-tg bd-tg--sm">{{ isMobile(record.platform) ? '移动端' : 'PC' }}</span>
              </template>
            </a-table-column>
            <a-table-column title="来源 IP" data-index="ip" :width="130" />
            <a-table-column title="最近敲门" :width="130">
              <template #cell="{ record }">{{ ago(record.lastKnock) }}</template>
            </a-table-column>
            <a-table-column title="最近业务流量" :width="180">
              <template #cell="{ record }">
                <!-- ★三态：不可判定 / 从未 / 具体时刻。绝不把"网关没报"画成"刚刚活跃过"，
                     也不画成"很久没动"——前者会误放行，后者会把正在干活的人踢下线。 -->
                <span v-if="!record.activityKnown" class="bd-dim" title="没有任何网关报过这条会话的活跃时刻，超时规则对它不生效">
                  不可判定
                </span>
                <span v-else-if="!record.lastActive" class="bd-dim" title="网关明确报告：这条会话自建立起从未承载业务连接">
                  从未有业务连接
                </span>
                <span v-else>{{ ago(record.lastActive) }}</span>
              </template>
            </a-table-column>
            <a-table-column title="状态" :width="180">
              <template #cell="{ record }">
                <span class="bd-tg" :style="tagStyle(record.state === 'active' ? '#00B42A' : '#F53F3F')">
                  {{ record.state === 'active' ? '接入中' : '已注销' }}
                </span>
                <span v-if="record.endedReason" class="bd-dim bd-reason" :title="record.endedReason">{{ record.endedReason }}</span>
              </template>
            </a-table-column>
          </template>
          <template #empty>
            <div class="bd-empty">暂无接入会话（终端取过敲门令牌后出现在这里）</div>
          </template>
        </a-table>
        <div class="bd-tblnote">
          活跃时刻按 <b>(账号, 来源 IP)</b> 与网关回执对应——网关的会话表按源 IP 记，它不知道终端指纹。
          同一 NAT 出口下的两台终端会共用一个 IP，此时活跃时刻互相顶替，方向是「不该踢的不踢」。
        </div>
      </div>

      <!-- 如实声明 -->
      <div class="bd-card bd-unimpl">
        <div class="bd-unimpl__h"><icon-info-circle />本版本未实现（此前这里是一整套不生效的继承编辑器，已摘除）</div>
        <div v-for="n in ACCESS_UNIMPL" :key="n.label" class="bd-unimpl__row">
          <b>{{ n.label }}</b><span>{{ n.why }}</span>
        </div>
        <div class="bd-unimpl__f">取舍与理由见 docs/SCOPE.md 与 docs/ARCHITECTURE.md 第七节</div>
      </div>
    </div>

<!-- ============ 全局策略（复刻设计稿开关行）============ -->
    <div v-show="tab === 'global'" class="bd-two">
      <div class="bd-card bd-gsec-nav">
        <button v-for="g in globalSecs" :key="g.key" class="bd-gnav" :class="{ on: gsec === g.key }" @click="gsec = g.key">
          {{ g.label }}
        </button>
      </div>
      <div class="bd-card bd-gbody">
        <div v-for="g in globalSecs" v-show="gsec === g.key" :key="g.key">
          <div class="bd-sec__h plain">{{ g.label }}</div>
          <!--
            这里原先有六个纯前端开关（图形校验码 / 弱网优化 / 0RTT / 禁止浏览器登录 /
            强制安装客户端 / 强制升级 / 开机自启），保存时根本不提交、后端一处消费都没有。
            按「界面上任何一个勾都必须真能生效」的纪律整批摘除，改为如实列出未实现项。
            其中「禁止用户通过浏览器登录」尤其危险：它看起来能关掉七层 Web 代理这条
            免客户端接入路径，而实际上那条路照常敞着——一个会被当成已生效的安全措施。
          -->
          <div v-if="g.notes.length" class="bd-unimpl">
            <div class="bd-unimpl__h"><icon-info-circle />本版本未实现（此前这里是几个不生效的演示开关，已摘除）</div>
            <div v-for="n in g.notes" :key="n.label" class="bd-unimpl__row">
              <b>{{ n.label }}</b><span>{{ n.why }}</span>
            </div>
            <div class="bd-unimpl__f">取舍与理由见 docs/ARCHITECTURE.md 第七节</div>
          </div>
          <!-- 防暴力破解 · 真实接线（GET/PUT /security/lockout-config，消费方=控制面登录链路） -->
          <template v-if="g.key === 'brute'">
            <div class="bd-row">
              <div class="bd-row__main">
                <div class="bd-row__label">同 IP 连续登录错误锁定</div>
                <div class="bd-row__desc">同一来源 IP 在窗口内密码错误达阈值后锁定该 IP（换用户名也拦）；可在「监控中心 · 用户状态」解锁</div>
              </div>
              <a-switch v-model="lockCfg.ipEnabled" size="small" @change="saveLockoutCfg" />
            </div>
            <div class="bd-row">
              <div class="bd-row__main">
                <div class="bd-row__label">同用户名连续登录错误锁定</div>
                <div class="bd-row__desc">窗口内连续密码错误达阈值后锁定该账号（登录成功即清零计数）；锁定到期自动解除</div>
              </div>
              <a-switch v-model="lockCfg.accountEnabled" size="small" @change="saveLockoutCfg" />
            </div>
            <div class="bd-row">
              <div class="bd-row__main">
                <div class="bd-row__label">阈值与时长</div>
                <div class="bd-row__desc">两个维度共用：滑动窗口内失败达阈值即锁定；保存后即时生效并落库（重启保留）</div>
              </div>
              <span class="bd-thr">阈值 <a-input-number v-model="lockCfg.threshold" :min="1" :max="100" size="mini" style="width: 76px" @change="saveLockoutCfg" /> 次</span>
              <span class="bd-thr">窗口 <a-input-number v-model="windowMin" :min="1" :max="1440" size="mini" style="width: 76px" @change="saveLockoutCfg" /> 分钟</span>
              <span class="bd-thr">锁定 <a-input-number v-model="durationMin" :min="1" :max="1440" size="mini" style="width: 76px" @change="saveLockoutCfg" /> 分钟</span>
            </div>
          </template>
        </div>
      </div>
    </div>

      </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type AccessPolicy, type AccessPolicyResp, type DeviceSessionRow, type LockoutConfig } from '@/lib/api';

const tab = ref<'access' | 'global'>('access');
const live = ref(false);

/* ── 接入策略（FR-POLICY-29/30）── */
const p = reactive<AccessPolicy>({
  deviceLimitEnabled: false, maxDevices: 3, splitPlatform: false, maxDevicesMobile: 2,
  idleEnabled: false, idleMinutes: 480
});
const resp = reactive<{ onlineWindowSec: number; storeReady: boolean; idleReady: boolean }>({
  onlineWindowSec: 90, storeReady: true, idleReady: false
});
const sessions = ref<DeviceSessionRow[]>([]);

/** 摘除的那套编辑器里，每一项在这里都要有交代——不写的话，下一波审计会把它当"漏做"再实现一遍。 */
const ACCESS_UNIMPL: { label: string; why: string }[] = [
  { label: '按组织/用户组分级的策略继承（FR-POLICY-02~05）', why: '不做：接入策略当前是全局的。此前那棵继承树上的 8 个设置项落库后全仓零消费方，摘除而不是保留一个能点开却不生效的编辑器' },
  { label: '专用 DNS 下发 / 虚拟专线隔离（FR-POLICY-26/27）', why: '不做：分离式 DNS 由客户端接入剖面下发（已实现，但不经这一页配置）；虚拟专线需要终端侧全局路由接管 + 白名单，现架构未做' },
  { label: '登录时段限制（FR-POLICY-32）', why: '已实现，但在「安全防护 → 认证策略」里（offHours 规则），不在这一页——同一件事只留一个入口' },
  { label: '二次认证豁免期（FR-POLICY-33）', why: '不做：现有豁免是「授信终端」维度（认证策略 trustedDevice），没有基于浏览器 Cookie 的天数豁免' },
  { label: '卸载防护 / 进程防护', why: '不做：需要终端侧驱动或系统服务，桌面客户端是普通用户态进程' },
  { label: 'PC 端「无键鼠操作」超时（FR-POLICY-30 的另一半）', why: '不做：控制面拿不到终端输入事件。已实现的是「无业务流量」那一半，判据来自网关逐会话回执' }
];

function shortFp(fp: string) { return fp && fp.length > 14 ? fp.slice(0, 14) + '…' : fp; }
function isMobile(plat: string) { return ['ios', 'android', 'harmonyos'].includes((plat || '').toLowerCase()); }
function tagStyle(color: string) { return { color, background: color + '14' }; }
function ago(ts: number) {
  if (!ts) return '—';
  const d = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (d < 60) return d + ' 秒前';
  if (d < 3600) return Math.floor(d / 60) + ' 分钟前';
  if (d < 86400) return Math.floor(d / 3600) + ' 小时前';
  return Math.floor(d / 86400) + ' 天前';
}

async function loadAccess() {
  try {
    const r = await api<AccessPolicyResp>('/policies/access');
    Object.assign(p, r.policy);
    resp.onlineWindowSec = r.onlineWindowSec ?? 90;
    resp.storeReady = r.storeReady !== false;
    resp.idleReady = !!r.idleReady;
    sessions.value = r.sessions ?? [];
    live.value = true;
  } catch { live.value = false; }
}
let saving = false;
async function save() {
  if (saving) return;
  // 输入框被清空的瞬间（undefined/NaN）不提交，等填回合法值。
  if (p.maxDevices == null || p.maxDevicesMobile == null || p.idleMinutes == null) return;
  saving = true;
  try {
    await api('/policies/access', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(p)
    });
    Message.success('接入策略已保存，最迟一个保活周期（约 15 秒）后生效');
    await loadAccess();
  } catch {
    Message.error('保存失败（需管理员登录 / 后端在线）');
    await loadAccess(); // 回读生效值，避免界面停在一个没保存上的状态
  } finally { saving = false; }
}

/* ── 全局策略（复刻设计稿开关行）── */
const gsec = ref('brute');
// ★防暴力破解的两个「锁定」开关不在这里：它们已接到真实后端（见 lockCfg），
// 不再是纯前端摆设。此处只剩尚无后端的演示行。
const globalSecs = reactive([
  { key: 'brute', label: '防暴力破解', notes: [
    { label: '图形校验码', why: '不做：账号锁跨 IP 计数、IP 锁按 /64 聚合，两道闸已覆盖撞库；验证码补的那道缝（分布式喷洒）它自己也挡不住，而自研抗 OCR 的验证码做不好等于没做' }
  ] },
  { key: 'access', label: '接入加速与限制', notes: [
    { label: '弱网带宽优化 / 时延优化（0RTT）', why: '不做：隧道传输层未做拥塞与握手优化，开关背后没有任何实现' },
    { label: '禁止用户通过浏览器登录', why: '不做：七层 Web 代理（-web）是否开启由网关启动参数决定，控制面没有关掉它的通道——这个开关看起来能封掉免客户端接入，实际封不掉' }
  ] },
  { key: 'client', label: '客户端强管控', notes: [
    { label: '强制安装客户端 / 开机自启', why: '不做：需要终端管控通道（现架构客户端只拉不收）' },
    { label: '强制升级至最新客户端', why: '不做：灰度只决定「告诉谁有新版」，控制面不阻断旧版本登录（见 SCOPE.md 第 4 章）' }
  ] }
] as { key: string; label: string; notes: { label: string; why: string }[] }[]);

/* ── 防暴力破解 · 真实接线（BAIDI_LOCKOUT_* 的运行时覆盖，settings 落库）──
 * 开关与阈值直接读写 /security/lockout-config，控制面登录链路即时消费——不是摆设。 */
const lockCfg = reactive<LockoutConfig>({ threshold: 5, windowSec: 600, durationSec: 900, ipEnabled: true, accountEnabled: true });
const windowMin = computed({
  get: () => Math.round(lockCfg.windowSec / 60),
  set: (v: number) => { lockCfg.windowSec = Math.round(v) * 60; }
});
const durationMin = computed({
  get: () => Math.round(lockCfg.durationSec / 60),
  set: (v: number) => { lockCfg.durationSec = Math.round(v) * 60; }
});

async function loadLockoutCfg() {
  try {
    Object.assign(lockCfg, await api<LockoutConfig>('/security/lockout-config'));
  } catch { /* 离线演示：留本地默认值，保存时会提示失败 */ }
}
async function saveLockoutCfg() {
  // 输入框被清空的瞬间（undefined/NaN）不提交，等填回合法值
  if (!lockCfg.threshold || !lockCfg.windowSec || !lockCfg.durationSec) return;
  try {
    await api('/security/lockout-config', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(lockCfg)
    });
    Message.success('防爆破配置已保存并即时生效');
  } catch {
    Message.error('保存失败，请检查后端连接');
    await loadLockoutCfg(); // 回读生效值，避免界面停留在未生效的假状态
  }
}

onMounted(async () => {
  await loadAccess();
  await loadLockoutCfg();
});
</script>

<style scoped>
.bd-head__right { margin-left: auto; }

/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

.bd-two { display: flex; gap: 16px; align-items: flex-start; }

.bd-sec__h { font-size: 14px; font-weight: 600; padding: 16px 0 6px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-sec__h.plain { border: none; padding: 8px 0 12px; }
.bd-row { display: flex; align-items: center; gap: 12px; padding: 15px 0; border-bottom: 1px solid var(--bd-fill-1); }
.bd-row:last-child { border-bottom: none; }
.bd-row__main { flex: 1; min-width: 0; }
.bd-row__label { font-size: 13.5px; font-weight: 500; color: var(--bd-t1); display: flex; align-items: center; gap: 6px; }
.bd-row__desc { font-size: 12px; color: var(--bd-t3); margin-top: 3px; }
.bd-risk { font-size: 11px; color: var(--bd-warning); background: var(--bd-tag-gold-bg); padding: 1px 6px; border-radius: 4px; font-weight: 400; }
.bd-row__unit { font-size: 12.5px; color: var(--bd-t3); }
.bd-thr { font-size: 12.5px; color: var(--bd-t2); }

/* 全局策略 */
.bd-unimpl { margin: 10px 0 4px; padding: 12px 14px; background: var(--color-fill-1); border-radius: 8px; }
.bd-unimpl__h { display: flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--color-text-2); margin-bottom: 8px; }
.bd-unimpl__row { display: flex; gap: 10px; padding: 5px 0; font-size: 12.5px; line-height: 1.7; }
.bd-unimpl__row b { flex: none; min-width: 210px; color: var(--color-text-1); font-weight: 600; }
.bd-unimpl__row span { color: var(--color-text-3); }
.bd-unimpl__f { margin-top: 8px; font-size: 12px; color: var(--color-text-3); }
.bd-gsec-nav { width: 200px; flex: none; padding: 8px; }
.bd-gnav { width: 100%; text-align: left; border: none; background: transparent; font-size: 13px; color: var(--bd-t2); padding: 10px 12px; border-radius: 7px; cursor: pointer; }
.bd-gnav:hover { background: var(--bd-fill-2); }
.bd-gnav.on { background: var(--bd-primary-1); color: var(--bd-primary); font-weight: 600; }
.bd-gbody { flex: 1; min-width: 0; padding: 8px 24px 14px; }

/* ── 接入策略页专属样式（wave8 行动 13-①）── */
.bd-acc { display: flex; flex-direction: column; gap: 16px; }
.bd-note, .bd-warn { display: flex; gap: 10px; align-items: flex-start; font-size: 12.5px; line-height: 1.7; color: var(--bd-t2); }
.bd-note :deep(svg) { color: var(--bd-primary); margin-top: 3px; flex: none; }
.bd-warn { color: var(--bd-warning); }
.bd-warn :deep(svg) { margin-top: 3px; flex: none; }
.bd-rule__h { display: flex; align-items: flex-start; gap: 16px; padding-bottom: 10px; border-bottom: 1px solid var(--bd-fill-1); }
.bd-rule__h > div:first-child { flex: 1; }
.bd-rule__t { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-rule__d { font-size: 12px; color: var(--bd-t3); line-height: 1.7; margin-top: 5px; }
.bd-fr { margin-left: 8px; font-size: 11px; font-weight: 500; color: var(--bd-t4); }
.bd-inline-warn {
  display: flex; gap: 8px; align-items: flex-start; margin-top: 10px; padding: 9px 11px;
  background: rgba(255, 125, 0, .08); border-radius: 6px; font-size: 12px; line-height: 1.7; color: var(--bd-t2);
}
.bd-inline-warn :deep(svg) { color: var(--bd-warning); margin-top: 3px; flex: none; }
.bd-inline-warn code { font-family: var(--bd-font-mono, monospace); font-size: 11.5px; }
.bd-cnt { margin-left: 8px; font-size: 12px; font-weight: 400; color: var(--bd-t3); }
.bd-mono { font-family: var(--bd-font-mono, monospace); font-size: 12px; }
.bd-dim { color: var(--bd-t4); }
.bd-reason { margin-left: 8px; font-size: 11.5px; }
.bd-tg--sm { margin-left: 6px; font-size: 10.5px; padding: 0 5px; }
.bd-empty { padding: 26px 0; text-align: center; color: var(--bd-t4); font-size: 12.5px; }
.bd-tblnote { margin-top: 10px; font-size: 11.5px; color: var(--bd-t3); line-height: 1.7; }
</style>
