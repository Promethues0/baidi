<template>
  <div class="bd-page">
    <!-- 离线文案按本页真实处境给：读不到时下面显示的是**本地默认值**（不是编出来的演示
         数据、也不是库里生效的值），页顶那条 warn 里另有后端原话。 -->
    <PageHeader title="策略管理" subtitle="接入策略（同时在线设备上限 / 接入超时注销）+ 全局防爆破 · 每一项都有真实执行方"
      :live="live" off-text="本地默认值" off-color="orange" />

    <!-- Tab 切换：真 button（可 Tab、可回车），外观沿用分段式页签 -->
    <div class="bd-tabs" role="tablist">
      <button type="button" class="bd-tab" role="tab" :aria-selected="tab === 'access'" @click="tab = 'access'">接入策略</button>
      <button type="button" class="bd-tab" role="tab" :aria-selected="tab === 'global'" @click="tab = 'global'">全局策略</button>
    </div>

    <!-- ============ 接入策略（FR-POLICY-29/30，真接进敲门令牌）============ -->
    <!-- 首屏骨架：loadAccess() 回来之前不画本地默认值——那一瞬显示的开关状态不是库里的。 -->
    <div v-show="tab === 'access'" v-if="!loaded" class="bd-acc">
      <div v-for="i in 2" :key="i" class="bd-card"><SkeletonBlock kind="card" :rows="3" /></div>
      <div class="bd-card"><SkeletonBlock kind="table" :rows="3" :cols="6" /></div>
    </div>
    <div v-show="tab === 'access'" v-else class="bd-acc">
      <div class="bd-notice">
        <icon-info-circle />
        <div class="bd-notice__body">
          C/S 客户端这条路的执行点是<b>敲门令牌</b>（客户端每 15 秒回控制面续一次）：改动最迟在一个保活周期内生效，
          被拒的终端会收到写明原因的提示。B/S（浏览器）那条路另有执行点，覆盖面<b>逐条不同</b>，见每条规则下的说明。
          <b>不涉及</b>按组织/用户组分级——本版本的接入策略是全局的，
          PRD 的策略继承（FR-POLICY-02~05）未实现，见下方「本版本未实现」。
        </div>
      </div>

      <!-- ★归因必须来自后端原话：读不到这一页有两种截然不同的处境——连不上控制面，
           或者 403（这一页归安全管理员一权）。只说「未连上 baidi-control」会把一次
           权限拒绝说成断网，管理员照着去查网络、去重登。 -->
      <div v-if="live === false" class="bd-notice bd-notice--warn">
        <icon-exclamation-circle-fill />
        <div class="bd-notice__body">
          接入策略未读取：下面显示的是<b>本地默认值</b>（不是库里生效的值），改动不会保存。
          <div v-if="accessErr" class="bd-hint">后端原话：{{ accessErr }}</div>
        </div>
      </div>
      <div v-else-if="!resp.storeReady" class="bd-notice bd-notice--warn">
        <icon-exclamation-circle-fill />
        <div class="bd-notice__body">当前存储后端不支持接入会话记账，这两条规则<b>整块不生效</b>（需 SQLite 后端）。</div>
      </div>

      <!-- 规则一：同时在线设备上限 -->
      <div class="bd-card bd-card--pad bd-rule">
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
                <span v-if="p.maxDevices === 0" class="bd-tg bd-tg--gold">= 禁止接入</span>
              </div>
              <div class="bd-row__desc">
                {{ p.maxDevices === 0
                  ? 'PRD 原文：0 表示禁止登录。当前配置会拒绝该系统内所有终端的接入请求。'
                  : '超出上限的终端取不到敲门令牌，隧道在 30 秒内自然关闭。' }}
              </div>
            </div>
            <a-input-number v-model="p.maxDevices" :min="0" :max="1000" size="small" class="bd-num bd-num--s" @change="save" />
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
            <a-input-number v-model="p.maxDevicesMobile" :min="0" :max="1000" size="small" class="bd-num bd-num--s" @change="save" />
            <span class="bd-row__unit">台</span>
          </div>
          <!-- ★B/S 覆盖面必须逐字说清，而不是让人以为「策略是全局的、当然管所有接入形态」。
               浏览器没有设备指纹：拿源 IP 当键会让同 NAT 出口两人共用一个名额（互相顶替），
               换个网络又多一个名额；而且它会与 C/S 抢同一个名额池，一次网页访问就能把
               一台正在用的终端挤下线。所以「上限 N 台」只统计 C/S，只有 0 那一档兼管浏览器。 -->
          <div class="bd-notice bd-notice--warn bd-rule__notice">
            <icon-info-circle />
            <div class="bd-notice__body">
              <b>浏览器（B/S）接入</b>：上限台数<b>只统计 C/S 客户端</b>——浏览器没有设备指纹，
              把源 IP 或 Cookie 当"设备"会让这个数字变成假话（同一出口两人共用一个名额、换个网络又多一个）。
              <template v-if="p.maxDevices === 0">
                当前上限为 <b>0（禁止接入）</b>：这一档是账号维度的，<b>浏览器接入同样被拒</b>（按 PC 计）。
              </template>
              <template v-else>
                只有把上限设为 <b>0（禁止接入）</b>时才会连浏览器一起挡住。
              </template>
              <template v-if="p.splitPlatform">
                分平台计数下，浏览器没有平台判据，与"从未上报 posture 的终端"同一条约定——<b>落进 PC 桶</b>。
              </template>
            </div>
          </div>
        </template>
      </div>

      <!-- 规则二：接入超时注销 -->
      <div class="bd-card bd-card--pad bd-rule">
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
        <div v-if="p.idleEnabled && live && resp.storeReady && !resp.idleReady" class="bd-notice bd-notice--warn bd-rule__notice">
          <icon-exclamation-circle-fill />
          <div class="bd-notice__body">
            目前<b>没有任何网关</b>报过 C/S 隧道会话的业务活跃时刻（需网关升级到带 <code>lastActive</code> 回执的版本）。
            在此之前这条规则<b>不会注销任何客户端接入</b>——判据缺席时一律放行，绝不拿「探不到」当「没有流量」。
            <b>浏览器接入不受这句话影响</b>：那条路的活跃度由网关逐请求判定，覆盖面见下方。
          </div>
        </div>
        <template v-if="p.idleEnabled">
          <div class="bd-row">
            <div class="bd-row__main">
              <div class="bd-row__label">无流量时长</div>
              <div class="bd-row__desc">5 分钟 ~ 365 天（PRD 范围）。PC 端「无键鼠操作」未实现——控制面拿不到终端输入事件。</div>
            </div>
            <a-input-number v-model="p.idleMinutes" :min="5" :max="525600" size="small" class="bd-num" @change="save" />
            <span class="bd-row__unit">分钟</span>
          </div>
          <!-- ★B/S 这条路是**真兑现**的（L7 逐请求鉴权天然带活跃度信号），但执行方在网关侧：
               「控制面下发了多少」与「网关在执行多少」是两件事，只能靠网关回执来判。
               一台还没升级的网关上的浏览器接入不会被注销，而这一页此前只会写「已启用 · N 分钟」。 -->
          <div class="bd-notice bd-rule__notice">
            <icon-info-circle />
            <div class="bd-notice__body">
              <b>浏览器（B/S）接入</b>：本规则同样生效，执行点在网关的七层代理上（每个 HTTP 请求都是业务流量，
              超时即注销该会话并要求回门户重新进入）。<b>门户登录态本身不受影响</b>——注销单条浏览器会话
              不能连带注销该账号的控制面令牌，那会把他的 C/S 隧道一起断掉。
              <b>WebSocket 等已升级的长连接不受本规则约束</b>：101 之后是裸字节转发，网关看不见上面还有没有流量，
              按"无请求即空闲"去切会切断正在传数据的连接；它们另有一条硬上界（不超过会话 Cookie 寿命）。
              <div v-if="webCoverageKnown" class="bd-hint">
                <template v-if="webCov.idleEnforcing.length">
                  正在执行的网关：<b>{{ webCov.idleEnforcing.join('、') }}</b>。
                </template>
                <template v-if="webCov.idleUnreported.length">
                  <b class="bd-warn-t">网关 {{ webCov.idleUnreported.join('、') }} 未回报执行阈值</b>（多为旧版本）——
                  经它们接入的浏览器<b>不会</b>被注销。
                </template>
                <template v-if="!webCov.idleEnforcing.length && !webCov.idleUnreported.length">
                  当前没有在线网关开启七层 Web 代理，本规则在 B/S 上暂无适用对象。
                </template>
              </div>
              <div v-else class="bd-hint">当前控制面未下发 B/S 覆盖面，哪几台网关在执行<b>判不出来</b>。</div>
            </div>
          </div>
        </template>
      </div>

      <!-- 当前接入会话（这两条规则的判定材料，逐条摆出来） -->
      <div class="bd-card">
        <div class="bd-card__h">
          当前接入会话
          <!-- 计数也不许在读取失败时写 0：这张表是上面两条规则的判定材料，
               「0 条」等于宣告"此刻没人接入"。 -->
          <span class="bd-card__h-sub">{{ accessErr ? '未读取' : `${sessions.length} 条` }}</span>
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
                <span v-if="p.splitPlatform" class="bd-tg bd-tg--grey bd-tg--sm">{{ isMobile(record.platform) ? '移动端' : 'PC' }}</span>
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
                <span class="bd-tg" :class="record.state === 'active' ? 'bd-tg--green' : 'bd-tg--red'">
                  {{ record.state === 'active' ? '接入中' : '已注销' }}
                </span>
                <span v-if="record.endedReason" class="bd-dim bd-reason" :title="record.endedReason">{{ record.endedReason }}</span>
              </template>
            </a-table-column>
          </template>
          <template #empty>
            <EmptyState v-if="accessErr" size="md" tone="danger" title="接入会话未读取"
              :desc="`后端原话：${accessErr}　这里显示的不是「没有接入会话」——终端可能正连着隧道。`" />
            <EmptyState v-else size="md" title="暂无接入会话" desc="终端取过敲门令牌后出现在这里" />
          </template>
        </a-table>
        <div class="bd-card__b bd-tblnote">
          活跃时刻按 <b>(账号, 来源 IP)</b> 与网关回执对应——网关的会话表按源 IP 记，它不知道终端指纹。
          同一 NAT 出口下的两台终端会共用一个 IP，此时活跃时刻互相顶替，方向是「不该踢的不踢」。
        </div>
      </div>

      <!-- 如实声明 -->
      <div class="bd-notice bd-notice--warn bd-unimpl">
        <icon-info-circle />
        <div class="bd-notice__body">
          <div class="bd-unimpl__h">本版本未实现</div>
          <div v-for="n in ACCESS_UNIMPL" :key="n.label" class="bd-unimpl__row">
            <b>{{ n.label }}</b><span>{{ n.why }}</span>
          </div>
          <div class="bd-unimpl__f">取舍与理由见 docs/SCOPE.md 与 docs/ARCHITECTURE.md 第七节</div>
        </div>
      </div>
    </div>

    <!-- ============ 全局策略（复刻设计稿开关行）============ -->
    <div v-show="tab === 'global'" class="bd-two">
      <div class="bd-card bd-gsec-nav">
        <button v-for="g in globalSecs" :key="g.key" type="button" class="bd-gnav" :class="{ on: gsec === g.key }" @click="gsec = g.key">
          {{ g.label }}
        </button>
      </div>
      <div class="bd-card bd-two__main">
        <div v-for="g in globalSecs" v-show="gsec === g.key" :key="g.key">
          <div class="bd-card__h">{{ g.label }}</div>
          <div class="bd-card__b">
            <!-- ★这一栏只列未实现项，不放开关：界面上任何一个勾都必须真能生效。
                 「禁止用户通过浏览器登录」尤其不能加——控制面关不掉网关的 -web 监听，
                 那条免客户端接入路照常敞着，而它会被当成一项已生效的安全措施。 -->
            <div v-if="g.notes.length" class="bd-notice bd-notice--warn bd-unimpl">
              <icon-info-circle />
              <div class="bd-notice__body">
                <div class="bd-unimpl__h">本版本未实现</div>
                <div v-for="n in g.notes" :key="n.label" class="bd-unimpl__row">
                  <b>{{ n.label }}</b><span>{{ n.why }}</span>
                </div>
                <div class="bd-unimpl__f">取舍与理由见 docs/ARCHITECTURE.md 第七节</div>
              </div>
            </div>
            <!-- 防暴力破解 · 真实接线（GET/PUT /security/lockout-config，消费方=控制面登录链路） -->
            <template v-if="g.key === 'brute'">
              <!-- ★与上面同一条纪律：读不到时下面三行显示的是**本地默认值**，
                   而它们长得跟"库里正生效的阈值"一模一样——不说的话，管理员会照着
                   一组根本没生效的数字去判断防爆破强度。 -->
              <div v-if="lockErr" class="bd-notice bd-notice--warn">
                <icon-exclamation-circle-fill />
                <div class="bd-notice__body">
                  防爆破配置未读取：下面是<b>本地默认值</b>，不是库里生效的值。
                  <div class="bd-hint">后端原话：{{ lockErr }}</div>
                </div>
              </div>
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
                <span class="bd-thr">阈值 <a-input-number v-model="lockCfg.threshold" :min="1" :max="100" size="mini" class="bd-num bd-num--xs" @change="saveLockoutCfg" /> 次</span>
                <span class="bd-thr">窗口 <a-input-number v-model="windowMin" :min="1" :max="1440" size="mini" class="bd-num bd-num--xs" @change="saveLockoutCfg" /> 分钟</span>
                <span class="bd-thr">锁定 <a-input-number v-model="durationMin" :min="1" :max="1440" size="mini" class="bd-num bd-num--xs" @change="saveLockoutCfg" /> 分钟</span>
              </div>
            </template>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type AccessPolicy, type AccessPolicyResp, type AccessPolicyWebCoverage, type DeviceSessionRow, type LockoutConfig, failReason } from '@/lib/api';
import PageHeader from '@/components/PageHeader.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

const tab = ref<'access' | 'global'>('access');
/** 连接态**三态**：undefined = 首轮请求还在路上（页头不画标签）；true = 读到了；
 *  false = 这一轮确实失败。初值 false 会让第一帧就宣告离线——那时还没读呢。 */
const live = ref<boolean | undefined>(undefined);
/** 接入策略读取失败的后端原话（空 = 这一轮读到了）。★页顶提示、会话计数与会话表
 *  空态三处同源：同一次失败在一页上只许有一种说法。 */
const accessErr = ref('');
/** 防爆破配置读取失败的后端原话（空 = 读到了）。 */
const lockErr = ref('');
/** 首屏是否已完成第一次 loadAccess（成功或降级都算）：只决定骨架屏何时让位，不改任何数据流。 */
const loaded = ref(false);

/* ── 接入策略（FR-POLICY-29/30）── */
const p = reactive<AccessPolicy>({
  deviceLimitEnabled: false, maxDevices: 3, splitPlatform: false, maxDevicesMobile: 2,
  idleEnabled: false, idleMinutes: 480
});
const resp = reactive<{ onlineWindowSec: number; storeReady: boolean; idleReady: boolean }>({
  onlineWindowSec: 90, storeReady: true, idleReady: false
});
const sessions = ref<DeviceSessionRow[]>([]);
/** B/S 覆盖面（后端 api.webAccessCoverage）。★null = 后端没下发这一段（旧控制面）：
 *  此时"哪几台网关在执行"是**判不出来**，页面必须这么说，不能默认成"全都在执行"。 */
const webCov = ref<AccessPolicyWebCoverage>({ deviceLimitTier: 'zero-only', idleEnforcing: [], idleUnreported: [] });
const webCoverageKnown = ref(false);

/** ★未实现项必须逐条列出并说明理由，否则下一次审计会把它当"漏做"再实现一遍。 */
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
    // ★三态：字段缺席 = 旧控制面，覆盖面判不出来（webCoverageKnown=false）；
    //   有值就原样用。默认成空数组会把"判不出来"渲染成"没有网关在执行"。
    webCoverageKnown.value = !!r.web;
    if (r.web) webCov.value = r.web;
    live.value = true; accessErr.value = '';
  } catch (e) {
    // ★接住 e：原话是这一页唯一能指导下一步的信息（403 缺哪个权限 / 存储怎么了）。
    live.value = false; accessErr.value = failReason(e);
    sessions.value = [];
  } finally { loaded.value = true; }
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
  } catch (e) {
    Message.error(`接入策略保存失败：${failReason(e)}`);
    await loadAccess(); // 回读生效值，避免界面停在一个没保存上的状态
  } finally { saving = false; }
}

/* ── 全局策略（复刻设计稿开关行）── */
const gsec = ref('brute');
// ★这份清单只放**尚无执行方**的条目；防暴力破解的两个锁定开关走真实后端，见下方 lockCfg。
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
    lockErr.value = '';
  } catch (e) {
    // 留本地默认值可以，但必须当面说清「这是默认值不是生效值」并带上原话——
    // 否则一组没生效的阈值会被当成防爆破的真实强度。
    lockErr.value = failReason(e);
  }
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
  } catch (e) {
    Message.error(`防爆破配置保存失败：${failReason(e)}`);
    await loadLockoutCfg(); // 回读生效值，避免界面停留在未生效的假状态
  }
}

onMounted(async () => {
  await loadAccess();
  await loadLockoutCfg();
});
</script>

<style scoped>
/* 本页独有的布局。页头 / 提示条 / 卡片头 / 分栏 / 标签都在共享件与 app.css 里，这里不再抄。 */


/* 设置行：左说明 + 右控件 */
.bd-row { display: flex; align-items: center; gap: var(--bd-sp-3); padding: var(--bd-sp-4) 0; border-bottom: 1px solid var(--bd-border-2); }
.bd-row:last-child { border-bottom: none; padding-bottom: 0; }
.bd-row__main { flex: 1; min-width: 0; }
.bd-row__label { font-size: var(--bd-fs-md); font-weight: 500; color: var(--bd-t1); display: flex; align-items: center; gap: 6px; }
.bd-row__desc { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin-top: 3px; line-height: var(--bd-lh); }
.bd-row__unit { font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-thr { font-size: var(--bd-fs-sm); color: var(--bd-t2); white-space: nowrap; }
.bd-num { width: 116px; }
.bd-num--s { width: 96px; }
.bd-num--xs { width: 76px; }

/* 「本版本未实现」清单：底色走 .bd-notice--warn，这里只排行内两栏 */
.bd-unimpl__h { font-weight: 600; color: var(--bd-t1); margin-bottom: var(--bd-sp-1); }
.bd-unimpl__row { display: grid; grid-template-columns: minmax(180px, 220px) 1fr; gap: var(--bd-sp-3); padding: 3px 0; }
.bd-unimpl__row b { color: var(--bd-t1); font-weight: 600; }
.bd-unimpl__row span { color: var(--bd-t2); }
.bd-unimpl__f { margin-top: var(--bd-sp-2); font-size: var(--bd-fs-xs); color: var(--bd-t3); }
.bd-card__b .bd-unimpl { margin-bottom: var(--bd-sp-2); }

/* 全局策略：左窄栏 */
.bd-gsec-nav { width: 200px; flex: none; padding: var(--bd-sp-2); }
.bd-gnav {
  width: 100%; text-align: left; border: none; background: transparent; font: inherit; font-size: var(--bd-fs-md); color: var(--bd-t2);
  padding: 10px var(--bd-sp-3); border-radius: var(--bd-radius-s); cursor: pointer;
  transition: background var(--bd-dur-fast) var(--bd-ease), color var(--bd-dur-fast) var(--bd-ease);
}
.bd-gnav:hover { background: var(--bd-fill-2); }
.bd-gnav.on { background: var(--bd-primary-1); color: var(--bd-primary); font-weight: 600; }

/* 接入策略：卡片纵向排布 */
.bd-acc { display: flex; flex-direction: column; gap: var(--bd-sp-4); }
.bd-acc > .bd-notice { margin-bottom: 0; }
.bd-rule__h { display: flex; align-items: flex-start; gap: var(--bd-sp-4); }
.bd-rule__h > div:first-child { flex: 1; }
.bd-rule__t { font-size: var(--bd-fs-base); font-weight: 600; color: var(--bd-t1); }
.bd-rule__d { font-size: var(--bd-fs-sm); color: var(--bd-t3); line-height: var(--bd-lh-loose); margin-top: 5px; }
.bd-fr { margin-left: var(--bd-sp-2); font-size: var(--bd-fs-xs); font-weight: 500; color: var(--bd-t4); }
.bd-rule__notice { margin: var(--bd-sp-3) 0 0; }
/* 提示行（后端原话 / 覆盖面明细）。此前本页三处用了 .bd-hint 却没有定义，
   于是那几行按正文字号渲染，与结论混成一片。 */
.bd-hint { font-size: var(--bd-fs-sm); color: var(--bd-t3); line-height: var(--bd-lh-loose); margin-top: 4px; }
/* 「未回报」这半句是本条提示里唯一需要被看见的坏消息：一台不执行的网关，
   与"已启用"这句话并排显示时，不上色就会被整段读过去。 */
.bd-warn-t { color: var(--bd-warning-t); }
.bd-rule__h { padding-bottom: var(--bd-sp-3); }
/* 规则卡里的设置行：与头部之间用行线分隔（行线在上、不在下，末行不留悬空线） */
.bd-rule .bd-row { border-top: 1px solid var(--bd-border-2); border-bottom: none; }
.bd-rule .bd-row:last-child { padding-bottom: 0; }
.bd-dim { color: var(--bd-t4); }
.bd-reason { margin-left: var(--bd-sp-2); font-size: var(--bd-fs-xs); }
.bd-tg--sm { margin-left: 6px; padding: 0 5px; }
.bd-tblnote { font-size: var(--bd-fs-xs); color: var(--bd-t3); line-height: var(--bd-lh-loose); border-top: 1px solid var(--bd-border-2); }
.bd-tblnote b { color: var(--bd-t2); }

@media (max-width: 1320px) {
  .bd-gsec-nav { width: 184px; }
  .bd-unimpl__row { grid-template-columns: 1fr; gap: 2px; padding: 5px 0; }
}
</style>
