<template>
  <div class="bd-page">
    <PageHeader title="安全中心" subtitle="终端环境基线 + SPA 服务隐身 · 风险驱动的纵深准入（UEM / 虚拟网络域不在白帝范围内）" :live="live" off-text="降级演示" />

    <!-- ★读取失败时，后端那句原话必须在页面上有地方看。改造前唯一的线索是页头右上
         那枚橙色「降级演示」标签——看得出"出事了"，看不到"是什么事"，而 /security 的
         403（这一页归安全管理员一权）与"连不上控制面"的下一步动作完全相反。
         基线是风险引擎的判据：把两条演示基线当成现场，会以为「阻断基线已启用」。 -->
    <div v-if="live === false" class="bd-notice bd-notice--warn">
      <icon-exclamation-circle-fill />
      <div class="bd-notice__body">
        安全基线未读取（后端原话：<b>{{ loadErr }}</b>），左栏与右侧详情里的基线是<b>内置演示数据</b>，
        <b>不代表风险引擎当前实际生效的基线</b>；此时「保存 / 新建 / 删除」仍会发往后端，成败以后端回执为准。
      </div>
    </div>

    <!-- ★终端合规清单读取失败的提示提到**页签之上**。改造前它挂在非激活的「终端合规」
         页签里：默认首屏是「安全基线」，于是控制面整个不可达时，第一眼只有一枚橙色
         「降级演示」和一屏演示基线，写着后端原话的那条 danger notice 一个字都看不到。
         两个页签是同一次故障的两个侧面，提示不该只挂在其中一个下面。 -->
    <div v-if="postureErr" class="bd-notice bd-notice--danger">
      <icon-exclamation-circle-fill />
      <div class="bd-notice__body">{{ postureErr }}</div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs" role="tablist">
      <button type="button" class="bd-tab" role="tab" :aria-selected="tab === 'baseline'" @click="tab = 'baseline'">安全基线</button>
      <button type="button" class="bd-tab" role="tab" :aria-selected="tab === 'posture'" @click="tab = 'posture'; loadPosture()">
        终端合规
        <!-- 红点角标：站在「安全基线」页签上也能看出另一边出了事（与上面那条 notice 同一判据） -->
        <span v-if="postureErr" class="bd-badge" title="终端合规清单读取失败">!</span>
      </button>
    </div>

    <!-- ============ 安全基线（两栏）============ -->
    <div v-show="tab === 'baseline'" class="bd-two">
      <!-- 左：基线列表 -->
      <div class="bd-card bd-blist">
        <div class="bd-blist__h">
          <span>安全基线策略</span>
          <button type="button" class="bd-link bd-blist__add" @click="addBaseline"><icon-plus-circle />新建</button>
        </div>
        <!-- 首屏骨架：第一次 /security 回来之前不画内置 mock——那一瞬显示的是假基线 -->
        <SkeletonBlock v-if="!loaded" kind="text" :rows="5" />
        <button
          v-for="b in (loaded ? baselines : [])"
          :key="b.id"
          class="bd-bnode"
          :class="{ on: b.id === selected }"
          @click="selected = b.id"
        >
          <div class="bd-bnode__top">
            <span class="bd-bnode__name">{{ b.name }}</span>
            <span class="bd-st" :class="b.status === 'enabled' ? 'bd-st--ok' : 'bd-st--off'"><span class="d" /></span>
          </div>
          <div class="bd-bnode__tags">
            <span class="bd-tg" :class="disposalTag(b.disposal)">{{ disposalText(b.disposal) }}</span>
            <span class="bd-tg" :class="scopeAll(b) ? 'bd-tg--blue' : 'bd-tg--green'">{{ scopeBrief(b) }}</span>
          </div>
          <div class="bd-bnode__scope">{{ scopeDetail(b) }}</div>
        </button>
      </div>

      <!-- 右：基线详情 / 编辑 -->
      <div class="bd-bedit bd-two__main" v-if="cur && loaded">
        <!-- 概要卡 -->
        <div class="bd-card bd-card--pad bd-bhead">
          <div class="bd-bhead__top">
            <div class="bd-bhead__name">
              <a-input v-model="cur.name" size="small" class="bd-bhead__name-in" />
            </div>
            <div class="bd-bhead__sw">
              <span class="bd-bhead__swt">{{ cur.status === 'enabled' ? '已启用' : '已停用' }}</span>
              <a-switch
                :model-value="cur.status === 'enabled'"
                size="small"
                @change="(v: string | number | boolean) => cur && (cur.status = v ? 'enabled' : 'disabled')"
              />
              <a-button type="primary" size="small" :loading="saving" @click="saveBaseline">保存</a-button>
              <!-- ★删基线必须二次确认：基线是风险引擎的判据，删掉一条 block 基线，
                   一批本该被拦的终端下一轮就直接放行，页面上不会有任何提示。 -->
              <a-popconfirm
                :content="`删除基线「${cur?.name ?? ''}」？风险引擎下一次评估起即不再应用这条规则——原本被它判为「${cur ? disposalText(cur.disposal) : '—'}」的终端会按剩余基线重新判定。此操作不可撤销。`"
                type="warning" ok-text="确认删除" cancel-text="取消" @ok="removeBaseline"
              >
                <a-button size="small" status="danger">删除</a-button>
              </a-popconfirm>
            </div>
          </div>
          <!-- ★适用范围是**真判据**：账号不在范围内，这条基线就不参与他的判定。判定点是控制面
               api.baselinesInScope，与资源授权、认证策略共用同一次子树展开。两栏都不选 = 对全体生效。 -->
          <div class="bd-kv bd-kv--scope">
            <span>适用范围</span>
            <b>
              <div class="bd-scope">
                <a-select v-model="cur.scopeOrgs" multiple allow-clear size="small"
                          placeholder="不限组织" class="bd-scope__sel">
                  <a-option v-for="o in orgOpts" :key="o.id" :value="o.id">
                    {{ o.name }}（{{ o.accounts.length }} 人）
                  </a-option>
                </a-select>
                <a-select v-model="cur.scopeGroups" multiple allow-clear size="small"
                          placeholder="不限用户组" class="bd-scope__sel">
                  <a-option v-for="g in groupOpts" :key="g.id" :value="g.id">
                    {{ g.name }}（{{ g.accounts.length }} 人）
                  </a-option>
                </a-select>
              </div>
              <div class="bd-scope__hint">{{ scopeDetail(cur) }}</div>
            </b>
          </div>
          <div class="bd-kv"><span>覆盖平台</span>
            <b><span v-for="p in cur.platforms" :key="p" class="bd-tg bd-tg--grey bd-plat">{{ p }}</span></b>
          </div>
        </div>

        <!-- 处置动作（P7 风险分级配色）-->
        <div class="bd-card">
          <div class="bd-card__h">命中处置动作<span class="bd-card__h-sub">终端未通过本基线检测项时的纵深准入处置（风险越高、处置越强）</span></div>
          <div class="bd-card__b bd-disp__grid">
            <button
              v-for="d in DISPOSALS"
              :key="d.key"
              type="button"
              class="bd-dchip"
              :class="[`bd-dchip--${d.tone}`, { on: cur.disposal === d.key }]"
              @click="cur.disposal = d.key"
            >
              <span class="bd-dchip__dot" />
              <span class="bd-dchip__t">{{ d.label }}</span>
              <span class="bd-dchip__d">{{ d.desc }}</span>
            </button>
          </div>
        </div>

        <!-- 平台条件编辑器（P6：分平台 AND 条件）-->
        <div class="bd-card">
          <div class="bd-card__h">
            平台检测项 · 分平台 AND 条件
            <span class="bd-card__h-sub">同一平台下所有检测项需全部满足（AND）方判为合规，否则按上方处置动作执行</span>
          </div>
          <div class="bd-card__b">
            <!-- 平台 pill 切换 -->
            <div class="bd-platbar">
              <button
                v-for="p in PLATFORMS"
                :key="p"
                type="button"
                class="bd-platpill"
                :class="{ on: plat === p }"
                @click="plat = p"
              >
                {{ p }}
                <span class="bd-platpill__n">{{ checksFor(p).length }}</span>
              </button>
            </div>

            <!-- 检测项表 -->
            <div class="bd-chktable">
            <table class="bd-table">
              <thead>
                <tr>
                  <th>检测项</th>
                  <th>期望值</th>
                  <th>风险等级</th>
                  <th>适用</th>
                  <th class="r">操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="c in checksFor(plat)" :key="c.key">
                  <td><b class="bd-cell-strong">{{ c.label }}</b></td>
                  <td><span class="bd-mono">{{ c.expect }}</span></td>
                  <td>
                    <span class="bd-tg" :class="severityTag(c.severity)">{{ severityText(c.severity) }}</span>
                  </td>
                  <td>
                    <span class="bd-tg" :class="c.platform === 'All' ? 'bd-tg--purple' : 'bd-tg--grey'">{{ c.platform === 'All' ? '全平台' : c.platform }}</span>
                  </td>
                  <td class="r">
                    <span class="bd-acts"><button type="button" class="bd-link bd-link--danger" @click="removeCheck(c.key)">删除</button></span>
                  </td>
                </tr>
                <tr v-if="checksFor(plat).length === 0" class="bd-table__emptyrow">
                  <td colspan="5"><EmptyState size="sm" title="该平台暂无检测项，可点击下方按钮添加" /></td>
                </tr>
              </tbody>
            </table>
            </div>

            <!-- ★只能从采集器目录里选，不能自由填 key：采集器不报的 key 会让这条基线
                 对全平台终端永远判违规（接入准入基线默认处置是 block）。目录由后端下发。 -->
            <div class="bd-addcheck-row">
              <a-select
                v-model="pickedCheck"
                size="small"
                placeholder="选择要添加的检测项…"
                :disabled="!addableChecks.length"
                class="bd-addcheck-sel"
                allow-clear
              >
                <a-option v-for="s in addableChecks" :key="s.key" :value="s.key">
                  {{ s.label }}（{{ s.key }}）
                </a-option>
              </a-select>
              <a-button size="small" type="primary" :disabled="!pickedCheck" @click="addCheck">
                <icon-plus />添加检测项
              </a-button>
              <span v-if="!catalog.length" class="bd-addcheck-note">未连后端，取不到采集项目录</span>
              <span v-else-if="!addableChecks.length" class="bd-addcheck-note">采集器可上报的 {{ catalog.length }} 项已全部配置</span>
              <span v-else class="bd-addcheck-note">
                只列采集器真的会上报的项——配一个采集器不报的 key，这条基线会对全平台终端永远判违规
              </span>
            </div>
            <div v-if="pickedSpec?.note" class="bd-notice bd-notice--plain bd-addcheck-hint"><icon-info-circle /><span>{{ pickedSpec.note }}</span></div>
          </div>
        </div>
      </div>
    </div>

    <!-- ============ 终端合规（最新 posture 上报 × 风险引擎判定）============ -->
    <div v-show="tab === 'posture'" class="bd-tablecard">
      <div class="bd-card__h">
        终端合规状态（最新上报）
        <div class="bd-card__h-right">
          <button type="button" class="bd-btn bd-btn--ghost bd-btn--sm" @click="loadPosture"><icon-refresh /> 刷新</button>
        </div>
      </div>
      <div v-if="postureTruncated && !postureErr" class="bd-card__b bd-posture__b">
        <!-- ★截断必须可见：清单只读前 N 条。不说的话，一份被截断的合规清单会被当成全量，
             管理员据此判断「没有不合规终端」——而看不见的那截里可能全是 block。 -->
        <div class="bd-notice bd-notice--warn">
          <icon-exclamation-circle-fill />
          <span>共 {{ postureTotal }} 台终端上报，本页只显示最近 {{ postureRows.length }} 条，
          其余 {{ postureTotal - postureRows.length }} 条未加载——请用 API 查询完整清单。
          （准入判定不受此上限影响：闸门读的是独立的全量查询。）</span>
        </div>
      </div>
      <SkeletonBlock v-if="!postureLoaded" kind="table" :rows="4" :cols="9" />
      <!-- 读取失败：表格整块不画，此处给一条 danger 空态说明"为什么是空的"——
           后端原话在上方那条页级 notice 里，两处不重复同一句话。 -->
      <div v-else-if="postureErr" class="bd-card__b">
        <EmptyState size="md" tone="danger" title="终端合规清单未读取"
          desc="失败原因见页面顶部的红色提示条（后端原话）；修好后点右上「刷新」重试。这里不画任何演示终端——编造的合规状态与真实上报在这一屏上无法区分。" />
      </div>
      <div v-else class="bd-tablewrap">
      <table class="bd-table">
        <thead>
          <tr><th>账号</th><th>设备指纹</th><th>平台 / 系统</th><th>客户端</th><th>检查</th><th>判定</th><th>评分</th><th>最后上报</th><th class="r">操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="p in postureRows" :key="p.user + p.device">
            <td><b class="bd-cell-strong">{{ p.user }}</b></td>
            <td><span class="bd-mono">{{ p.device }}</span></td>
            <td>{{ p.platform }} · {{ p.os || '—' }}</td>
            <td>{{ p.clientVersion || '—' }}</td>
            <td>
              <!--
                三态：绿=通过 / 红=不合规 / 灰=终端探不到（unknown）。unknown 时终端把 ok 置 false，
                只按 ok 上色会把"这台机器读不到 BitLocker"画成"这台机器没加密"，
                管理员据此去追一台其实合规的终端。title 给出终端上报的原始值/原因。
              -->
              <span
                v-for="c in p.checks" :key="c.key" class="bd-tg bd-chk" :title="c.value"
                :class="c.unknown ? 'bd-tg--grey' : c.ok ? 'bd-tg--green' : 'bd-tg--red'"
              >{{ c.label }}{{ c.unknown ? '（无法判定）' : '' }}</span>
            </td>
            <td><span class="bd-tg" :class="verdictTag(p.verdict)">{{ verdictText(p.verdict) }}</span></td>
            <td><b :class="`bd-score bd-score--${scoreTone(p.score)}`">{{ p.score }}</b></td>
            <td class="bd-dim">{{ tsText(p.ts) }}</td>
            <td class="r">
              <a-popconfirm
                :content="p.verdict === 'block' ? '该设备为阻断状态，退役后将解除其触发的接入收缩。确认删除？' : '删除该设备的终端报告（设备退役）？'"
                type="warning" @ok="removePosture(p)"
              >
                <button type="button" class="bd-link bd-link--danger">退役</button>
              </a-popconfirm>
            </td>
          </tr>
          <tr v-if="postureRows.length === 0" class="bd-table__emptyrow">
            <td colspan="9"><EmptyState size="md" title="尚无终端上报" desc="桌面客户端登录后每 60s 自动上报" /></td>
          </tr>
        </tbody>
      </table>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type SecurityBundle, type BaselinePolicy, type BaselineCheck, type CheckSpec, type PostureRow, type PostureResp, type SubjectOption, failReason } from '@/lib/api';
import PageHeader from '@/components/PageHeader.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

type Platform = 'Windows' | 'macOS' | 'Linux';
const PLATFORMS: Platform[] = ['Windows', 'macOS', 'Linux'];

const tab = ref<'baseline' | 'posture'>('baseline');
/** 连接态三态：undefined = 首轮请求还在路上（判不出来，PageHeader 此时不画标签）/
 *  true 已连 / false 降级演示。★初值写 false 的话，首屏那一瞬页头就挂上一枚橙色
 *  「降级演示」——把"还没探过"说成"确定离线"，而那一刻什么都还没发生。 */
const live = ref<boolean | undefined>(undefined);
/** /security 读取失败时后端那句原话（failReason 收口，前端不编造归因）。 */
const loadErr = ref('');
/** 首屏是否已完成一次 /security 加载（成功或降级都算）——只决定骨架屏何时让位，不改任何数据流。 */
const loaded = ref(false);

/* ── 内置 mock（结构同后端 SecurityBundle）── */
const MOCK_BASELINES: BaselinePolicy[] = [
  {
    id: 'bl-admission', name: '接入准入基线', scopeOrgs: [], scopeGroups: [],
    disposal: 'block', status: 'enabled', platforms: ['Windows', 'macOS', 'Linux'],
    checks: [
      { key: 'disk_encrypted', label: '磁盘已加密', platform: 'All', expect: 'FileVault / BitLocker = On', severity: 'high' },
      { key: 'sys_integrity', label: '系统完整性保护开启', platform: 'macOS', expect: 'SIP = enabled', severity: 'high' }
    ]
  },
  {
    id: 'bl-health', name: '终端健康基线', scopeOrgs: [], scopeGroups: [],
    disposal: 'degrade', status: 'enabled', platforms: ['Windows', 'macOS', 'Linux'],
    checks: [
      { key: 'firewall_on', label: '系统防火墙启用', platform: 'All', expect: 'firewall = enabled', severity: 'medium' },
      { key: 'os_version', label: '系统版本合规', platform: 'All', expect: 'macOS ≥ 13 / Win ≥ 10', severity: 'medium' },
      { key: 'edr_online', label: 'EDR 终端防护在线', platform: 'All', expect: 'EDR 进程存活', severity: 'low' },
      { key: 'client_version', label: '客户端版本合规', platform: 'All', expect: '≥ 灰度发布里配置的稳定版', severity: 'low' }
    ]
  }
];
// ★这一页刻意不展示 SPA 隐身状态：控制面既不实测端口可见性、也不代数据面宣布敲门是否正常，
// 在这里放那张卡等于替一台可能压根没配防火墙规则的网关打包票。
// 真实版本在「安全防护 → 网关与隐身」，每一项都来自网关注册心跳。

const baselines = ref<BaselinePolicy[]>(MOCK_BASELINES);
/** 采集器可上报的检查项目录（后端下发，未连库时为空——此时只能删不能加，见 addCheck）。 */
const catalog = ref<CheckSpec[]>([]);
const selected = ref(MOCK_BASELINES[0].id);
const plat = ref<Platform>('Windows');

const cur = computed(() => baselines.value.find((b) => b.id === selected.value));

/** 某平台下生效的检测项 = 该平台专属 + 全平台(All) */
function checksFor(p: Platform): BaselineCheck[] {
  return cur.value?.checks.filter((c) => c.platform === p || c.platform === 'All') ?? [];
}

/* ── 处置动作（P7 风险分级配色）── */
/* tone 只走 --bd-* 语义族（allow 绿 / degrade 橙 / block 红 / gray 中性灰），不写十六进制。 */
const DISPOSALS: { key: BaselinePolicy['disposal']; label: string; desc: string; tone: 'success' | 'warning' | 'danger' | 'grey' }[] = [
  { key: 'allow', label: '放行', desc: '记录但不拦截', tone: 'success' },
  { key: 'degrade', label: '降权', desc: '仅放行低敏应用', tone: 'warning' },
  { key: 'block', label: '阻断', desc: '高危 · 直接拒绝接入', tone: 'danger' },
  { key: 'gray', label: '灰度', desc: '小范围观察', tone: 'grey' }
];

/* ── 颜色 / 文案 ── */
function disposalText(d: BaselinePolicy['disposal']) {
  return d === 'allow' ? '放行' : d === 'degrade' ? '降权' : d === 'block' ? '阻断' : '灰度';
}
function disposalTag(d: BaselinePolicy['disposal']) {
  return d === 'allow' ? 'bd-tg--green' : d === 'degrade' ? 'bd-tg--gold' : d === 'block' ? 'bd-tg--red' : 'bd-tg--grey';
}
function severityText(s: BaselineCheck['severity']) { return s === 'high' ? '高' : s === 'medium' ? '中' : '低'; }
function severityTag(s: BaselineCheck['severity']) {
  return s === 'high' ? 'bd-tg--red' : s === 'medium' ? 'bd-tg--gold' : 'bd-tg--grey';
}

/* ── 适用范围（真判据）──
 * 候选与账号展开由后端随 /security 下发，与资源授权、认证策略共用同一次组织子树展开；
 * 前端不自己算"这个组织有几个人"——各算一份必然与判定分叉。 */
const orgOpts = ref<SubjectOption[]>([]);
const groupOpts = ref<SubjectOption[]>([]);
function scopeAll(b: BaselinePolicy) { return !(b.scopeOrgs ?? []).length && !(b.scopeGroups ?? []).length; }
function scopeBrief(b: BaselinePolicy) { return scopeAll(b) ? '全体终端' : '限定范围'; }
/** 展开后覆盖的账号数（与判定用的是同一份展开）。 */
function scopeAccounts(b: BaselinePolicy) {
  const set = new Set<string>();
  for (const id of b.scopeOrgs ?? []) orgOpts.value.find((o) => o.id === id)?.accounts.forEach((a) => set.add(a));
  for (const id of b.scopeGroups ?? []) groupOpts.value.find((g) => g.id === id)?.accounts.forEach((a) => set.add(a));
  return set.size;
}
function scopeDetail(b: BaselinePolicy) {
  if (scopeAll(b)) return '未限定范围 · 对全体上报终端生效';
  const names = [
    ...(b.scopeOrgs ?? []).map((id) => orgOpts.value.find((o) => o.id === id)?.name || id),
    ...(b.scopeGroups ?? []).map((id) => groupOpts.value.find((g) => g.id === id)?.name || id)
  ];
  // ★展开为 0 人时当面说出来：限定了范围却一个人都不在里面 = 这条基线对谁都不生效，
  // 而它在列表上仍显示「已启用 · 阻断」。
  const n = scopeAccounts(b);
  return names.join('、') + (n ? `　·　展开 ${n} 个账号` : '　·　展开后 0 个账号，这条基线当前对谁都不生效');
}

/* ── 编辑动作（真实落库：整条基线 POST /security/baselines）── */
const saving = ref(false);
async function saveBaseline() {
  if (!cur.value) return;
  saving.value = true;
  try {
    await api('/security/baselines', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cur.value) });
    Message.success('基线已保存，风险引擎即时生效');
  } catch (e) {
    // ★必须原样转述后端：基线保存有八类具体校验（引用了不存在的组织/用户组、
    // 检查项 key 不认识…），每一条都点名了该改哪里，自拟归因会把它们全盖掉。
    Message.error(`基线保存失败：${failReason(e)}`);
  } finally { saving.value = false; }
}
async function addBaseline() {
  const nb: BaselinePolicy = {
    id: '', name: '新建基线', scopeOrgs: [], scopeGroups: [], disposal: 'degrade', status: 'enabled',
    platforms: ['Windows', 'macOS', 'Linux'], checks: []
  };
  try {
    const r = await api<{ ok: boolean; baseline: BaselinePolicy }>('/security/baselines', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(nb) });
    baselines.value.push(r.baseline);
    selected.value = r.baseline.id;
    Message.success('已创建，可继续编辑后保存');
  } catch (e) { Message.error(`基线创建失败：${failReason(e)}`); }
}
async function removeBaseline() {
  if (!cur.value) return;
  const id = cur.value.id;
  try {
    await api(`/security/baselines/${id}`, { method: 'DELETE' });
    baselines.value = baselines.value.filter((b) => b.id !== id);
    if (baselines.value.length) selected.value = baselines.value[0].id;
    Message.success('基线已删除');
  } catch (e) { Message.error(`基线删除失败：${failReason(e)}`); }
}
/**
 * 可添加的检测项 = 采集器目录 − 本基线已配的 key。目录由后端随 /security 下发，与入口校验同源。
 * ★绝不能让管理员自由填 key：采集器不上报的 key 被风险引擎按「缺失即不合规」判失败，
 * 这条基线于是对该平台全体终端永远违规，而准入基线默认处置是 block（全员拒发敲门令牌 +
 * 撤窗断隧道），保存那一刻零报错。
 */
const addableChecks = computed(() =>
  catalog.value.filter((s) => !(cur.value?.checks ?? []).some((c) => c.key === s.key)));
const pickedCheck = ref('');
/** 选中项的采集说明（哪些情况会探不到 / 判据在哪一侧）——直接摆在选择器下面，
 *  免得管理员配完一条 low 严重度的项，事后才发现它在半数终端上恒为「无法判定」。 */
const pickedSpec = computed(() => catalog.value.find((s) => s.key === pickedCheck.value));

function addCheck() {
  const spec = catalog.value.find((s) => s.key === pickedCheck.value);
  if (!cur.value || !spec) return;
  cur.value.checks.push({
    key: spec.key,
    label: spec.label,
    // 采集器六项三平台都采（spec.platform 恒为 All），故按目录声明的适用面写，
    // 不按当前选中的平台页签写——后者会造出「只在 Windows 生效」的假限定。
    platform: spec.platform,
    expect: spec.expect,
    severity: 'medium'
  });
  pickedCheck.value = '';
}
function removeCheck(key: string) {
  if (!cur.value) return;
  cur.value.checks = cur.value.checks.filter((c) => c.key !== key);
}

/* ── 终端合规（GET /posture，admin）── */
const postureRows = ref<PostureRow[]>([]);
/** 库里的报告总数与「本页是否被截断」（后端 /posture 下发）。
 *  ★不显示的话，一份被截断的合规清单会被当成全量——管理员据此判断「没有不合规终端」。 */
const postureTotal = ref(0);
const postureTruncated = ref(false);
const postureErr = ref('');
/** 终端合规清单是否已完成一次拉取（成功或失败都算）——只决定骨架屏何时让位。 */
const postureLoaded = ref(false);
async function loadPosture() {
  try {
    const pr = await api<PostureResp>('/posture');
    postureRows.value = pr.reports;
    postureTotal.value = pr.total ?? pr.reports.length;
    postureTruncated.value = !!pr.truncated;
    postureErr.value = '';
    // 同页其余读取早就按纪律转述后端原话，唯独这一处漏了：改造前是
    // `catch { postureErr.value = '暂无法读取（需管理员登录 / 后端在线）' }`——
    // 而 /posture 的 403 说的是「角色「系统管理员」无权执行该操作（需要权限：security）」。
    // 把"缺哪个权限"换成"需管理员登录"，管理员会去重登（他本来就登着），
    // 而这一格恰好是终端合规判定的唯一入口。
  } catch (e) { postureErr.value = '终端环境判定读取失败：' + failReason(e); }
  finally { postureLoaded.value = true; }
}
function verdictText(v: string) { return v === 'allow' ? '合规' : v === 'degrade' ? '降权' : v === 'gray' ? '灰度' : '阻断'; }
function verdictTag(v: string) { return v === 'allow' ? 'bd-tg--green' : v === 'degrade' ? 'bd-tg--gold' : v === 'gray' ? 'bd-tg--grey' : 'bd-tg--red'; }
/** 评分上色阈值与改造前一致（≥60 红 / ≥30 橙 / 其余正文色）。 */
function scoreTone(score: number) { return score >= 60 ? 'danger' : score >= 30 ? 'warning' : 'default'; }
function tsText(ts: number) { return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }); }
async function removePosture(p: PostureRow) {
  try {
    await api(`/posture/${encodeURIComponent(p.user)}/${encodeURIComponent(p.device)}`, { method: 'DELETE' });
    postureRows.value = postureRows.value.filter((r) => !(r.user === p.user && r.device === p.device));
    Message.success('终端报告已删除（设备退役）');
  } catch (e) { Message.error(`终端报告删除失败：${failReason(e)}`); }
}

onMounted(async () => {
  try {
    const b = await api<SecurityBundle>('/security');
    // 归一化：旧后端不带这两个字段时给空数组，否则 v-model 绑到 undefined 上，
    // 选一次组织就把整条基线的其它字段一起提交回一个 undefined。
    baselines.value = b.baselines.map((x) => ({ ...x, scopeOrgs: x.scopeOrgs ?? [], scopeGroups: x.scopeGroups ?? [] }));
    orgOpts.value = b.orgs ?? [];
    groupOpts.value = b.groups ?? [];
    // ★目录取不到就给空数组：宁可「加不了检测项」，也不能回退成自由填 key
    // （那会把全平台终端判违规，见 addableChecks）。
    catalog.value = b.checkCatalog ?? [];
    if (b.baselines.length) selected.value = b.baselines[0].id;
    live.value = true;
    loadErr.value = '';
  } catch (e) {
    live.value = false;
    loadErr.value = failReason(e);
  } finally {
    loaded.value = true;
  }
  loadPosture();
});
</script>

<style scoped>
/* 本页独有：基线左栏、处置动作芯片、平台 pill。页签在 app.css（.bd-tabs / .bd-tab）；卡片头 / 表格 / 标签 / 状态点 / 空态 / 提示条都在共享件与 app.css 里。 */

.bd-kv { display: flex; align-items: center; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid var(--bd-border-2); font-size: var(--bd-fs-md); }
.bd-kv:last-child { border-bottom: none; padding-bottom: 0; }
.bd-kv span { color: var(--bd-t3); }
.bd-kv b { font-weight: 500; color: var(--bd-t1); }
.bd-kv--scope { align-items: flex-start; }
.bd-kv--scope > span { padding-top: 5px; }
.bd-scope { display: flex; gap: var(--bd-sp-2); flex-wrap: wrap; justify-content: flex-end; }
.bd-scope__sel { min-width: 210px; }
.bd-scope__hint { margin-top: 6px; font-size: var(--bd-fs-xs); color: var(--bd-t3); text-align: right; font-weight: 400; }

/* 左：基线列表 */
.bd-blist { width: 300px; flex: none; padding: 10px; }
.bd-blist__h { display: flex; align-items: center; justify-content: space-between; font-size: var(--bd-fs-sm); font-weight: 600; color: var(--bd-t3); padding: var(--bd-sp-1) var(--bd-sp-2) 10px; }
.bd-blist__add { display: inline-flex; align-items: center; gap: var(--bd-sp-1); font-size: var(--bd-fs-sm); }
.bd-bnode {
  width: 100%; display: block; text-align: left; border: 1px solid transparent; background: transparent;
  border-radius: var(--bd-radius-s); cursor: pointer; padding: 10px var(--bd-sp-3); margin-bottom: 2px;
  transition: background var(--bd-dur-fast) var(--bd-ease), border-color var(--bd-dur-fast) var(--bd-ease);
}
.bd-bnode:hover { background: var(--bd-fill-2); }
.bd-bnode.on { background: var(--bd-primary-1); border-color: var(--bd-primary-b); }
.bd-bnode__top { display: flex; align-items: center; justify-content: space-between; }
.bd-bnode__name { font-size: var(--bd-fs-md); font-weight: 500; color: var(--bd-t1); }
.bd-bnode.on .bd-bnode__name { color: var(--bd-primary); }
.bd-bnode__tags { display: flex; gap: 6px; margin-top: var(--bd-sp-2); }
.bd-bnode__scope { font-size: var(--bd-fs-xs); color: var(--bd-t3); margin-top: 7px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* 右：编辑区 */
.bd-bedit { display: flex; flex-direction: column; gap: var(--bd-sp-4); }

/* 概要卡 */
.bd-bhead__top { display: flex; align-items: center; justify-content: space-between; gap: var(--bd-sp-3); margin-bottom: 6px; flex-wrap: wrap; }
.bd-bhead__name { display: flex; align-items: center; gap: 10px; }
.bd-bhead__name-in { width: 220px; }
.bd-bhead__name-in :deep(.arco-input) { font-weight: 700; }
.bd-bhead__sw { display: flex; align-items: center; gap: var(--bd-sp-2); }
.bd-bhead__swt { font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-plat { margin-right: 6px; }

/* 处置动作：芯片的语义色只走 --bd-* 语义族，选中态由 .on 抬亮 */
.bd-disp__grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: var(--bd-sp-3); }
.bd-dchip {
  display: flex; flex-direction: column; align-items: flex-start; gap: var(--bd-sp-1); text-align: left;
  border: 1.5px solid var(--bd-border); background: var(--bd-bg-1); border-radius: var(--bd-radius-s); padding: var(--bd-sp-3) 14px; cursor: pointer;
  font: inherit; --chip: var(--bd-t3); --chip-1: var(--bd-fill-2);
  transition: border-color var(--bd-dur-fast) var(--bd-ease), background var(--bd-dur-fast) var(--bd-ease);
}
.bd-dchip--success { --chip: var(--bd-success); --chip-1: var(--bd-success-1); }
.bd-dchip--warning { --chip: var(--bd-warning); --chip-1: var(--bd-warning-1); }
.bd-dchip--danger { --chip: var(--bd-danger); --chip-1: var(--bd-danger-1); }
.bd-dchip:hover { border-color: var(--bd-t4); }
.bd-dchip.on { border-color: var(--chip); background: var(--chip-1); }
.bd-dchip__dot { width: 8px; height: 8px; border-radius: 50%; background: var(--chip); }
.bd-dchip__t { font-size: var(--bd-fs-base); font-weight: 600; color: var(--bd-t1); }
.bd-dchip.on .bd-dchip__t { color: var(--chip); }
.bd-dchip__d { font-size: var(--bd-fs-xs); color: var(--bd-t3); }

/* 平台检测项编辑器 */
.bd-platbar { display: flex; gap: var(--bd-sp-2); margin-bottom: 14px; }
.bd-platpill {
  display: inline-flex; align-items: center; gap: 7px; border: 1px solid var(--bd-border); background: var(--bd-bg-1);
  border-radius: var(--bd-radius-pill); padding: 6px 14px; font: inherit; font-size: var(--bd-fs-md); color: var(--bd-t2); cursor: pointer;
  transition: background var(--bd-dur-fast) var(--bd-ease), color var(--bd-dur-fast) var(--bd-ease), border-color var(--bd-dur-fast) var(--bd-ease);
}
.bd-platpill:hover { border-color: var(--bd-primary-b); }
.bd-platpill.on { background: var(--bd-primary-1); border-color: var(--bd-primary-b); color: var(--bd-primary); font-weight: 600; }
.bd-platpill__n { font-size: var(--bd-fs-xs); min-width: 18px; height: 18px; padding: 0 5px; border-radius: 9px; background: var(--bd-fill-2); color: var(--bd-t3); display: inline-flex; align-items: center; justify-content: center; }
.bd-platpill.on .bd-platpill__n { background: var(--bd-bg-1); color: var(--bd-primary); }

/* 内嵌表格：带边框的表格卡，clip 而非 hidden（见 app.css 对粘性表头的说明） */
.bd-chktable { border: 1px solid var(--bd-border-2); border-radius: var(--bd-radius-s); overflow: clip; }
.bd-cell-strong { color: var(--bd-t1); font-weight: 500; }

.bd-addcheck-row {
  margin-top: 14px; padding: 10px var(--bd-sp-3); border: 1px dashed var(--bd-border); background: var(--bd-fill-1);
  border-radius: var(--bd-radius-s); display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
}
.bd-addcheck-sel { flex: 1; max-width: 340px; }
.bd-addcheck-note { font-size: var(--bd-fs-sm); color: var(--bd-t3); flex: 1; min-width: 200px; }
.bd-addcheck-hint { margin: var(--bd-sp-2) 0 0; }

/* 终端合规 */
.bd-posture__b { padding-bottom: 0; }
.bd-posture__b > .bd-notice { margin-bottom: var(--bd-sp-4); }
.bd-tablewrap { overflow-x: auto; }
.bd-chk { margin: 1px 3px 1px 0; }
.bd-dim { color: var(--bd-t3); }
.bd-score--danger { color: var(--bd-danger); }
.bd-score--warning { color: var(--bd-warning); }
.bd-score--default { color: var(--bd-t1); }

@media (max-width: 1320px) {
  .bd-blist { width: 250px; }
  .bd-disp__grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
</style>
