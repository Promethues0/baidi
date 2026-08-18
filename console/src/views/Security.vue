<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">安全中心</div>
        <div class="bd-page__sub">终端环境基线 + SPA 服务隐身 · 风险驱动的纵深准入（UEM / 虚拟网络域不在白帝范围内）</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'baseline' }" @click="tab = 'baseline'">安全基线</span>
      <span class="bd-tab" :class="{ on: tab === 'posture' }" @click="tab = 'posture'; loadPosture()">终端合规</span>
    </div>

    <!-- ============ 安全基线（两栏）============ -->
    <div v-show="tab === 'baseline'" class="bd-two">
      <!-- 左：基线列表 -->
      <div class="bd-card bd-blist">
        <div class="bd-blist__h">
          <span>安全基线策略</span>
          <span class="bd-blist__add" @click="addBaseline"><icon-plus-circle />新建</span>
        </div>
        <button
          v-for="b in baselines"
          :key="b.id"
          class="bd-bnode"
          :class="{ on: b.id === selected }"
          @click="selected = b.id"
        >
          <div class="bd-bnode__top">
            <span class="bd-bnode__name">{{ b.name }}</span>
            <span class="bd-st"><span class="d" :style="{ background: b.status === 'enabled' ? 'var(--bd-success)' : 'var(--bd-t4)' }" /></span>
          </div>
          <div class="bd-bnode__tags">
            <span class="bd-tg" :style="tagStyle(disposalColor(b.disposal))">{{ disposalText(b.disposal) }}</span>
            <span class="bd-tg" :style="tagStyle(scopeAll(b) ? '#165DFF' : '#00B42A')">{{ scopeBrief(b) }}</span>
          </div>
          <div class="bd-bnode__scope">{{ scopeDetail(b) }}</div>
        </button>
      </div>

      <!-- 右：基线详情 / 编辑 -->
      <div class="bd-bedit" v-if="cur">
        <!-- 概要卡 -->
        <div class="bd-card bd-bhead">
          <div class="bd-bhead__top">
            <div style="display: flex; align-items: center; gap: 10px">
              <a-input v-model="cur.name" size="small" style="width: 220px; font-weight: 700" />
            </div>
            <div class="bd-bhead__sw">
              <span class="bd-bhead__swt">{{ cur.status === 'enabled' ? '已启用' : '已停用' }}</span>
              <a-switch
                :model-value="cur.status === 'enabled'"
                size="small"
                @change="(v: string | number | boolean) => cur && (cur.status = v ? 'enabled' : 'disabled')"
              />
              <a-button type="primary" size="small" :loading="saving" @click="saveBaseline">保存</a-button>
              <a-button size="small" status="danger" @click="removeBaseline">删除</a-button>
            </div>
          </div>
          <!-- ★适用范围是**真判据**：上报 posture 的账号不在范围内，这条基线就不参与他的判定。
               判定点在控制面 api.baselinesInScope，与资源授权、认证策略共用同一次组织子树展开。
               两栏都不选 = 对全体生效（与改造前自由文本时代的实际行为一致）。 -->
          <div class="bd-kv bd-kv--scope">
            <span>适用范围</span>
            <b>
              <div class="bd-scope">
                <a-select v-model="cur.scopeOrgs" multiple allow-clear size="small"
                          placeholder="不限组织" style="min-width: 210px">
                  <a-option v-for="o in orgOpts" :key="o.id" :value="o.id">
                    {{ o.name }}（{{ o.accounts.length }} 人）
                  </a-option>
                </a-select>
                <a-select v-model="cur.scopeGroups" multiple allow-clear size="small"
                          placeholder="不限用户组" style="min-width: 210px">
                  <a-option v-for="g in groupOpts" :key="g.id" :value="g.id">
                    {{ g.name }}（{{ g.accounts.length }} 人）
                  </a-option>
                </a-select>
              </div>
              <div class="bd-scope__hint">{{ scopeDetail(cur) }}</div>
            </b>
          </div>
          <div class="bd-kv"><span>覆盖平台</span>
            <b><span v-for="p in cur.platforms" :key="p" class="bd-tg bd-plat">{{ p }}</span></b>
          </div>
        </div>

        <!-- 处置动作（P7 风险分级配色）-->
        <div class="bd-card bd-disp">
          <div class="bd-section-title">命中处置动作</div>
          <div class="bd-disp__hint">终端未通过本基线检测项时的纵深准入处置（风险越高、处置越强）</div>
          <div class="bd-disp__grid">
            <button
              v-for="d in DISPOSALS"
              :key="d.key"
              class="bd-dchip"
              :class="{ on: cur.disposal === d.key }"
              :style="cur.disposal === d.key ? { borderColor: d.color, background: d.color + '14' } : {}"
              @click="cur.disposal = d.key"
            >
              <span class="bd-dchip__dot" :style="{ background: d.color }" />
              <span class="bd-dchip__t" :style="cur.disposal === d.key ? { color: d.color } : {}">{{ d.label }}</span>
              <span class="bd-dchip__d">{{ d.desc }}</span>
            </button>
          </div>
        </div>

        <!-- 平台条件编辑器（P6：分平台 AND 条件）-->
        <div class="bd-card bd-checks">
          <div class="bd-checks__top">
            <div>
              <div class="bd-section-title" style="margin-bottom: 4px">平台检测项 · 分平台 AND 条件</div>
              <div class="bd-checks__hint">同一平台下所有检测项需全部满足（AND）方判为合规，否则按上方处置动作执行</div>
            </div>
          </div>

          <!-- 平台 pill 切换 -->
          <div class="bd-platbar">
            <button
              v-for="p in PLATFORMS"
              :key="p"
              class="bd-platpill"
              :class="{ on: plat === p }"
              @click="plat = p"
            >
              {{ p }}
              <span class="bd-platpill__n">{{ checksFor(p).length }}</span>
            </button>
          </div>

          <!-- 检测项表 -->
          <table class="bd-table bd-chktable">
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
                <td><b style="color: var(--bd-t1); font-weight: 500">{{ c.label }}</b></td>
                <td><span class="bd-mono">{{ c.expect }}</span></td>
                <td>
                  <span class="bd-tg" :style="tagStyle(severityColor(c.severity))">{{ severityText(c.severity) }}</span>
                </td>
                <td>
                  <span class="bd-tg" :style="tagStyle(c.platform === 'All' ? '#722ED1' : '#86909C')">{{ c.platform === 'All' ? '全平台' : c.platform }}</span>
                </td>
                <td class="r">
                  <span class="bd-link bd-link--danger" @click="removeCheck(c.key)">删除</span>
                </td>
              </tr>
              <tr v-if="checksFor(plat).length === 0">
                <td colspan="5" class="bd-empty">该平台暂无检测项，可点击下方按钮添加</td>
              </tr>
            </tbody>
          </table>

          <!-- ★只能从采集器目录里选，不能自由填 key：采集器不报的 key 会让这条基线
               对全平台终端永远判违规（接入准入基线默认处置是 block）。目录由后端下发。 -->
          <div class="bd-addcheck-row">
            <a-select
              v-model="pickedCheck"
              size="small"
              placeholder="选择要添加的检测项…"
              :disabled="!addableChecks.length"
              style="flex: 1; max-width: 340px"
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
          <div v-if="pickedSpec?.note" class="bd-addcheck-hint"><icon-info-circle />{{ pickedSpec.note }}</div>
        </div>
      </div>
    </div>

    <!-- ============ 终端合规（最新 posture 上报 × 风险引擎判定）============ -->
    <div v-show="tab === 'posture'" class="bd-card" style="padding: 16px 20px">
      <div class="bd-section-title" style="display: flex; justify-content: space-between; align-items: center">
        终端合规状态（最新上报）
        <a-button size="small" @click="loadPosture"><icon-refresh /> 刷新</a-button>
      </div>
      <div v-if="postureErr" class="bd-empty" style="display: block">{{ postureErr }}</div>
      <table v-else class="bd-table">
        <thead>
          <tr><th>账号</th><th>设备指纹</th><th>平台 / 系统</th><th>客户端</th><th>检查</th><th>判定</th><th>评分</th><th>最后上报</th><th class="r">操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="p in postureRows" :key="p.user + p.device">
            <td><b style="color: var(--bd-t1)">{{ p.user }}</b></td>
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
                v-for="c in p.checks" :key="c.key" class="bd-tg" :title="c.value"
                :style="tagStyle(c.unknown ? '#86909C' : c.ok ? '#00B42A' : '#F53F3F')"
                style="margin: 1px 3px 1px 0"
              >{{ c.label }}{{ c.unknown ? '（无法判定）' : '' }}</span>
            </td>
            <td><span class="bd-tg" :style="tagStyle(verdictColor(p.verdict))">{{ verdictText(p.verdict) }}</span></td>
            <td><b :style="{ color: p.score >= 60 ? '#F53F3F' : p.score >= 30 ? '#FF7D00' : 'var(--bd-t1)' }">{{ p.score }}</b></td>
            <td style="color: var(--bd-t3)">{{ tsText(p.ts) }}</td>
            <td class="r">
              <a-popconfirm
                :content="p.verdict === 'block' ? '该设备为阻断状态，退役后将解除其触发的接入收缩。确认删除？' : '删除该设备的终端报告（设备退役）？'"
                type="warning" @ok="removePosture(p)"
              >
                <span class="bd-link bd-link--danger">退役</span>
              </a-popconfirm>
            </td>
          </tr>
          <tr v-if="postureRows.length === 0">
            <td colspan="9" class="bd-empty">尚无终端上报——桌面客户端登录后每 60s 自动上报</td>
          </tr>
        </tbody>
      </table>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type SecurityBundle, type BaselinePolicy, type BaselineCheck, type CheckSpec, type PostureRow, type PostureResp, type SubjectOption } from '@/lib/api';

type Platform = 'Windows' | 'macOS' | 'Linux';
const PLATFORMS: Platform[] = ['Windows', 'macOS', 'Linux'];

const tab = ref<'baseline' | 'posture'>('baseline');
const live = ref(false);

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
// ★这里原来还有一份 MOCK_SPA（G3 / 已隐身 / 敲门正常 / 6 个受保护端口）与页面上的
// 「SPA 服务隐身」页签，两者都已删除：控制面既不实测端口可见性，也不代数据面宣布
// 敲门是否正常，那张卡片是在替一台可能压根没配防火墙规则的网关打包票。
// 真实版本在「安全防护 → 网关与隐身 → SPA 服务隐身」，每一项都来自网关注册心跳。

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
const DISPOSALS: { key: BaselinePolicy['disposal']; label: string; desc: string; color: string }[] = [
  { key: 'allow', label: '放行', desc: '记录但不拦截', color: '#00B42A' },
  { key: 'degrade', label: '降权', desc: '仅放行低敏应用', color: '#FF7D00' },
  { key: 'block', label: '阻断', desc: '高危 · 直接拒绝接入', color: '#F53F3F' },
  { key: 'gray', label: '灰度', desc: '小范围观察', color: '#86909C' }
];

/* ── 颜色 / 文案 ── */
function disposalText(d: BaselinePolicy['disposal']) {
  return d === 'allow' ? '放行' : d === 'degrade' ? '降权' : d === 'block' ? '阻断' : '灰度';
}
function disposalColor(d: BaselinePolicy['disposal']) {
  return d === 'allow' ? '#00B42A' : d === 'degrade' ? '#FF7D00' : d === 'block' ? '#F53F3F' : '#86909C';
}
function severityText(s: BaselineCheck['severity']) { return s === 'high' ? '高' : s === 'medium' ? '中' : '低'; }
function severityColor(s: BaselineCheck['severity']) {
  return s === 'high' ? '#F53F3F' : s === 'medium' ? '#FF7D00' : '#86909C';
}
function tagStyle(color: string) { return { color, background: color + '14' }; }

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
  // ★展开为 0 人时当面说出来。限定了范围却一个人都不在里面 = 这条基线**对谁都不生效**，
  // 而它在列表上仍显示「已启用 · 阻断」——正是这次要消灭的那种"看着在管、实际不管"。
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
  } catch { Message.error('保存失败（需管理员登录 / 后端在线）'); } finally { saving.value = false; }
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
  } catch { Message.error('创建失败（需管理员登录 / 后端在线）'); }
}
async function removeBaseline() {
  if (!cur.value) return;
  const id = cur.value.id;
  try {
    await api(`/security/baselines/${id}`, { method: 'DELETE' });
    baselines.value = baselines.value.filter((b) => b.id !== id);
    if (baselines.value.length) selected.value = baselines.value[0].id;
    Message.success('基线已删除');
  } catch { Message.error('删除失败'); }
}
/**
 * 可添加的检测项 = 采集器目录 − 本基线已配的 key。
 *
 * ★不能让管理员自由填 key。采集器不上报的 key，风险引擎按「缺失即不合规」判该项失败
 * （那是防选择性上报的正确设计），于是这条基线对该平台**全体终端**永远违规——
 * 而接入准入基线的默认处置是 block，等于一键给所有人拒发敲门令牌 + 撤窗断隧道，
 * 保存那一刻零报错。此前这个按钮 100% 产出这种 key（写死 'c-' + Date.now()）。
 * 目录由后端随 /security 下发，与入口校验读同一份，前端不另抄一份。
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
const postureErr = ref('');
async function loadPosture() {
  try {
    postureRows.value = (await api<PostureResp>('/posture')).reports;
    postureErr.value = '';
  } catch { postureErr.value = '暂无法读取（需管理员登录 / 后端在线）'; }
}
function verdictText(v: string) { return v === 'allow' ? '合规' : v === 'degrade' ? '降权' : v === 'gray' ? '灰度' : '阻断'; }
function verdictColor(v: string) { return v === 'allow' ? '#00B42A' : v === 'degrade' ? '#FF7D00' : v === 'gray' ? '#86909C' : '#F53F3F'; }
function tsText(ts: number) { return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }); }
async function removePosture(p: PostureRow) {
  try {
    await api(`/posture/${encodeURIComponent(p.user)}/${encodeURIComponent(p.device)}`, { method: 'DELETE' });
    postureRows.value = postureRows.value.filter((r) => !(r.user === p.user && r.device === p.device));
    Message.success('终端报告已删除（设备退役）');
  } catch { Message.error('删除失败（需管理员登录 / 后端在线）'); }
}

onMounted(async () => {
  try {
    const b = await api<SecurityBundle>('/security');
    // 归一化：旧后端不带这两个字段时给空数组，否则 v-model 绑到 undefined 上，
    // 选一次组织就把整条基线的其它字段一起提交回一个 undefined。
    baselines.value = b.baselines.map((x) => ({ ...x, scopeOrgs: x.scopeOrgs ?? [], scopeGroups: x.scopeGroups ?? [] }));
    orgOpts.value = b.orgs ?? [];
    groupOpts.value = b.groups ?? [];
    // 目录取不到就给空数组——宁可「加不了检测项」，也不能回退成自由填 key：
    // 那正是这次要消灭的、会把全平台终端判违规的入口。
    catalog.value = b.checkCatalog ?? [];
    if (b.baselines.length) selected.value = b.baselines[0].id;
    live.value = true;
  } catch {
    live.value = false;
  }
  loadPosture();
});
</script>

<style scoped>
/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

.bd-two { display: flex; gap: 16px; align-items: flex-start; }
.bd-section-title { font-size: 15px; font-weight: 600; color: var(--bd-t1); margin-bottom: 14px; }
.bd-kv { display: flex; align-items: center; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid var(--bd-fill-1); font-size: 13px; }
.bd-kv:last-child { border-bottom: none; }
.bd-kv span { color: var(--bd-t3); }
.bd-kv b { font-weight: 500; color: var(--bd-t1); }
.bd-kv--scope { align-items: flex-start; }
.bd-kv--scope > span { padding-top: 5px; }
.bd-scope { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
.bd-scope__hint { margin-top: 6px; font-size: 11.5px; color: var(--bd-t3); text-align: right; font-weight: 400; }

/* 左：基线列表 */
.bd-blist { width: 300px; flex: none; padding: 10px; }
.bd-blist__h { display: flex; align-items: center; justify-content: space-between; font-size: 12px; font-weight: 600; color: var(--bd-t3); padding: 4px 8px 10px; }
.bd-blist__add { display: inline-flex; align-items: center; gap: 4px; color: var(--bd-primary); cursor: pointer; font-weight: 500; }
.bd-blist__add:hover { text-decoration: underline; }
.bd-bnode {
  width: 100%; display: block; text-align: left; border: 1px solid transparent; background: transparent;
  border-radius: 8px; cursor: pointer; padding: 10px 12px; transition: background .12s, border-color .12s; margin-bottom: 2px;
}
.bd-bnode:hover { background: var(--bd-fill-2); }
.bd-bnode.on { background: var(--bd-primary-1); border-color: var(--bd-primary-b); }
.bd-bnode__top { display: flex; align-items: center; justify-content: space-between; }
.bd-bnode__name { font-size: 13.5px; font-weight: 500; color: var(--bd-t1); }
.bd-bnode.on .bd-bnode__name { color: var(--bd-primary); }
.bd-bnode__tags { display: flex; gap: 6px; margin-top: 8px; }
.bd-bnode__scope { font-size: 11.5px; color: var(--bd-t3); margin-top: 7px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* 右：编辑区 */
.bd-bedit { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 14px; }

/* 概要卡 */
.bd-bhead { padding: 16px 20px; }
.bd-bhead__top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
.bd-bhead__name { font-size: 16px; font-weight: 700; color: var(--bd-t1); }
.bd-bhead__sw { display: flex; align-items: center; gap: 8px; }
.bd-bhead__swt { font-size: 12.5px; color: var(--bd-t3); }
.bd-plat { margin-right: 6px; }

/* tag 通用（页内细化 padding） */
.bd-tg { font-size: 11.5px; padding: 2px 8px; border-radius: 4px; font-weight: 500; display: inline-flex; align-items: center; gap: 4px; }

/* 处置动作 */
.bd-disp { padding: 16px 20px 18px; }
.bd-disp__hint { font-size: 12px; color: var(--bd-t3); margin: -8px 0 14px; }
.bd-disp__grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.bd-dchip {
  display: flex; flex-direction: column; align-items: flex-start; gap: 4px; text-align: left;
  border: 1.5px solid var(--bd-border); background: #fff; border-radius: 9px; padding: 12px 14px; cursor: pointer;
  transition: border-color .12s, background .12s;
}
.bd-dchip:hover { border-color: var(--bd-t4); }
.bd-dchip__dot { width: 8px; height: 8px; border-radius: 50%; }
.bd-dchip__t { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-dchip__d { font-size: 11.5px; color: var(--bd-t3); }

/* 平台检测项编辑器 */
.bd-checks { padding: 16px 20px 18px; }
.bd-checks__hint { font-size: 12px; color: var(--bd-t3); margin-bottom: 14px; }
.bd-platbar { display: flex; gap: 8px; margin-bottom: 14px; }
.bd-platpill {
  display: inline-flex; align-items: center; gap: 7px; border: 1px solid var(--bd-border); background: #fff;
  border-radius: 16px; padding: 6px 14px; font-size: 13px; color: var(--bd-t2); cursor: pointer; transition: all .12s;
}
.bd-platpill:hover { border-color: var(--bd-primary-b); }
.bd-platpill.on { background: var(--bd-primary-1); border-color: var(--bd-primary-b); color: var(--bd-primary); font-weight: 600; }
.bd-platpill__n { font-size: 11px; min-width: 18px; height: 18px; padding: 0 5px; border-radius: 9px; background: var(--bd-fill-2); color: var(--bd-t3); display: inline-flex; align-items: center; justify-content: center; }
.bd-platpill.on .bd-platpill__n { background: #fff; color: var(--bd-primary); }

.bd-chktable { border: 1px solid var(--bd-fill-2); border-radius: var(--bd-radius-s); overflow: hidden; }
.bd-chktable thead tr { background: var(--bd-fill-1); }
.bd-empty { text-align: center; color: var(--bd-t3); font-size: 12.5px; padding: 22px 0; }

.bd-addcheck-row {
  margin-top: 14px; padding: 10px 12px; border: 1px dashed var(--bd-border); background: var(--bd-fill-1);
  border-radius: 8px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
}
.bd-addcheck-note { font-size: 12px; color: var(--bd-t3); flex: 1; min-width: 200px; }
.bd-addcheck-hint {
  margin-top: 8px; padding: 8px 12px; border-radius: 6px; font-size: 12px; line-height: 1.6;
  color: var(--bd-t2); background: var(--bd-fill-1); display: flex; align-items: flex-start; gap: 6px;
}

</style>
