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
      <span class="bd-tab" :class="{ on: tab === 'spa' }" @click="tab = 'spa'">SPA 服务隐身</span>
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
            <span class="bd-tg" :style="tagStyle('#165DFF')">{{ typeText(b.type) }}</span>
            <span class="bd-tg" :style="tagStyle(disposalColor(b.disposal))">{{ disposalText(b.disposal) }}</span>
          </div>
          <div class="bd-bnode__scope">{{ b.scope }}</div>
        </button>
      </div>

      <!-- 右：基线详情 / 编辑 -->
      <div class="bd-bedit" v-if="cur">
        <!-- 概要卡 -->
        <div class="bd-card bd-bhead">
          <div class="bd-bhead__top">
            <div style="display: flex; align-items: center; gap: 10px">
              <a-input v-model="cur.name" size="small" style="width: 220px; font-weight: 700" />
              <span class="bd-bhead__type bd-tg" :style="tagStyle('#165DFF')">{{ typeText(cur.type) }}</span>
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
          <div class="bd-kv"><span>适用范围</span><b>{{ cur.scope }}</b></div>
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

          <button class="bd-addcheck" @click="addCheck"><icon-plus />添加检测项（{{ plat }}）</button>
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
          <tr><th>账号</th><th>设备指纹</th><th>平台 / 系统</th><th>客户端</th><th>检查</th><th>判定</th><th>评分</th><th>最后上报</th></tr>
        </thead>
        <tbody>
          <tr v-for="p in postureRows" :key="p.user + p.device">
            <td><b style="color: var(--bd-t1)">{{ p.user }}</b></td>
            <td><span class="bd-mono">{{ p.device }}</span></td>
            <td>{{ p.platform }} · {{ p.os || '—' }}</td>
            <td>{{ p.clientVersion || '—' }}</td>
            <td>
              <span v-for="c in p.checks" :key="c.key" class="bd-tg" :style="tagStyle(c.ok ? '#00B42A' : '#F53F3F')" style="margin: 1px 3px 1px 0">{{ c.label }}</span>
            </td>
            <td><span class="bd-tg" :style="tagStyle(verdictColor(p.verdict))">{{ verdictText(p.verdict) }}</span></td>
            <td><b :style="{ color: p.score >= 60 ? '#F53F3F' : p.score >= 30 ? '#FF7D00' : 'var(--bd-t1)' }">{{ p.score }}</b></td>
            <td style="color: var(--bd-t3)">{{ tsText(p.ts) }}</td>
          </tr>
          <tr v-if="postureRows.length === 0">
            <td colspan="8" class="bd-empty">尚无终端上报——桌面客户端登录后每 60s 自动上报</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- ============ SPA 服务隐身 ============ -->
    <div v-show="tab === 'spa'">
      <div class="bd-spa">
        <!-- 状态总览卡 -->
        <div class="bd-card bd-spacard">
          <div class="bd-section-title">服务隐身状态</div>
          <div class="bd-spa__top">
            <div class="bd-gen">
              <span class="bd-gen__badge">{{ spa.generation }}</span>
              <span class="bd-gen__cap">单包授权代次</span>
            </div>
            <div class="bd-spa__meta">
              <div class="bd-kv"><span>认证模式</span><b>{{ spa.authMode }}</b></div>
              <div class="bd-kv"><span>服务隐身</span>
                <b>
                  <span class="bd-st"><span class="d" :style="{ background: spa.hidden ? 'var(--bd-success)' : 'var(--bd-danger)' }" />{{ spa.hidden ? '已隐身（端口默认丢弃）' : '未隐身' }}</span>
                </b>
              </div>
              <div class="bd-kv"><span>SPA 敲门校验</span>
                <b>
                  <span class="bd-tg" :style="tagStyle(spa.knockOk ? '#00B42A' : '#F53F3F')">
                    {{ spa.knockOk ? '正常' : '异常' }}
                  </span>
                </b>
              </div>
            </div>
          </div>

          <div class="bd-spa__ports">
            <div class="bd-spa__portshead">受保护端口（默认对外不可见，仅 SPA 敲门后短暂放行）</div>
            <div class="bd-spa__portslist">
              <span v-for="p in spa.protectedPorts" :key="p" class="bd-tg bd-port"><icon-lock />{{ p }}</span>
            </div>
          </div>
        </div>

        <!-- 隐身效果对比 -->
        <div class="bd-section-title" style="margin-top: 22px">隐身效果 · 未装专属客户端 vs 已装客户端</div>
        <div class="bd-cmp">
          <div class="bd-card bd-cmp__c bd-cmp__c--bad">
            <div class="bd-cmp__h">
              <icon-close-circle-fill class="bd-cmp__ic bad" />未装专属客户端
            </div>
            <ul class="bd-cmp__list">
              <li><icon-info-circle />端口扫描全程超时，<b>无任何端口可探测</b></li>
              <li><icon-info-circle />未通过 SPA 敲门，网关<b>静默丢弃</b>所有报文</li>
              <li><icon-info-circle />无法建立 TCP 连接，<b>无法接入</b>任何业务</li>
              <li><icon-info-circle />在攻击者视角下，网关与业务<b>等同于不存在</b></li>
            </ul>
            <div class="bd-cmp__foot bad">攻击面 = 0 · 先认证后连接</div>
          </div>

          <div class="bd-card bd-cmp__c bd-cmp__c--good">
            <div class="bd-cmp__h">
              <icon-check-circle-fill class="bd-cmp__ic good" />已装专属客户端
            </div>
            <ul class="bd-cmp__list">
              <li><icon-check-circle-fill class="li-ok" />客户端发送 <b>{{ spa.generation }} 单包授权</b>完成身份敲门</li>
              <li><icon-check-circle-fill class="li-ok" />网关校验通过后<b>按需短暂放行</b>受保护端口</li>
              <li><icon-check-circle-fill class="li-ok" />仅放行<b>本人已授权应用</b>，其余仍不可见</li>
              <li><icon-check-circle-fill class="li-ok" />会话结束端口<b>立即重新隐身</b></li>
            </ul>
            <div class="bd-cmp__foot good">认证通过 · 最小化按需暴露</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type SecurityBundle, type BaselinePolicy, type BaselineCheck, type SpaStatus, type PostureRow, type PostureResp } from '@/lib/api';

type Platform = 'Windows' | 'macOS' | 'Linux';
const PLATFORMS: Platform[] = ['Windows', 'macOS', 'Linux'];

const tab = ref<'baseline' | 'spa' | 'posture'>('baseline');
const live = ref(false);

/* ── 内置 mock（结构同后端 SecurityBundle）── */
const MOCK_BASELINES: BaselinePolicy[] = [
  {
    id: 'bl-onboard', name: '上线准入基线 · 全员', type: 'onboarding',
    scope: '全部访问者 / 所有终端', disposal: 'block', status: 'enabled',
    platforms: ['Windows', 'macOS', 'Linux'],
    checks: [
      { key: 'av', label: '杀毒软件运行中', platform: 'All', expect: '进程存活 + 病毒库 ≤ 7 天', severity: 'high' },
      { key: 'patch', label: '高危补丁已安装', platform: 'Windows', expect: 'KB 缺失 = 0', severity: 'high' },
      { key: 'disk', label: '磁盘加密已开启', platform: 'Windows', expect: 'BitLocker = On', severity: 'medium' },
      { key: 'filevault', label: '磁盘加密已开启', platform: 'macOS', expect: 'FileVault = On', severity: 'medium' },
      { key: 'firewall', label: '系统防火墙启用', platform: 'macOS', expect: 'pf 状态 = enabled', severity: 'medium' },
      { key: 'selinux', label: '强制访问控制开启', platform: 'Linux', expect: 'SELinux = enforcing', severity: 'low' }
    ]
  },
  {
    id: 'bl-app-core', name: '核心业务防护基线', type: 'app-protect',
    scope: '财务系统 / OA / 代码仓库', disposal: 'degrade', status: 'enabled',
    platforms: ['Windows', 'macOS'],
    checks: [
      { key: 'client-guard', label: '客户端进程防护开启', platform: 'All', expect: '防调试 / 防 dump = On', severity: 'high' },
      { key: 'screen-lock', label: '锁屏超时合规', platform: 'All', expect: '空闲锁屏 ≤ 5 分钟', severity: 'medium' },
      { key: 'usb', label: '外设存储管控', platform: 'Windows', expect: 'USB 大容量存储 = 禁用', severity: 'high' },
      { key: 'gatekeeper', label: '应用来源校验', platform: 'macOS', expect: 'Gatekeeper = On', severity: 'low' }
    ]
  },
  {
    id: 'bl-byod', name: '个人设备灰度基线', type: 'onboarding',
    scope: '个人 BYOD 设备', disposal: 'gray', status: 'disabled',
    platforms: ['Windows', 'macOS', 'Linux'],
    checks: [
      { key: 'managed', label: '已注册受管', platform: 'All', expect: '资产纳管 = true', severity: 'medium' },
      { key: 'root', label: '未越狱 / 未提权', platform: 'Linux', expect: 'root 异常 = 无', severity: 'low' }
    ]
  }
];
const MOCK_SPA: SpaStatus = {
  generation: 'G3',
  authMode: 'SPA 单包授权 + mTLS 双向证书',
  protectedPorts: ['443/HTTPS', '8443/HTTPS', '22/SSH', '3389/RDP', '5432/PG', '6379/Redis'],
  hidden: true,
  knockOk: true
};

const baselines = ref<BaselinePolicy[]>(MOCK_BASELINES);
const spa = ref<SpaStatus>(MOCK_SPA);
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
function typeText(t: BaselinePolicy['type']) { return t === 'onboarding' ? '上线准入' : '应用防护'; }
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
    id: '', name: '新建基线', type: 'onboarding', scope: '全体访问者', disposal: 'degrade', status: 'enabled',
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
function addCheck() {
  if (!cur.value) return;
  cur.value.checks.push({
    key: 'c-' + Date.now(),
    label: '新检测项',
    platform: plat.value,
    expect: '待配置',
    severity: 'medium'
  });
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

onMounted(async () => {
  try {
    const b = await api<SecurityBundle>('/security');
    baselines.value = b.baselines;
    spa.value = b.spa;
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
.bd-bhead__type { margin-left: 10px; }
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

.bd-addcheck {
  margin-top: 14px; width: 100%; height: 38px; border: 1px dashed var(--bd-border); background: var(--bd-fill-1);
  border-radius: 8px; color: var(--bd-primary); font-size: 13px; font-weight: 500; cursor: pointer;
  display: inline-flex; align-items: center; justify-content: center; gap: 6px; transition: all .12s;
}
.bd-addcheck:hover { border-color: var(--bd-primary); background: var(--bd-primary-1); }

/* ── SPA（复用 Gateway 写法）── */
.bd-spa { max-width: 1080px; }
.bd-spacard { padding: 18px 20px 20px; }
.bd-spa__top { display: flex; gap: 28px; align-items: stretch; }
.bd-gen { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; width: 168px; flex: none; background: var(--bd-primary-1); border: 1px solid var(--bd-primary-b); border-radius: var(--bd-radius); padding: 18px 0; }
.bd-gen__badge { font-size: 40px; font-weight: 800; color: var(--bd-primary); line-height: 1; letter-spacing: 1px; }
.bd-gen__cap { font-size: 12px; color: var(--bd-t3); }
.bd-spa__meta { flex: 1; min-width: 0; display: flex; flex-direction: column; justify-content: center; }

.bd-spa__ports { margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--bd-fill-2); }
.bd-spa__portshead { font-size: 12.5px; color: var(--bd-t3); margin-bottom: 12px; }
.bd-spa__portslist { display: flex; flex-wrap: wrap; gap: 10px; }
.bd-port { font-size: 12.5px; padding: 5px 12px; border-radius: 14px; background: var(--bd-fill-2); color: var(--bd-t2); font-family: ui-monospace, monospace; }

/* 对比卡 */
.bd-cmp { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.bd-cmp__c { padding: 18px 20px; }
.bd-cmp__c--bad { border-color: var(--bd-tag-red-bg); background: linear-gradient(180deg, #FFF8F7 0%, #fff 60%); }
.bd-cmp__c--good { border-color: var(--bd-tag-green-bg); background: linear-gradient(180deg, #F6FFF8 0%, #fff 60%); }
.bd-cmp__h { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--bd-t1); margin-bottom: 14px; }
.bd-cmp__ic { font-size: 18px; }
.bd-cmp__ic.bad { color: var(--bd-danger); }
.bd-cmp__ic.good { color: var(--bd-success); }
.bd-cmp__list { list-style: none; margin: 0; padding: 0; }
.bd-cmp__list li { display: flex; align-items: flex-start; gap: 8px; font-size: 13px; color: var(--bd-t2); line-height: 1.7; padding: 5px 0; }
.bd-cmp__list li :deep(svg) { flex: none; margin-top: 4px; color: var(--bd-t4); font-size: 13px; }
.bd-cmp__list li :deep(svg.li-ok) { color: var(--bd-success); }
.bd-cmp__list b { color: var(--bd-t1); font-weight: 600; }
.bd-cmp__foot { margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--bd-fill-2); font-size: 12.5px; font-weight: 600; }
.bd-cmp__foot.bad { color: var(--bd-danger); }
.bd-cmp__foot.good { color: #0B8235; }
</style>
