<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">升级管理</div>
        <div class="bd-page__sub">升级前校验 · 加密配置备份 · 客户端灰度发布</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '未连' }}</a-tag>
      </div>
    </div>

    <!-- 边界声明：由后端下发，前端不得自行编写或省略。
         这一章有大量源产品专有内容，不说清楚管理员会以为界面上没有的是「还没做完」。 -->
    <div v-for="(b, i) in bundle.boundaries" :key="i" class="bd-bound">
      <icon-info-circle-fill /><span>{{ b }}</span>
    </div>

    <div v-if="err" class="bd-bound bd-bound--err"><icon-close-circle-fill /><span>{{ err }}</span></div>

    <div class="bd-two">
      <!-- 版本与组件 -->
      <div class="bd-card bd-vers">
        <div class="bd-vers__h">当前版本</div>
        <div class="bd-vers__big">{{ bundle.control || '—' }}</div>
        <div class="bd-vers__sub">控制面 baidi-control</div>

        <div class="bd-sec2">网关组件</div>
        <div v-if="!gwList.length" class="bd-vers__empty">暂无网关注册</div>
        <div v-for="g in gwList" :key="g.id" class="bd-gwrow">
          <b class="bd-mono">{{ g.id }}</b>
          <span v-if="g.version" class="bd-tg" :style="tagStyle(g.version === bundle.control ? '#00B42A' : '#FF7D00')">
            {{ g.version }}
          </span>
          <!-- 不上报版本的旧网关如实标「无法校验」，绝不当成一致 -->
          <span v-else class="bd-tg bd-unknown" title="该网关版本低于 v0.4，不上报版本号——无法校验组件一致性">
            无法校验
          </span>
        </div>
      </div>

      <div style="flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 14px">
        <!-- 升级包校验 -->
        <div class="bd-card">
          <div class="bd-vers__h">升级包校验</div>
          <div class="bd-hint">
            粘贴升级包随附的 <b class="bd-mono">manifest.json</b> 原文与 <b class="bd-mono">.sig</b> 签名（base64）。
            描述原文必须**原样**粘贴——重新格式化会让签名验不过。
          </div>
          <a-textarea v-model="chk.manifest" :auto-size="{ minRows: 4, maxRows: 8 }"
            placeholder='{"product":"baidi","component":"control","version":"0.4.0","sha256":"…"}' class="bd-mono" />
          <a-input v-model="chk.sig" placeholder="签名（base64）" class="bd-mono" style="margin-top: 8px" />
          <div style="margin-top: 10px">
            <button class="bd-btn" :disabled="chk.busy || !chk.manifest.trim()"
              :style="{ opacity: chk.busy || !chk.manifest.trim() ? .5 : 1 }" @click="doCheck">校验</button>
          </div>
          <div v-if="chk.result" class="bd-chk" :class="chk.result.blocked ? 'bd-chk--bad' : 'bd-chk--ok'">
            <b>{{ chk.result.blocked ? '校验不通过 · 不可升级' : '校验通过' }}</b>
            <div v-for="(r, i) in chk.result.reasons ?? []" :key="'r' + i" class="bd-chk__l">✕ {{ r }}</div>
            <div v-for="(r, i) in chk.result.warnings ?? []" :key="'w' + i" class="bd-chk__l">⚠ {{ r }}</div>
            <div v-if="chk.result.nextHop" class="bd-chk__l">→ 请先升级到 <b>{{ chk.result.nextHop }}</b></div>
          </div>
        </div>

        <!-- 校验规则 -->
        <div class="bd-card">
          <div class="bd-vers__h">校验规则</div>
          <div class="bd-fld bd-fld--row">
            <div><label>允许降级</label><span class="bd-fld__d">默认禁止：数据库结构已被当前版本迁移，旧版读不了</span></div>
            <a-switch v-model="rules.allowDowngrade" @change="saveRules" />
          </div>
          <div class="bd-fld bd-fld--row">
            <div><label>校验组件一致性</label><span class="bd-fld__d">控制面与网关版本不一致时给出警告（不阻断）</span></div>
            <a-switch v-model="rules.requireComponentMatch" @change="saveRules" />
          </div>
          <div class="bd-sec2">强制跳跃链路</div>
          <div class="bd-hint" style="margin-bottom: 8px">
            低于「起始版本」的设备必须先升到「下一跳」，不得直升更高版本。
            白帝目前没有已知的不可直升版本对，故默认为空——留空即不限制。
          </div>
          <!-- ★两个输入框必须挂保存触发器。此前它们只有 v-model、整张卡也没有保存按钮，
               而同卡的两个开关挂了 @change 是**真保存**的——三项并排、两真一假，
               管理员没有任何线索区分：填好的一跳刷新即消失，库里 Rules.Hops 恒为空，
               于是 upgrade.CheckPackage 的链路约束对任何包都不触发（低版本直升最新包
               照样回「校验通过」，而这条规则存在的全部理由就是拦住这次升级）。
               副作用更迷惑：先填好一跳、再顺手拨一下任一开关，这一跳会被顺带存上，
               表现为「有时能保存有时不能」。 -->
          <div v-for="(h, i) in rules.hops" :key="i" class="bd-hop">
            <a-input v-model="h.below" placeholder="低于此版本" class="bd-mono" size="small"
              @blur="saveHops" @press-enter="saveHops" />
            <span>→ 先升到</span>
            <a-input v-model="h.next" placeholder="下一跳版本" class="bd-mono" size="small"
              @blur="saveHops" @press-enter="saveHops" />
            <button type="button" class="bd-link bd-link--danger" :aria-label="`删除第 ${i + 1} 条跳跃规则`"
              @click="rules.hops.splice(i, 1); saveRules()"><icon-delete /></button>
          </div>
          <button type="button" class="bd-link" @click="rules.hops.push({ below: '', next: '' })">
            <icon-plus />添加一跳
          </button>
          <!-- 半填状态要当面说：saveRules 会 filter 掉只填了一半的行，不说的话
               管理员会以为它存上了（页面上那一行还在）。 -->
          <div v-if="halfFilledHops" class="bd-hint bd-hint--warn">
            有 {{ halfFilledHops }} 条跳跃规则只填了一半，不会被保存——两栏都填完才生效。
          </div>
        </div>

        <!-- 客户端灰度 -->
        <div class="bd-card">
          <div class="bd-vers__h">客户端灰度发布</div>
          <div class="bd-hint">
            灰度判定在服务端做，终端只被告知一个版本号。同一账号的分桶稳定——
            扩大比例只会新增命中，不会把已升级的用户退回旧版。
          </div>
          <table class="bd-table" style="margin-top: 10px">
            <thead><tr><th>平台</th><th>稳定版</th><th>灰度版</th><th>比例</th><th>定向</th><th>预计影响</th><th class="r">操作</th></tr></thead>
            <tbody>
              <tr v-for="p in bundle.gray" :key="p.platform">
                <td><b>{{ platformLabel(p.platform) }}</b></td>
                <td class="bd-mono">{{ p.stable || '—' }}</td>
                <td class="bd-mono">{{ p.version }}</td>
                <td>{{ p.percent }}%</td>
                <td class="bd-dim" :title="targetTitle(p)">{{ targetText(p) }}</td>
                <!-- ★「预计影响」是 upgrade.Coverage 精确数出来的（分桶确定性），不是
                     accounts×percent/100 的估算。缺席时显示「—」而不是 0：
                     把读取失败画成「0 人」会让管理员以为这条灰度谁也没命中，进而调高比例。 -->
                <td>{{ coverText(p) }}</td>
                <td class="r">
                  <button type="button" class="bd-link" @click="openGray(p)">编辑</button>
                  <button type="button" class="bd-link bd-link--danger" style="margin-left: 12px"
                    @click="removeGray(p)">撤销</button>
                </td>
              </tr>
              <tr v-if="!bundle.gray.length">
                <td colspan="6" class="bd-vers__empty">尚无灰度计划——所有终端拿各自平台的稳定版。</td>
              </tr>
            </tbody>
          </table>
          <button type="button" class="bd-link" style="margin-top: 8px" @click="openGray()"><icon-plus />新增灰度计划</button>

          <!-- ★现场实际版本分布（FR-UPG-19 AC-12 的验收依据）。
               灰度只决定「告诉谁有新版」，不决定任何人**实际**装了什么——
               客户端不自动下载、不自动安装。放开比例前要看的是这一份，
               改造前它根本不存在，AC-12「先小范围验证再放开」在真机上无从验证。 -->
          <div class="bd-vers__sub">现场终端版本分布</div>
          <div class="bd-hint">
            来自终端 posture 上报（每台设备最新一份），是「谁在跑哪个版本」的唯一权威事实。
            <b>未上报</b>单列一桶——把它并进稳定版会让「有一批机器根本没报过版本」这件事消失，
            而那批机器恰恰是升级里最需要盯的。
          </div>
          <table v-if="versionRows.length" class="bd-table" style="margin-top: 8px">
            <thead><tr><th>平台</th><th>客户端版本</th><th>终端数</th></tr></thead>
            <tbody>
              <tr v-for="(v, i) in versionRows" :key="i">
                <td>{{ v.platform || '未上报' }}</td>
                <td :class="v.version ? 'bd-mono' : 'bd-dim'">{{ v.version || '未上报' }}</td>
                <td>{{ v.count }}</td>
              </tr>
            </tbody>
          </table>
          <div v-else class="bd-vers__empty" style="padding: 14px 0">
            尚无终端上报过环境（posture）——装上客户端并登录一次后这里就会有数据。
          </div>
        </div>

        <!-- 配置备份 -->
        <div class="bd-card">
          <div class="bd-vers__h">配置备份</div>
          <div class="bd-hint">
            备份含数据库、CA 私钥、IPSec PSK、认证源凭据与审计链密钥，
            整体以口令加密（PBKDF2 + AES-256-GCM），**不提供不加密的导出**。
            口令丢失无法找回——白帝不保存它。
          </div>
          <div class="bd-bkrow">
            <a-input-password v-model="bk.pass" placeholder="备份口令（至少 12 位）" />
            <a-input v-model="bk.note" placeholder="备注（如：升级前）" />
            <button class="bd-btn" :disabled="bk.busy || bk.pass.length < 12"
              :style="{ opacity: bk.busy || bk.pass.length < 12 ? .5 : 1 }" @click="doBackup">
              <icon-download />导出备份
            </button>
          </div>
          <div class="bd-hint" style="margin-top: 8px">
            恢复由停机后的部署脚本执行（解开归档覆盖回目录再启动）：在进程运行中就地覆写
            正在使用的数据库与密钥文件，会让一半请求读到旧库、一半读到新库，且失败后没有回头路。
          </div>
        </div>
      </div>
    </div>

    <!-- 灰度计划编辑 -->
    <a-modal v-model:visible="gr.open" :width="520" :title="gr.editing ? '编辑灰度计划' : '新增灰度计划'" :footer="false">
      <div class="bd-uform">
        <div class="bd-fld"><label>平台</label>
          <a-select v-model="gr.platform" :disabled="gr.editing">
            <a-option v-for="p in PLATFORMS" :key="p.key" :value="p.key">{{ p.label }}</a-option>
          </a-select>
        </div>
        <div class="bd-fld"><label>稳定版本</label>
          <a-input v-model="gr.stable" class="bd-mono" placeholder="0.4.0（不在灰度内的终端拿这个）" />
        </div>
        <div class="bd-fld"><label>灰度版本</label>
          <a-input v-model="gr.version" class="bd-mono" placeholder="0.5.0（必须高于稳定版）" />
        </div>
        <div class="bd-fld"><label>灰度比例：{{ gr.percent }}%</label>
          <a-slider v-model="gr.percent" :min="0" :max="100" :step="5" show-ticks />
        </div>
        <div class="bd-fld"><label>定向账号（无视比例，逗号分隔）</label>
          <a-input v-model="gr.accounts" placeholder="qa.liu, dev.wang" class="bd-mono" />
        </div>
        <!-- ★用户组定向：改造前这个多选**根本不存在**，而保存请求体里写死 groups: []。
             于是管理员只要在页面上改一下比例，经 API 配好的用户组定向就被整体清空——
             接口回 200、页面看不出差别，灰度对象从「测试组」变成「全体 N% 随机分桶」。
             SaveGrayPlan 是整条覆盖式保存，前端漏一个字段就是一次静默的配置丢失。 -->
        <div class="bd-fld"><label>定向用户组（无视比例）</label>
          <a-select v-model="gr.groups" multiple allow-clear placeholder="不按用户组定向">
            <a-option v-for="g in groupOpts" :key="g.id" :value="g.id">{{ g.name }}（{{ g.accounts.length }} 人）</a-option>
          </a-select>
        </div>
        <!-- ★措辞必须与算法一致：定向部分是精确的（就是这些人），比例部分是估算的
             （前端算不出服务端的 SHA-256 分桶）。写成「精确算出来的」就是在替一个
             估算值背书——保存后表格「预计影响」那一列才是后端精确数出来的权威值。 -->
        <div class="bd-fld__hint">
          预览：定向命中 <b>{{ previewDirect }}</b> 人（精确）
          <template v-if="gr.percent > 0">
            ＋ 按 {{ gr.percent }}% 分桶<b>约</b> {{ previewCoverage - previewDirect }} 人（估算，前端算不出服务端分桶）
          </template>
          ，共 {{ bundle.total ?? '—' }} 个账号。保存后表格「预计影响」列是后端精确数出来的。
        </div>
        <div class="bd-fld__foot">
          <button class="bd-btn bd-btn--ghost" @click="gr.open = false">取消</button>
          <button class="bd-btn" :disabled="gr.busy" @click="saveGray">保存</button>
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, getToken, type UpgradeBundle, type UpgradeRules, type GrayPlan, type UpgradeCheckResult } from '@/lib/api';

const PLATFORMS = [
  { key: 'macos', label: 'macOS' }, { key: 'windows', label: 'Windows' }, { key: 'linux', label: 'Linux' },
  { key: 'android', label: 'Android' }, { key: 'ios', label: 'iOS' }, { key: 'harmony', label: '鸿蒙' }
];
function platformLabel(k: string) { return PLATFORMS.find((p) => p.key === k)?.label ?? k; }
function tagStyle(color: string) { return { color, background: color + '14' }; }

const live = ref(false);
const err = ref('');
const bundle = ref<UpgradeBundle>({ control: '', gateways: {}, rules: { allowDowngrade: false, requireComponentMatch: true, hops: [] }, gray: [], boundaries: [] });
const rules = reactive<UpgradeRules>({ allowDowngrade: false, requireComponentMatch: true, hops: [] });

const gwList = computed(() => Object.entries(bundle.value.gateways ?? {})
  .map(([id, version]) => ({ id, version })).sort((a, b) => a.id.localeCompare(b.id)));

const chk = reactive({ manifest: '', sig: '', busy: false, result: null as UpgradeCheckResult | null });
const bk = reactive({ pass: '', note: '', busy: false });
const gr = reactive({ open: false, editing: false, busy: false, platform: 'macos', stable: '', version: '', percent: 10, accounts: '', groups: [] as string[] });

async function load() {
  try {
    const b = await api<UpgradeBundle>('/upgrade');
    bundle.value = b;
    Object.assign(rules, b.rules, { hops: b.rules.hops ?? [] });
    // 同步保存基线：不同步的话，进页面后第一次失焦（哪怕什么都没改）就会触发一次
    // 无谓的 PUT + toast，而那正是「保存触发器」最容易被做成噪声的地方。
    lastHopsJSON = JSON.stringify(rules.hops.filter((h) => h.below && h.next));
    live.value = true;
  } catch (e) {
    live.value = false;
    err.value = (e as Error).message || '无法读取升级配置';
  }
}

/** 跳跃链路的保存触发器（失焦 / 回车）。
 *
 *  只在**内容真的变了**时才发请求：输入框失焦本身很频繁（点一下别处就触发），
 *  每次都 PUT 会把审计冲成噪声，也会让「规则已保存」的 toast 在没改任何东西时乱弹。 */
let lastHopsJSON = '';
async function saveHops() {
  const cur = JSON.stringify(rules.hops.filter((h) => h.below && h.next));
  if (cur === lastHopsJSON) return;
  lastHopsJSON = cur;
  await saveRules();
}
/** 只填了一半的跳跃规则条数（saveRules 会把它们 filter 掉）。 */
const halfFilledHops = computed(
  () => rules.hops.filter((h) => (!!h.below) !== (!!h.next)).length
);

async function saveRules() {
  try {
    await api('/upgrade/rules', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...rules, hops: rules.hops.filter((h) => h.below && h.next) })
    });
    Message.success('规则已保存');
    await load();
  } catch (e) { err.value = (e as Error).message || '保存规则失败'; }
}

async function doCheck() {
  chk.busy = true; err.value = ''; chk.result = null;
  try {
    // manifest 原文必须原样送到后端验签：这里解析只为了尽早发现 JSON 语法错，
    // 送出去的仍是用户粘贴的原文（重新序列化会改变字节，签名就验不过了）。
    let parsed: unknown;
    try { parsed = JSON.parse(chk.manifest); } catch { throw new Error('描述不是合法 JSON'); }
    chk.result = await api<UpgradeCheckResult>('/upgrade/check', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ manifest: parsed, signature: chk.sig.trim() })
    });
  } catch (e) { err.value = (e as Error).message || '校验失败'; }
  finally { chk.busy = false; }
}

/** 灰度定向的用户组候选（后端随 /upgrade 下发，与资源授权、认证策略共用同一处展开）。 */
const groupOpts = computed(() => bundle.value.groups ?? []);
/** 版本分布按「终端数降序」排：升级要先看的是量最大的那一桶。 */
const versionRows = computed(() => [...(bundle.value.versions ?? [])].sort((a, b) => b.count - a.count));

function targetText(p: GrayPlan) {
  const a = p.accounts?.length ?? 0, g = p.groups?.length ?? 0;
  if (!a && !g) return '—';
  return [a ? `${a} 账号` : '', g ? `${g} 用户组` : ''].filter(Boolean).join(' + ');
}
function targetTitle(p: GrayPlan) {
  const names = (p.groups ?? []).map((id) => groupOpts.value.find((x) => x.id === id)?.name || id);
  return [ (p.accounts ?? []).join('、'), names.join('、') ].filter(Boolean).join(' | ') || '未做定向';
}
/** ★缺席（后端读取失败）显示「—」，不是 0。两者在决策上正好相反。 */
function coverText(p: GrayPlan) {
  const c = bundle.value.coverage?.[p.platform];
  if (c === undefined) return '—';
  const total = bundle.value.total;
  return total ? `${c} / ${total} 人` : `${c} 人`;
}
/** 弹窗里的实时预览：与后端 upgrade.Decide 同构（定向命中 → 必中；否则按稳定分桶）。
 *  ★只是预览，权威值是保存后后端算的那份（表格「预计影响」列）。 */
/** 定向命中（账号 ∪ 用户组展开）——这一半是精确的。 */
const previewDirect = computed(() => {
  const direct = new Set(gr.accounts.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean));
  for (const id of gr.groups) {
    groupOpts.value.find((g) => g.id === id)?.accounts.forEach((a) => direct.add(a.toLowerCase()));
  }
  return direct.size;
});
const previewCoverage = computed(() => {
  const direct = new Set(gr.accounts.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean));
  for (const id of gr.groups) {
    groupOpts.value.find((g) => g.id === id)?.accounts.forEach((a) => direct.add(a.toLowerCase()));
  }
  const total = bundle.value.total ?? 0;
  if (!gr.version.trim()) return 0; // 版本为空 = 撤销该平台的灰度（后端语义）
  // 比例部分按 percent 估：前端算不出 SHA-256 分桶，故只对定向部分精确、比例部分取整估。
  const byPercent = Math.round(((total - direct.size) * gr.percent) / 100);
  return direct.size + Math.max(0, byPercent);
});

function openGray(p?: GrayPlan) {
  err.value = '';
  Object.assign(gr, {
    open: true, editing: !!p, busy: false,
    platform: p?.platform ?? 'macos', stable: p?.stable ?? '', version: p?.version ?? '',
    percent: p?.percent ?? 10, accounts: (p?.accounts ?? []).join(', '),
    // ★必须回填：不回填 + 保存时整条覆盖 = 编辑一次就把用户组定向清空。
    groups: [...(p?.groups ?? [])]
  });
}

async function saveGray() {
  gr.busy = true; err.value = '';
  try {
    await api('/upgrade/gray', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        platform: gr.platform, stable: gr.stable.trim(), version: gr.version.trim(),
        percent: gr.percent,
        accounts: gr.accounts.split(',').map((s) => s.trim()).filter(Boolean),
        groups: [...gr.groups]
      })
    });
    gr.open = false;
    Message.success('灰度计划已保存');
    await load();
  } catch (e) { err.value = (e as Error).message || '保存灰度计划失败'; }
  finally { gr.busy = false; }
}

async function removeGray(p: GrayPlan) {
  try {
    // version 置空即撤销该平台的计划（后端语义）
    await api('/upgrade/gray', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ platform: p.platform, version: '', stable: p.stable, percent: 0, accounts: [], groups: [] })
    });
    Message.success(`已撤销 ${platformLabel(p.platform)} 的灰度计划`);
    await load();
  } catch (e) { err.value = (e as Error).message || '撤销失败'; }
}

async function doBackup() {
  bk.busy = true; err.value = '';
  try {
    // 备份是二进制附件，走原生 fetch 而不是 api()（后者只处理 JSON）。
    const res = await fetch('/api/v1/upgrade/backup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
      body: JSON.stringify({ passphrase: bk.pass, note: bk.note })
    });
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: { message?: string } } | null;
      throw new Error(body?.error?.message ?? `${res.status} ${res.statusText}`);
    }
    const blob = await res.blob();
    const cd = res.headers.get('Content-Disposition') ?? '';
    const name = /filename=([^;]+)/.exec(cd)?.[1]?.trim() || 'baidi-backup.bak';
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
    Message.success(`备份已导出（${(blob.size / 1024).toFixed(0)} KB）`);
    bk.pass = '';
  } catch (e) { err.value = (e as Error).message || '导出备份失败'; }
  finally { bk.busy = false; }
}

onMounted(load);
</script>

<style scoped>
.bd-bound {
  display: flex; align-items: flex-start; gap: 8px; margin-bottom: 10px; padding: 10px 12px;
  border-radius: 8px; font-size: 12.5px; line-height: 1.7;
  color: var(--bd-t2); background: var(--bd-fill-2); border: 1px solid var(--bd-line);
}
.bd-bound--err { color: var(--bd-danger); background: var(--bd-tag-red-bg); border-color: #FFC2C2; }
.bd-bound > :first-child { flex: none; margin-top: 3px; font-size: 14px; color: var(--bd-t3); }

.bd-vers { width: 300px; flex: none; padding: 16px; align-self: flex-start; }
.bd-vers__h { font-size: 13px; font-weight: 600; margin-bottom: 10px; }
.bd-vers__big { font-size: 30px; font-weight: 700; color: var(--bd-primary); font-family: ui-monospace, monospace; }
.bd-vers__sub { font-size: 12px; color: var(--bd-t3); margin-top: 2px; }
.bd-vers__empty { color: var(--bd-t3); font-size: 12.5px; padding: 14px 0; text-align: center; }
.bd-gwrow { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 7px 0; border-top: 1px solid var(--bd-line); font-size: 12.5px; }
.bd-unknown { color: var(--bd-t3); background: var(--bd-fill-2); cursor: help; }

.bd-sec2 { font-size: 12px; font-weight: 600; color: var(--bd-t2); margin: 16px 0 8px; padding-top: 12px; border-top: 1px solid var(--bd-line); }
.bd-hint { font-size: 12px; color: var(--bd-t3); line-height: 1.7; margin-bottom: 8px; }
.bd-dim { color: var(--bd-t3); }

.bd-chk { margin-top: 12px; padding: 10px 12px; border-radius: 8px; font-size: 12.5px; line-height: 1.8; }
.bd-chk--ok { color: #1D7A38; background: #E8FFEA; border: 1px solid #AFF0B5; }
.bd-chk--bad { color: var(--bd-danger); background: var(--bd-tag-red-bg); border: 1px solid #FFC2C2; }
.bd-chk__l { margin-top: 2px; }

.bd-hop { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 12px; color: var(--bd-t3); }
.bd-hop :deep(.arco-input-wrapper) { width: 130px; }
.bd-bkrow { display: flex; align-items: center; gap: 10px; }
.bd-bkrow :deep(.arco-input-wrapper) { flex: 1; }

.bd-fld { margin-bottom: 16px; }
.bd-fld > label { display: block; font-size: 13px; font-weight: 500; color: var(--bd-t1); margin-bottom: 7px; }
.bd-fld :deep(.arco-input-wrapper), .bd-fld :deep(.arco-select-view) { width: 100%; }
.bd-fld--row { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.bd-fld--row label { display: block; margin-bottom: 2px; }
.bd-fld__d { display: block; margin-top: 4px; font-size: 12px; color: var(--bd-t3); line-height: 1.6; }
.bd-fld--row .bd-fld__d { margin-top: 0; }
.bd-fld__foot { display: flex; justify-content: flex-end; gap: 10px; }
.bd-hint--warn { margin-top: 8px; padding: 6px 10px; border-radius: 5px;
  color: var(--bd-warning); background: var(--bd-tag-gold-bg, #FFF7E8); }
</style>
