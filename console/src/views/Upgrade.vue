<template>
  <div class="bd-page">
    <!-- 本页没有降级演示数据（编一条假的灰度计划比空着更危险），离线态标「数据未读取」 -->
    <PageHeader title="升级管理" subtitle="升级前校验 · 加密配置备份 · 客户端灰度发布" :live="live" off-text="数据未读取" off-color="red" />

    <!-- 边界声明：由后端下发，前端不得自行编写或省略。
         这一章有大量源产品专有内容，不说清楚管理员会以为界面上没有的是「还没做完」。 -->
    <div v-for="(b, i) in bundle.boundaries" :key="i" class="bd-notice bd-notice--plain bd-up__bound">
      <icon-info-circle-fill /><span>{{ b }}</span>
    </div>

    <!-- 边界声明整段消失比说错更危险：这一章有大量源产品专有内容没做，
         清单不见了会被读成「这一页的能力都齐了」。读不到就当面说读不到。 -->
    <div v-if="!bundle.boundaries.length && loadErr" class="bd-notice bd-notice--warn bd-up__bound">
      <icon-exclamation-circle-fill />
      <span>「本版本未实现」的边界声明由控制面随 <i class="bd-mono">/upgrade</i> 下发，本次未读到——这不是「没有边界」。</span>
    </div>

    <div v-if="err" class="bd-notice bd-notice--danger"><icon-close-circle-fill /><span>{{ err }}</span></div>

    <div class="bd-two">
      <!-- 版本与组件 -->
      <div class="bd-card bd-vers">
        <div class="bd-card__h">当前版本</div>
        <SkeletonBlock v-if="!loaded" kind="card" :rows="4" />
        <div v-else class="bd-card__b">
          <!-- ★未注入时显示「未注入」而不是任何数字：这一格此前读的是源码里的常量，
               而 -ldflags -X 对常量静默无效——它显示的版本与这台机器上装的是哪次构建无关。 -->
          <div class="bd-vers__big bd-mono">{{ bundle.control || '未注入' }}</div>
          <div class="bd-vers__sub">控制面 baidi-control</div>
          <!-- 构建标识是与语义版本**并列**的第二个字段：同一个 0.4.0 可以是几十次不同的构建，
               出事那天要拿它去对代码。 -->
          <div class="bd-vers__build bd-mono">构建 {{ bundle.controlBuild || '未注入' }}</div>
          <div v-if="bundle.controlNote" class="bd-notice bd-notice--warn bd-up__vnote">
            <icon-exclamation-circle-fill /><span>{{ bundle.controlNote }}</span>
          </div>

          <div class="bd-sec2">网关组件</div>
          <!-- ★读取失败时不许再说「暂无网关注册」：那是一句确定结论，而此刻的事实是没读到。 -->
          <EmptyState v-if="!gwList.length && loadErr" size="sm" tone="danger" title="网关组件未读取"
            :desc="`后端原话：${loadErr}　这不是「没有网关」——组件版本一致性此刻不可判定。`" />
          <EmptyState v-else-if="!gwList.length" size="sm" tone="warn" title="暂无网关注册" />
          <div v-for="g in gwList" :key="g.id" class="bd-gwrow">
            <b class="bd-mono">{{ g.id }}</b>
            <span v-if="gwVerState(g.version) === 'match'" class="bd-tg bd-tg--green">{{ g.version }}</span>
            <span v-else-if="gwVerState(g.version) === 'stale'" class="bd-tg bd-tg--gold"
              :title="`与控制面 ${bundle.control} 不一致`">{{ g.version }}</span>
            <!-- 不可判定单成一档：它与「确定不一致」的下一步动作完全不同（去升级构建 vs 去同步版本） -->
            <span v-else class="bd-tg bd-tg--grey bd-up__unk" :title="gwVerTitle(g.version)">不可判定</span>
            <span v-if="g.build" class="bd-up__gwbuild bd-mono" :title="`构建标识：${g.build}`">{{ g.build }}</span>
          </div>
        </div>
      </div>

      <div class="bd-two__main bd-up__col">
        <!-- 升级包校验 -->
        <div class="bd-card">
          <div class="bd-card__h">升级包校验</div>
          <div class="bd-card__b">
            <div class="bd-hint">
              粘贴升级包随附的 <b class="bd-mono">manifest.json</b> 原文与 <b class="bd-mono">.sig</b> 签名（base64）。
              描述原文必须**原样**粘贴——重新格式化会让签名验不过。
            </div>
            <a-textarea v-model="chk.manifest" :auto-size="{ minRows: 4, maxRows: 8 }"
              placeholder='{"product":"baidi","component":"control","version":"0.4.0","sha256":"…"}' class="bd-mono" />
            <a-input v-model="chk.sig" placeholder="签名（base64）" class="bd-mono bd-up__sig" />
            <!-- ★没配发布公钥时**先说清楚再置灰**，而不是让人撞一次「校验不通过」。
                 验签是 fail-closed 的（不验签等于任何人都能推包上来，方向是对的），
                 但在此之前页面完全不提这件事：管理员会以为是自己的包有问题，反复换包重传。 -->
            <div v-if="bundle && bundle.signKeysConfigured === false" class="bd-notice bd-notice--warn bd-up__signwarn">
              <icon-exclamation-circle-fill />
              <span>{{ bundle.signKeyNote }}</span>
            </div>
            <div class="bd-up__act">
              <button class="bd-btn" :disabled="signBlocked || chk.busy || !chk.manifest.trim()"
                :title="signBlocked ? '未配置发布公钥，校验必然不通过' : ''" @click="doCheck">校验</button>
            </div>
            <div v-if="chk.result" class="bd-notice bd-up__chk" :class="chk.result.blocked ? 'bd-notice--danger' : 'bd-notice--success'">
              <icon-close-circle-fill v-if="chk.result.blocked" />
              <icon-check-circle-fill v-else />
              <div class="bd-notice__body">
                <b>{{ chk.result.blocked ? '校验不通过 · 不可升级' : '校验通过' }}</b>
                <div v-for="(r, i) in chk.result.reasons ?? []" :key="'r' + i" class="bd-chk__l">✕ {{ r }}</div>
                <div v-for="(r, i) in chk.result.warnings ?? []" :key="'w' + i" class="bd-chk__l">⚠ {{ r }}</div>
                <div v-if="chk.result.nextHop" class="bd-chk__l">→ 请先升级到 <b>{{ chk.result.nextHop }}</b></div>
              </div>
            </div>
          </div>
        </div>

        <!-- 校验规则 -->
        <div class="bd-card">
          <div class="bd-card__h">校验规则</div>
          <div class="bd-card__b">
            <div class="bd-fld bd-fld--row">
              <div><label>允许降级</label><span class="bd-fld__d">默认禁止：数据库结构已被当前版本迁移，旧版读不了</span></div>
              <a-switch v-model="rules.allowDowngrade" @change="saveRules" />
            </div>
            <div class="bd-fld bd-fld--row">
              <div><label>校验组件一致性</label><span class="bd-fld__d">控制面与网关版本不一致时给出警告（不阻断）</span></div>
              <a-switch v-model="rules.requireComponentMatch" @change="saveRules" />
            </div>
            <div class="bd-sec2">强制跳跃链路</div>
            <div class="bd-hint">
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
            <div v-if="halfFilledHops" class="bd-notice bd-notice--warn bd-up__half">
              <icon-exclamation-circle-fill />
              <span>有 {{ halfFilledHops }} 条跳跃规则只填了一半，不会被保存——两栏都填完才生效。</span>
            </div>
          </div>
        </div>

        <!-- 客户端灰度 -->
        <div class="bd-card">
          <div class="bd-card__h">客户端灰度发布</div>
          <div class="bd-card__b">
            <div class="bd-hint">
              灰度判定在服务端做，终端只被告知一个版本号。同一账号的分桶稳定——
              扩大比例只会新增命中，不会把已升级的用户退回旧版。
            </div>
            <div class="bd-up__tbl">
              <SkeletonBlock v-if="!loaded" kind="table" :rows="3" :cols="7" />
              <table v-else class="bd-table">
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
                      <span class="bd-acts">
                        <button type="button" class="bd-link" @click="openGray(p)">编辑</button>
                        <button type="button" class="bd-link bd-link--danger" @click="removeGray(p)">撤销</button>
                      </span>
                    </td>
                  </tr>
                  <tr v-if="!bundle.gray.length" class="bd-table__emptyrow">
                    <td colspan="7">
                      <EmptyState v-if="loadErr" size="sm" tone="danger" title="灰度计划未读取"
                        :desc="`后端原话：${loadErr}　这不是「没有灰度计划」——现网可能正有一条计划在分发。`" />
                      <EmptyState v-else size="sm" title="尚无灰度计划" desc="所有终端拿各自平台的稳定版。" />
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <button type="button" class="bd-link bd-up__add" @click="openGray()"><icon-plus />新增灰度计划</button>

            <!-- ★现场实际版本分布。灰度只决定「告诉谁有新版」，不决定任何人**实际**装了什么
                 （客户端不自动下载、不自动安装）——放开比例前要看的是这一份。 -->
            <div class="bd-sec2">现场终端版本分布</div>
            <div class="bd-hint">
              来自终端 posture 上报（每台设备最新一份），是「谁在跑哪个版本」的唯一权威事实。
              <b>未上报</b>单列一桶——把它并进稳定版会让「有一批机器根本没报过版本」这件事消失，
              而那批机器恰恰是升级里最需要盯的。
            </div>
            <!-- 首屏骨架：/upgrade 回来之前不说「尚无终端上报过环境」——那句话在请求
                 还在路上时是假的（这一块此前是本页唯一没被骨架盖住的空态）。 -->
            <SkeletonBlock v-if="!loaded" kind="table" :rows="3" :cols="3" />
            <div v-else-if="versionRows.length" class="bd-up__tbl">
              <table class="bd-table">
                <thead><tr><th>平台</th><th>客户端版本</th><th>终端数</th></tr></thead>
                <tbody>
                  <tr v-for="(v, i) in versionRows" :key="i">
                    <td>{{ v.platform || '未上报' }}</td>
                    <td :class="v.version ? 'bd-mono' : 'bd-dim'">{{ v.version || '未上报' }}</td>
                    <td>{{ v.count }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <EmptyState v-else-if="loadErr" size="sm" tone="danger" title="现场版本分布未读取"
              :desc="`后端原话：${loadErr}　这不是「没有终端上报过」——现场版本分布此刻不可判定。`" />
            <EmptyState v-else size="sm" tone="warn" title="尚无终端上报过环境（posture）" desc="装上客户端并登录一次后这里就会有数据。" />
          </div>
        </div>

        <!-- 配置备份 -->
        <div class="bd-card">
          <div class="bd-card__h">配置备份</div>
          <div class="bd-card__b">
            <div class="bd-hint">
              备份含数据库、CA 私钥、IPSec PSK、认证源凭据与审计链密钥，
              整体以口令加密（PBKDF2 + AES-256-GCM），**不提供不加密的导出**。
              口令丢失无法找回——白帝不保存它。
            </div>
            <div class="bd-bkrow">
              <a-input-password v-model="bk.pass" placeholder="备份口令（至少 12 位）" />
              <a-input v-model="bk.note" placeholder="备注（如：升级前）" />
              <button class="bd-btn" :disabled="bk.busy || bk.pass.length < 12" @click="doBackup">
                <icon-download />导出备份
              </button>
            </div>
            <div class="bd-hint bd-up__after">
              恢复由停机后的部署脚本执行（解开归档覆盖回目录再启动）：在进程运行中就地覆写
              正在使用的数据库与密钥文件，会让一半请求读到旧库、一半读到新库，且失败后没有回头路。
            </div>
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
        <!-- ★用户组定向必须随保存原样带回：SaveGrayPlan 是整条覆盖式保存，这里漏发
             就等于把经 API 配好的定向清空——接口回 200、页面看不出差别，灰度对象
             会从「测试组」变成「全体 N% 随机分桶」。
             SaveGrayPlan 是整条覆盖式保存，前端漏一个字段就是一次静默的配置丢失。 -->
        <div class="bd-fld"><label>定向用户组（无视比例）</label>
          <a-select v-model="gr.groups" multiple allow-clear placeholder="不按用户组定向">
            <a-option v-for="g in groupOpts" :key="g.id" :value="g.id">{{ g.name }}（{{ g.accounts.length }} 人）</a-option>
          </a-select>
        </div>
        <!-- ★措辞必须与算法一致：定向部分是精确的（就是这些人），比例部分是估算的
             （前端算不出服务端的 SHA-256 分桶）。写成「精确算出来的」就是在替一个
             估算值背书——保存后表格「预计影响」那一列才是后端精确数出来的权威值。 -->
        <div class="bd-notice bd-notice--plain">
          <icon-info-circle />
          <span>
            预览：定向命中 <b>{{ previewDirect }}</b> 人（精确）
            <template v-if="gr.percent > 0">
              ＋ 按 {{ gr.percent }}% 分桶<b>约</b> {{ previewCoverage - previewDirect }} 人（估算，前端算不出服务端分桶）
            </template>
            ，共 {{ bundle.total ?? '—' }} 个账号。保存后表格「预计影响」列是后端精确数出来的。
          </span>
        </div>
        <div class="bd-drawer__foot">
          <div class="bd-drawer__foot-spacer" />
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
import { api, getToken, failReason, type UpgradeBundle, type UpgradeRules, type GrayPlan, type UpgradeCheckResult } from '@/lib/api';
import PageHeader from '@/components/PageHeader.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

const PLATFORMS = [
  { key: 'macos', label: 'macOS' }, { key: 'windows', label: 'Windows' }, { key: 'linux', label: 'Linux' },
  { key: 'android', label: 'Android' }, { key: 'ios', label: 'iOS' }, { key: 'harmony', label: '鸿蒙' }
];
function platformLabel(k: string) { return PLATFORMS.find((p) => p.key === k)?.label ?? k; }

/** 连接态**三态**：undefined = 首轮请求还在路上（页头不画标签）；true = 读到了；
 *  false = 这一轮确实失败。初值 false 会让第一帧就宣告「数据未读取」——那时还没读呢。 */
const live = ref<boolean | undefined>(undefined);
/** 页顶那条 danger 通知：读取失败与写操作失败共用。 */
const err = ref('');
/** **读取**失败的后端原话（空 = 这一轮读到了）。页顶通知与下面三块子空态同源——
 *  同一次失败在一页上只许有一种说法。 */
const loadErr = ref('');
/** 首屏是否已完成第一次 load()：只决定骨架屏何时让位（成功 / 失败都算完成），不改任何数据流。 */
const loaded = ref(false);
const bundle = ref<UpgradeBundle>({ control: '', gateways: {}, rules: { allowDowngrade: false, requireComponentMatch: true, hops: [] }, gray: [], boundaries: [] });

/** 未配置发布公钥时禁用校验按钮。★只在**明确**为 false 时禁用：
 *  旧后端不下发这一格 → undefined → 照旧可点（宁可让人撞一次，也不误禁一个可用的功能）。 */
const signBlocked = computed(() => bundle.value.signKeysConfigured === false);
const rules = reactive<UpgradeRules>({ allowDowngrade: false, requireComponentMatch: true, hops: [] });

const gwList = computed(() => Object.entries(bundle.value.gateways ?? {})
  .map(([id, version]) => ({ id, version, build: bundle.value.gatewayBuilds?.[id] ?? '' }))
  .sort((a, b) => a.id.localeCompare(b.id)));

/**
 * 网关版本与控制面的关系，**三态**。
 *
 * ★`unknown` 与 `stale` 必须分开：改造前 deploy/build.sh 往语义版本那一格注的是
 * git 短哈希，解析不出来与"解析出来了但确实不等于控制面"被合并成同一种黄色标签——
 * 于是每一台按脚本装出来的网关都常年挂着「版本不一致」，一条永远为真的提示等于没有提示。
 * ★控制面自己未注入时也是 `unknown`：拿一个不可判定的基准去宣布别人"一致"是空话。
 */
function isSemver(v: string): boolean { return /^v?\d+\.\d+\.\d+(-[\w.]+)?$/.test(v.trim()); }
function gwVerState(v: string): 'unknown' | 'match' | 'stale' {
  const cur = bundle.value.control.trim();
  const got = v.trim();
  if (!got || !isSemver(got) || !cur || !isSemver(cur)) return 'unknown';
  return got.replace(/^v/, '') === cur.replace(/^v/, '') ? 'match' : 'stale';
}
/** 不可判定那一档的悬停解释——三种成因的下一步动作不同，不能只说"无法校验"。 */
function gwVerTitle(v: string): string {
  const got = v.trim();
  if (!bundle.value.control.trim()) return '控制面自身的版本未注入，无从比对';
  if (!got) return '该网关未上报语义版本（版本过旧，或二进制未注入版本身份）';
  if (!isSemver(got)) return `该网关上报的是 ${got}，不是语义版本——多半是构建时把提交哈希注进了版本那一格`;
  return '';
}

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
    loadErr.value = ''; err.value = '';
  } catch (e) {
    live.value = false;
    // 原话收口在 failReason：(e as Error).message 对 NetworkError 拿到的是浏览器的
    // "Failed to fetch"，而 failReason 会把它翻成「连不上控制面…」。
    loadErr.value = failReason(e);
    err.value = '升级配置未读取：' + failReason(e);
  } finally {
    loaded.value = true;
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
  } catch (e) { err.value = '保存规则失败：' + failReason(e); }
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
  } catch (e) { err.value = '校验失败：' + failReason(e); }
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
  } catch (e) { err.value = '保存灰度计划失败：' + failReason(e); }
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
  } catch (e) { err.value = '撤销灰度计划失败：' + failReason(e); }
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
  } catch (e) { err.value = '导出备份失败：' + failReason(e); }
  finally { bk.busy = false; }
}

onMounted(load);
</script>

<style scoped>
/* 本页独有：左栏版本卡 / 跳跃规则行 / 备份输入行。
   页头、提示条、空态、骨架、卡片头、表格、按钮、标签、表单字段都在共享件与 app.css 里。 */
.bd-up__bound { margin-bottom: var(--bd-sp-2); }
.bd-up__bound:last-of-type { margin-bottom: var(--bd-sp-4); }
.bd-up__col { display: flex; flex-direction: column; gap: var(--bd-sp-4); }
.bd-up__tbl { overflow-x: auto; margin-top: var(--bd-sp-2); border: 1px solid var(--bd-border-2); border-radius: var(--bd-radius-s); }
.bd-up__add { margin-top: var(--bd-sp-2); }
.bd-up__sig { margin-top: var(--bd-sp-2); }
.bd-up__signwarn { margin: var(--bd-sp-3) 0 0; }
.bd-up__act { margin-top: var(--bd-sp-3); }
.bd-up__chk { margin: var(--bd-sp-3) 0 0; }
.bd-up__half { margin: var(--bd-sp-2) 0 0; }
.bd-up__after { margin-top: var(--bd-sp-2); margin-bottom: 0; }
.bd-up__unk { cursor: help; }
.bd-chk__l { margin-top: 2px; }

.bd-vers { width: 300px; flex: none; align-self: flex-start; }
.bd-vers__big { font-size: var(--bd-fs-2xl); font-weight: 700; color: var(--bd-primary); line-height: 1.2; }
.bd-vers__sub { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin-top: 2px; }
/* 构建标识排在语义版本下方、比它弱一档：两者是并列事实，但只有语义版本参与判定。 */
.bd-vers__build { font-size: var(--bd-fs-xs); color: var(--bd-t3); margin-top: 6px; word-break: break-all; }
.bd-up__vnote { margin-top: var(--bd-sp-3); }
.bd-gwrow {
  display: flex; align-items: center; justify-content: space-between; gap: var(--bd-sp-2); padding: 7px 0;
  border-top: 1px solid var(--bd-border-2); font-size: var(--bd-fs-sm); flex-wrap: wrap;
}
/* 网关构建标识：整行已被 space-between 撑开，它挤在中间会把版本标签推到边上，
   所以整行换行放到第二行去（flex-basis:100%）。 */
.bd-up__gwbuild { flex: 0 0 100%; font-size: var(--bd-fs-xs); color: var(--bd-t3); word-break: break-all; }

.bd-sec2 {
  font-size: var(--bd-fs-sm); font-weight: 600; color: var(--bd-t2); margin: var(--bd-sp-4) 0 var(--bd-sp-2);
  padding-top: var(--bd-sp-3); border-top: 1px solid var(--bd-border-2);
}
.bd-hint { font-size: var(--bd-fs-sm); color: var(--bd-t3); line-height: var(--bd-lh-loose); margin-bottom: var(--bd-sp-2); }
.bd-dim { color: var(--bd-t3); }

/* 开关行的 label 嵌在一层 div 里，全局 `.bd-fld > label` 选不中它，这里补一份同规格 */
.bd-fld--row label { display: block; font-size: var(--bd-fs-md); font-weight: 500; color: var(--bd-t1); margin-bottom: 2px; line-height: var(--bd-lh); }
.bd-fld--row .bd-fld__d { margin-top: 0; }

.bd-hop { display: flex; align-items: center; gap: var(--bd-sp-2); margin-bottom: var(--bd-sp-2); font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-hop :deep(.arco-input-wrapper) { width: 130px; }
.bd-bkrow { display: flex; align-items: center; gap: var(--bd-sp-3); flex-wrap: wrap; }
.bd-bkrow :deep(.arco-input-wrapper) { flex: 1; min-width: 180px; }

/* 1280 下左栏收窄，右侧四张卡保持单列 */
@media (max-width: 1320px) {
  .bd-vers { width: 246px; }
}
</style>
