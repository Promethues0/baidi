<template>
  <div class="bd-page">
    <!-- 本页没有任何演示回落：/apps 拉不到时左栏分类与右侧列表都是空的、空态走 danger 分支，
         离线标签按 DESIGN.md §2 口径用「数据未读取」（红）而不是默认的「降级演示」（橙）——
         否则页头说"在画演示数据"、正文说"未读取"，同一屏两句相反。 -->
    <PageHeader title="应用管理" subtitle="把内网业务注册为受控资源 · 隧道应用与 WEB 应用 · 以资源为最小授权单元" :live="live" off-text="数据未读取" off-color="red">
      <button class="bd-btn" @click="openWizard"><icon-plus />新增应用</button>
    </PageHeader>

    <div class="bd-two">
      <!-- 分类 -->
      <div class="bd-card bd-cats">
        <div class="bd-cats__h">
          <span>应用分类</span>
          <!-- ★真 button 而非 <span @click>：裸 span 不进 Tab 焦点序列、读屏也报不出它可操作，
               而这是分类维护的唯一入口。 -->
          <button type="button" class="bd-link bd-cats__mgr" @click="openCatMgr"><icon-settings />管理分类</button>
        </div>
        <button v-for="c in categories" :key="c.key" class="bd-cat" :class="{ on: cat === c.key }" @click="cat = c.key">
          <icon-folder class="bd-cat__ic" />
          <span class="bd-cat__t">{{ c.label }}</span>
          <span class="bd-cat__n">{{ c.count }}</span>
        </button>
      </div>

      <!-- 应用表 -->
      <div class="bd-tablecard bd-two__main">
        <div class="bd-toolbar">
          <span class="bd-toolbar__c">共 {{ filtered.length }} 个应用</span>
          <div class="bd-toolbar__spacer" />
          <div class="bd-searchbox bd-apps__search">
            <icon-search />
            <input v-model="kw" class="bd-searchbox__in" placeholder="按名称 / 地址搜索" />
          </div>
        </div>
        <!-- 首屏骨架：load() 回来之前不画表头下面的空白，也不画任何假行 -->
        <SkeletonBlock v-if="!loaded" kind="table" :rows="5" :cols="6" />
        <table v-else class="bd-table">
          <thead>
            <tr>
              <th>应用名称</th><th>发布模式</th><th>关联资源</th><th>已授权</th><th>状态</th><th class="r">操作</th>
            </tr>
          </thead>
          <tbody>
            <!-- 空态分三种处境：搜索无命中 / 该分类下没有 / 库里一个应用都没有——
                 三者下一步动作不同（清关键词 / 换分类 / 发布第一个），一句"暂无数据"分不开。 -->
            <tr v-if="!filtered.length" class="bd-table__emptyrow">
              <td colspan="6">
                <EmptyState v-if="loadErr" size="md" tone="danger" title="应用列表未读取" :desc="`${loadErr}——这里显示的不是「没有应用」`" />
                <EmptyState v-else-if="kw.trim()" size="md" title="没有匹配的应用" :desc="`当前分类内按「${kw.trim()}」搜索名称与地址均无命中`" />
                <EmptyState v-else-if="cat !== 'all'" size="md" title="该分类下还没有应用" desc="发布向导里选择这个分类即可归入；分类只影响归类与筛选，不参与授权判定" />
                <EmptyState v-else size="md" title="尚未发布任何应用" desc="把内网业务注册为受控资源后，门户与客户端剖面才会出现它的磁贴">
                  <template #action><button class="bd-btn" @click="openWizard"><icon-plus />新增应用</button></template>
                </EmptyState>
              </td>
            </tr>
            <tr v-for="a in filtered" :key="a.id">
              <td>
                <div class="bd-cellname">
                  <span class="bd-appic" :style="{ background: modeMeta(a.mode).bg }">
                    <component :is="modeMeta(a.mode).icon" :style="{ color: modeMeta(a.mode).color }" />
                  </span>
                  <span><b>{{ a.name }}</b><i class="bd-mono">{{ a.addr }}</i></span>
                </div>
              </td>
              <td><span class="bd-tg" :style="tagStyle(modeMeta(a.mode).color)">{{ modeMeta(a.mode).label }}</span></td>
              <!-- 关联资源：它决定访问授权与网关能不能拨出去。★这一列不许换成恒值字段
                   （如"所属区域"），管理员没有那个输入项，列出来就是一列假事实。 -->
              <td>
                <span v-if="a.resourceId" class="bd-mono">{{ a.resourceId }}</span>
                <span v-else class="bd-auth--none" title="未关联受控资源：隧道与七层两条路都不通">未关联</span>
              </td>
              <td><span :class="{ 'bd-auth--none': a.authScope === 'unlinked' }" :title="authTitle(a)">{{ authText(a) }}</span></td>
              <td>
                <span class="bd-st"><span class="d" :style="{ background: a.status === 'running' ? 'var(--bd-success)' : 'var(--bd-t4)' }" />{{ a.status === 'running' ? '运行中' : '已停用' }}</span>
              </td>
              <!-- ★「编辑」必须走编辑抽屉（PUT /apps/{id}），不能复用发布向导：
                   向导发的是 POST，点一次就多出一条同名应用。 -->
              <td class="r">
                <span class="bd-acts">
                  <button type="button" class="bd-link" @click="openEdit(a)">编辑</button>
                  <button type="button" class="bd-link bd-link--danger" @click="confirmDelete(a)">下架</button>
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ============ 分类维护（增删改 + 排序）============ -->
    <a-modal v-model:visible="mgr.open" :width="680" title="管理应用分类" :footer="false" unmount-on-close>
      <div class="bd-catmgr">
        <div class="bd-notice bd-notice--plain">
          <icon-info-circle /><span>分类只影响管理台上的归类与筛选，不参与任何访问授权判定——授权在「安全防护 → 资源策略」按资源配置。</span>
        </div>
        <div v-if="mgr.err" class="bd-notice bd-notice--danger"><icon-exclamation-circle-fill /><span>{{ mgr.err }}</span></div>

        <table class="bd-table bd-catmgr__t">
          <thead>
            <tr><th style="width: 76px">排序</th><th>名称</th><th style="width: 150px">分类 key</th><th style="width: 80px">应用数</th><th class="r" style="width: 64px">操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="(c, i) in mgr.list" :key="c.key">
              <td>
                <button type="button" class="bd-link bd-catmgr__mv" :disabled="mgr.busy || i === 0"
                  :title="`把「${c.label}」上移一位`" :aria-label="`把分类「${c.label}」上移一位`"
                  @click="move(i, -1)"><icon-arrow-up /></button>
                <button type="button" class="bd-link bd-catmgr__mv" :disabled="mgr.busy || i === mgr.list.length - 1"
                  :title="`把「${c.label}」下移一位`" :aria-label="`把分类「${c.label}」下移一位`"
                  @click="move(i, 1)"><icon-arrow-down /></button>
              </td>
              <td>
                <a-input v-model="c.label" :max-length="64" size="small" :disabled="mgr.busy"
                  @blur="rename(c)" @press-enter="rename(c)" />
              </td>
              <td>
                <i class="bd-mono">{{ c.key }}</i>
                <span v-if="c.builtin" class="bd-tg bd-catmgr__bi">内置</span>
              </td>
              <td>{{ c.count }}</td>
              <td class="r">
                <span v-if="c.builtin" class="bd-catmgr__no" title="内置分类不可删除（key 被既有应用引用），可改名与调整排序">—</span>
                <button v-else type="button" class="bd-link bd-link--danger" :disabled="mgr.busy"
                  :title="`删除分类「${c.label}」`" :aria-label="`删除分类「${c.label}」`"
                  @click="askRemove(c)"><icon-delete /></button>
              </td>
            </tr>
            <tr v-if="!mgr.list.length && mgr.loaded">
              <td colspan="5" class="bd-catmgr__empty">分类字典为空——新增一个后才能发布应用。</td>
            </tr>
          </tbody>
        </table>

        <div class="bd-catmgr__add">
          <a-input v-model="mgr.newKey" placeholder="key（小写字母/数字/连字符）" class="bd-mono" :max-length="32" :disabled="mgr.busy" />
          <a-input v-model="mgr.newLabel" placeholder="显示名称" :max-length="64" :disabled="mgr.busy" @press-enter="create" />
          <button class="bd-btn" :disabled="mgr.busy || !mgr.newKey || !mgr.newLabel" @click="create"><icon-plus />新增</button>
        </div>
        <div class="bd-catmgr__foot">key 落库后不可更改（既有应用按 key 引用分类）；名称随时可改，应用页与发布向导立即跟随。</div>
      </div>
    </a-modal>

    <!-- ============ 发布向导（P1 分步 + 分支）============ -->
    <a-drawer v-model:visible="wz.open" :width="720" title="应用发布向导" :footer="false" unmount-on-close>
      <div class="bd-wz">
        <a-steps :current="wz.step + 1" small class="bd-wz__steps">
          <a-step v-for="(t, i) in STEPS" :key="i" :title="t" />
        </a-steps>

        <!-- Step 1: 发布模式（分支点） -->
        <div v-if="wz.step === 0" class="bd-wz__body">
          <div class="bd-wz__hint">选择业务的发布模式 —— 不同模式决定后续的配置项与可用安全能力。</div>
          <button v-for="m in MODES" :key="m.key" class="bd-mode-card" :class="{ on: wz.mode === m.key }" @click="wz.mode = m.key">
            <span class="bd-mode-card__ic" :style="{ background: m.bg }"><component :is="m.icon" :style="{ color: m.color }" /></span>
            <span class="bd-mode-card__txt"><b>{{ m.label }}</b><i>{{ m.desc }}</i></span>
            <icon-check-circle-fill v-if="wz.mode === m.key" class="bd-mode-card__chk" />
          </button>
        </div>

        <!-- Step 2: 基础配置（按模式分支） -->
        <div v-else-if="wz.step === 1" class="bd-wz__body">
          <div class="bd-fld"><label>应用名称</label><a-input v-model="wz.f.name" placeholder="例如：OA 协同办公" /></div>
          <div class="bd-fld"><label>所属分类</label>
            <a-select v-model="wz.f.cat" placeholder="选择分类">
              <a-option v-for="c in pickableCats" :key="c.key" :value="c.key">{{ c.label }}</a-option>
            </a-select>
            <span v-if="!pickableCats.length" class="bd-fld__d">分类字典为空，请先用左侧「管理分类」新增一个——后端会拒收字典外的分类。</span>
          </div>
          <div v-if="wz.mode === 'tunnel'" class="bd-fld"><label>内网地址</label><a-input v-model="wz.f.addr" placeholder="10.30.5.8:22" class="bd-mono" /></div>
          <div v-else-if="wz.mode === 'web'" class="bd-fld"><label>内网 URL</label><a-input v-model="wz.f.addr" placeholder="http://10.20.1.10:8080" class="bd-mono" /></div>
          <div v-else class="bd-fld">
            <label>链接地址</label>
            <a-input v-model="wz.f.addr" placeholder="https://www.cnki.net" class="bd-mono" />
            <span class="bd-fld__d">填完整 URL 门户里可以直接点开；填泛域名（<code>*.cnki.net</code>）则只作为说明文字展示。</span>
          </div>
          <!-- ★这条告警是这张模式卡保留下来的前提：不说的话，它在向导里与两条真链路
               平级摆着，管理员会合理推断「已发布并受控」。
               ★只在 global 模式下画（与下方编辑抽屉那条 `v-if="ed.f.mode === 'global'"` 同口径）：
               它此前是上面 tunnel / web / 直连书签三分支之外的兄弟节点，没带任何条件，
               于是发布一条隧道应用或 Web 应用时也顶着一句「直连书签不受访问控制」——
               对着一条真受控链路说它不受控，管理员要么怀疑自己选错了模式、要么学会忽略
               这条告警，到真选直连书签时它就再也起不到作用了。 -->
          <div v-if="wz.mode === 'global'" class="bd-notice bd-notice--warn">
            <icon-exclamation-circle-fill />
            <div class="bd-notice__body">
              <b>直连书签不受访问控制。</b>
              它不经网关、不进隧道路由、不做鉴权——门户与客户端对它一律标为可访问，
              <b>凡是能登录的人都看得到、点得开</b>。资源策略页的 ACL、JIT 审批、降权、
              强制下线对它都不生效。要做真正的受控发布，请选上面两条模式之一。
              （泛域名代理需要证书签发与正文改写，本版本不做，见 docs/ARCHITECTURE.md 第七节。）
            </div>
          </div>
          <div class="bd-fld"><label>关联受控资源</label>
            <a-select v-model="wz.f.resourceId" placeholder="选择资源（决定客户端路由与 JIT 申请）" allow-clear>
              <a-option v-for="r in resources" :key="r.id" :value="r.id">{{ r.name }}（{{ r.backend }}）</a-option>
            </a-select>
            <span v-if="!wz.f.resourceId" class="bd-fld__d">不关联资源的应用无法经隧道访问、也无法被 JIT 申请——客户端剖面会对此显式告警。</span>
          </div>

          <!-- 七层 Web 代理（B/S 免客户端）专属：只有 web 模式且已关联资源时才有执行方 -->
          <template v-if="wz.mode === 'web' && wz.f.resourceId">
            <div class="bd-fld">
              <label>内网后端协议</label>
              <a-select v-model="wz.f.webScheme">
                <a-option value="http">HTTP</a-option>
                <a-option value="https">HTTPS（内网应用自带 TLS）</a-option>
              </a-select>
              <span class="bd-fld__d">
                七层代理拨后端时用哪个协议。选错的症状是浏览器上一个空白页而两侧日志都正常，
                所以这里显式选，不按端口猜。留空保存则按端口推默认（443 / 8443 → HTTPS）。
              </span>
            </div>
            <div class="bd-fld">
              <label>对外访问域名（可选）</label>
              <a-input v-model="wz.f.webEntry" placeholder="https://oa.corp.example" class="bd-mono" allow-clear />
              <span class="bd-fld__d">
                浏览器该跳到哪个入口。留空 = 依次用整站入口 BAIDI_WEB_ENTRY_BASE / 网关页登记的对外接入地址 / 网关自报落点。只填到主机[:端口]，不要带路径；
                实际路由按 <code>/app/&lt;资源id&gt;/</code> 路径前缀分流，与域名无关。
              </span>
            </div>
            <div class="bd-notice bd-notice--warn">
              <icon-exclamation-circle-fill />
              <div class="bd-notice__body">
                <b>七层入口不受 SPA 服务隐身保护。</b>
                浏览器做不了 SPA 敲门，所以该端口必须对浏览器可达——它是一个真实的入站攻击面，
                与地址转换（NAT）绕过隐身是同性质的取舍。请确认已由前置 HTTPS 暴露，
                并只对确需 B/S 免客户端的业务开启；C/S 隧道那条路不受影响。
              </div>
            </div>
          </template>
        </div>

        <!-- Step 3: 确认发布 -->
        <div v-else class="bd-wz__body">
          <div class="bd-wz__summary">
            <b>发布摘要</b>
            <div>{{ modeMeta(wz.mode || 'web').label }} · {{ wz.f.name || '未命名' }} · {{ wz.f.addr || '—' }} · {{ wz.f.resourceId ? `关联资源 ${wz.f.resourceId}` : '未关联资源' }}</div>
            <div v-if="wz.mode === 'web' && wz.f.resourceId" class="bd-wz__summary-sub">
              七层代理：后端 {{ wz.f.webScheme.toUpperCase() }} · 入口 {{ wz.f.webEntry || '默认推导（整站入口 / 登记的接入地址 / 网关自报落点）' }}
              （这两项会写进资源「{{ wz.f.resourceId }}」）
            </div>
          </div>
          <div class="bd-notice bd-notice--plain"><icon-info-circle /><span>访问授权在「安全防护 → 资源策略」按资源配置（角色/用户白名单），时限授予走「JIT 即时访问」审批流。</span></div>
        </div>

        <div class="bd-drawer__foot">
          <button v-if="wz.step > 0" class="bd-btn bd-btn--ghost" @click="wz.step--">上一步</button>
          <div class="bd-drawer__foot-spacer" />
          <button class="bd-btn bd-btn--ghost" @click="wz.open = false">取消</button>
          <button class="bd-btn" :disabled="!canNext" @click="next">
            {{ wz.step < 2 ? '下一步' : '发布应用' }}
          </button>
        </div>
      </div>
    </a-drawer>

    <!-- ============ 编辑已发布应用（PUT /apps/{id}）============
         ★与发布向导刻意分开：提交动词不同（POST vs PUT），复用向导还会让「取消」后
         再点「新增」带着上一条应用的值。 -->
    <a-drawer v-model:visible="ed.open" :width="520" title="编辑应用" unmount-on-close :footer="false">
      <div class="bd-wz__body">
        <div class="bd-fld"><label>应用名称</label><a-input v-model="ed.f.name" /></div>
        <div class="bd-fld"><label>发布模式</label>
          <a-select v-model="ed.f.mode">
            <a-option v-for="m in MODES" :key="m.key" :value="m.key">{{ m.label }}</a-option>
          </a-select>
          <span class="bd-fld__d">{{ modeMeta(ed.f.mode).desc }}</span>
        </div>
        <div v-if="ed.f.mode === 'global'" class="bd-notice bd-notice--warn">
          <icon-exclamation-circle-fill />
          <div class="bd-notice__body"><b>直连书签不受访问控制。</b>不经网关、不进隧道路由、不做鉴权，凡是能登录的人都看得到、点得开。</div>
        </div>
        <div class="bd-fld"><label>{{ ed.f.mode === 'global' ? '链接地址' : '内网地址' }}</label>
          <a-input v-model="ed.f.addr" class="bd-mono" />
        </div>
        <div class="bd-fld"><label>所属分类</label>
          <a-select v-model="ed.f.category">
            <a-option v-for="c in pickableCats" :key="c.key" :value="c.key">{{ c.label }}</a-option>
          </a-select>
        </div>
        <div class="bd-fld"><label>关联受控资源</label>
          <a-select v-model="ed.f.resourceId" placeholder="未关联" allow-clear>
            <a-option v-for="r in resources" :key="r.id" :value="r.id">{{ r.name }}（{{ r.backend }}）</a-option>
          </a-select>
          <span v-if="!ed.f.resourceId && ed.f.mode !== 'global'" class="bd-fld__d">
            不关联资源的应用无法经隧道访问、也无法被 JIT 申请——客户端剖面会对此显式告警。
          </span>
        </div>
        <div class="bd-fld"><label>状态</label>
          <a-select v-model="ed.f.status">
            <a-option value="running">运行中（进门户与客户端剖面）</a-option>
            <a-option value="stopped">已停用（不下发给任何终端）</a-option>
          </a-select>
        </div>
        <div class="bd-drawer__foot">
          <div class="bd-drawer__foot-spacer" />
          <button class="bd-btn bd-btn--ghost" @click="ed.open = false">取消</button>
          <button class="bd-btn" :disabled="!canSaveEdit || ed.busy" @click="saveEdit">保存</button>
        </div>
      </div>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, watch, onMounted } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { api, type AppBundle, type App, type AppCategory, type AppCategoryDef, type AppCategoriesResp, type Resource, type ResourcesResp, failReason } from '@/lib/api';
import PageHeader from '@/components/PageHeader.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

/* 连接态三态：undefined = 首轮读取还没回来，页头不画连接标签。
 * ★不能写 ref(false)：那会让红色「数据未读取」在第一次请求回来之前就画出来——
 *   它宣告的是一件**还没发生**的事，慢网 / 大表下能持续好几秒，与「真的读失败了」完全同形。
 * 落定点：load() 的 try 尾（true）与 catch（false）；同一个 load() 里第二次 /resources 读取不参与判定（拉不到只是选不出资源）。两条路径都必须落定，漏一条标签就永远不画（比误报更难发现）。 */
const live = ref<boolean | undefined>(undefined);
/** 首屏是否已完成一次加载（成功或失败都算）——只决定骨架屏何时让位，不改任何数据流。 */
const loaded = ref(false);
/** 应用列表读取失败时的后端原话：空态据此说「没读到」而不是「没有应用」——两者下一步动作相反。 */
const loadErr = ref('');
const categories = ref<AppCategory[]>([{ key: 'all', label: '全部应用', count: 0 }]);
const apps = ref<App[]>([]);
const cat = ref('all');
/** 关键词。过滤字段与占位文案逐字对应（名称 / 地址），且与分类筛选是「与」关系
 *  ——搜索只在当前分类内收窄，不会静默把管理员选中的分类换掉。 */
const kw = ref('');
const filtered = computed(() => {
  let list = cat.value === 'all' ? apps.value : apps.value.filter((a) => a.category === cat.value);
  const k = kw.value.trim().toLowerCase();
  if (!k) return list;
  return list.filter((a) => `${a.name} ${a.addr ?? ''}`.toLowerCase().includes(k));
});

const MODES = [
  { key: 'tunnel', label: '隧道应用（C/S）', desc: 'SSH / RDP / 数据库等 C/S 业务，走 SSL 访问隧道', icon: 'IconCode', bg: '#F5E8FF', color: '#722ED1' },
  { key: 'web', label: 'WEB 应用（B/S）', desc: '浏览器直达的 B/S 业务，免客户端，走 HTTPS 代理', icon: 'IconCommon', bg: '#F2F7FF', color: '#165DFF' },
  // ★这一项的名字必须直说它不经网关：它**不受任何访问控制**，剖面与门户一律给
  // Accessible: true，对全体登录用户可见。取个与上面两条真链路平级的名字会被读成「已受控」。
  { key: 'global', label: '直连书签（不经隧道）', desc: '门户里的一个链接：不经网关、不受访问控制、对全体登录用户可见', icon: 'IconPublic', bg: '#E8FFEA', color: '#00B42A' }
] as const;
function modeMeta(m: string) { return MODES.find((x) => x.key === m) ?? MODES[1]; }

/* 「已授权」列：授权面由后端按关联资源的真实 ACL 现算，三种性质要分开呈现——
   都渲染成一个数字的话，「没关联资源所以谁也进不去」会长得跟「授权了 0 个人」一样。 */
function authText(a: App) {
  if (a.authScope === 'unlinked') return '未关联资源';
  if (a.authScope === 'unlimited') return `全部用户（${a.authedUsers}）`;
  return `${a.authedUsers} 用户`;
}
function authTitle(a: App) {
  if (a.authScope === 'unlinked') return '该应用未关联受控资源，无法经隧道访问——在发布向导里关联一个资源';
  if (a.authScope === 'unlimited') return '关联资源未设置任何访问控制，对全部登录用户开放';
  return '按资源 ACL（用户 / 角色 / 组织 / 用户组展开）统计，不含有时限的 JIT 临时授予';
}
function tagStyle(color: string) { return { color, background: color + '14' }; }

// ★向导只收集会真正提交后端的字段：收集了却静默丢弃的控件比没有更糟。
// DLP / 水印 / 浏览器管控 / 负载均衡等暂无执行方，故不提供入口，别在这里加回来。
const STEPS = ['发布模式', '基础配置', '确认发布'];
const wz = reactive({
  open: false, step: 0, mode: '' as '' | 'tunnel' | 'web' | 'global',
  // webScheme/webEntry 只在 web 模式下有执行方，落的是**资源**而不是应用
  // （七层代理按资源路由与鉴权，同一资源被多个应用引用时不该有两份配置）。
  f: { name: '', cat: '', addr: '', resourceId: '', webScheme: 'http' as 'http' | 'https', webEntry: '' }
});
/** 发布向导可选的分类 = 筛选条去掉合成项 all（它不是真实分类）。 */
const pickableCats = computed(() => categories.value.filter((c) => c.key !== 'all'));
function openWizard() {
  wz.open = true; wz.step = 0; wz.mode = '';
  wz.f.name = ''; wz.f.addr = ''; wz.f.resourceId = '';
  wz.f.webScheme = 'http'; wz.f.webEntry = '';
  // ★默认选第一个真实分类，不许写死某个 key：分类可增删，那个 key 一旦被删掉，
  // 每次发布都会 400，而错误来自一个界面上根本没显示的默认值。
  wz.f.cat = pickableCats.value[0]?.key ?? '';
}
const canNext = computed(() => {
  if (wz.step === 0) return !!wz.mode;
  // 分类是必选：后端会拒收字典外的 key，前端放行只会把校验推迟到最后一步。
  if (wz.step === 1) return !!wz.f.name && !!wz.f.addr && !!wz.f.cat;
  return true;
});
const publishing = ref(false);
const resources = ref<Resource[]>([]);
// 选中资源时回填它已有的七层配置：不回填的话，发布第二个引用同一资源的应用
// 会用表单默认值把管理员配好的入口静默覆盖掉。
watch(() => wz.f.resourceId, (id) => {
  const r = resources.value.find((x) => x.id === id);
  wz.f.webScheme = r?.webScheme ?? 'http';
  wz.f.webEntry = r?.webEntry ?? '';
});
async function load() {
  try {
    const b = await api<AppBundle>('/apps');
    categories.value = b.categories; apps.value = b.apps; live.value = true;
    // 成功必须清掉上一次的失败原话：load() 会被发布/编辑/下架/分类增删反复调用，首屏那次失败
    // 若留着，之后搜索无命中时空态会优先命中 danger 分支，显示「未读取 + 早已过期的错误」，
    // 而页头同时是绿色「已连」——两处互相矛盾（Users/Audit/Devices 三页同款写法）。
    loadErr.value = '';
    // 当前筛选的分类可能刚被删掉（自己删的，或另一个管理员删的）：不重置的话左栏一项都不高亮、
    // 右侧列表恒空，看起来像"这个分类下没有应用"，而实际是筛选卡在了一个不存在的 key 上。
    if (cat.value !== 'all' && !b.categories.some((c) => c.key === cat.value)) cat.value = 'all';
  } catch (e) { live.value = false; loadErr.value = failReason(e); }
  finally { loaded.value = true; }
  try {
    const r = await api<ResourcesResp>('/resources');
    resources.value = r.resources ?? [];
  } catch { resources.value = []; }
}
async function next() {
  if (!canNext.value) return;
  if (wz.step < 2) { wz.step++; return; }
  publishing.value = true;
  try {
    // web 模式的两项七层配置落在**资源**上，须先保存资源再发布应用：
    // 顺序反了的话，资源保存失败时应用已经建出来了，而它的入口配置是空的——
    // 页面上看起来发布成功，浏览器点开却拿不到正确的后端协议。
    const res = resources.value.find((x) => x.id === wz.f.resourceId);
    if (wz.mode === 'web' && res && (res.webScheme !== wz.f.webScheme || (res.webEntry ?? '') !== wz.f.webEntry)) {
      await api('/resources', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        // 整条资源回写（后端是 upsert）：只发改动字段会把 ACL 等未提交的列清空。
        body: JSON.stringify({ ...res, webScheme: wz.f.webScheme, webEntry: wz.f.webEntry.trim() })
      });
    }
    await api('/apps', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: wz.f.name, addr: wz.f.addr, mode: wz.mode, category: wz.f.cat, resourceId: wz.f.resourceId })
    });
    wz.open = false;
    Message.success(`应用「${wz.f.name}」已发布并落库`);
    cat.value = 'all';
    await load();
  } catch (e) {
    Message.error(`发布失败：${failReason(e)}`);
  } finally {
    publishing.value = false;
  }
}

/* ── 编辑 / 下架已发布应用（FR-APP-01）── */
const ed = reactive({
  open: false, busy: false,
  f: { id: '', name: '', addr: '', mode: 'web' as App['mode'], category: '', resourceId: '', status: 'running' as App['status'] }
});
const canSaveEdit = computed(() => !!ed.f.name.trim() && !!ed.f.addr.trim() && !!ed.f.category);
function openEdit(a: App) {
  ed.f = {
    id: a.id, name: a.name, addr: a.addr, mode: a.mode,
    category: a.category, resourceId: a.resourceId ?? '', status: a.status
  };
  ed.open = true;
}
async function saveEdit() {
  if (!canSaveEdit.value) return;
  ed.busy = true;
  try {
    await api(`/apps/${encodeURIComponent(ed.f.id)}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: ed.f.name.trim(), addr: ed.f.addr.trim(), mode: ed.f.mode,
        category: ed.f.category, resourceId: ed.f.resourceId, status: ed.f.status
      })
    });
    ed.open = false;
    Message.success(`应用「${ed.f.name}」已更新`);
    await load();
  } catch (e) {
    Message.error(`保存失败：${failReason(e)}`);
  } finally { ed.busy = false; }
}
function confirmDelete(a: App) {
  Modal.warning({
    title: `下架应用「${a.name}」？`,
    // ★必须说清"资源不删"：不说的话，管理员会以为下架顺手收回了访问权，
    // 而资源侧的 ACL 与 JIT 授予原样有效（隧道照样能连）。
    content: a.resourceId
      ? `磁贴会从门户与客户端剖面里移除。关联的受控资源 ${a.resourceId} 不会被删除——它的访问控制仍按资源策略生效，如需一并收回请去「安全防护 → 资源策略」。`
      : '磁贴会从门户与客户端剖面里移除。该应用未关联受控资源。',
    okText: '确认下架', cancelText: '取消', hideCancel: false,
    onOk: async () => {
      try {
        await api(`/apps/${encodeURIComponent(a.id)}`, { method: 'DELETE' });
        Message.success(`应用「${a.name}」已下架`);
        await load();
      } catch (e) {
        Message.error(`下架失败：${failReason(e)}`);
      }
    }
  });
}

/* ── 分类维护（增删改 + 排序）：分类字典的唯一维护入口。
   每次操作立刻落库，不做本地暂存 + 批量保存——批量提交要维护差异集，任何一条失败都会让
   页面状态与库里分家，而那种分家在这一屏上看不出来。 */
const mgr = reactive({
  open: false, loaded: false, busy: false, err: '',
  list: [] as AppCategoryDef[],
  newKey: '', newLabel: ''
});

async function loadCats() {
  try {
    mgr.list = (await api<AppCategoriesResp>('/app-categories')).categories ?? [];
  } catch (e) {
    mgr.list = [];
    mgr.err = `读取分类字典失败：${failReason(e)}`;
  } finally {
    mgr.loaded = true;
  }
}
function openCatMgr() { mgr.open = true; mgr.loaded = false; mgr.err = ''; mgr.newKey = ''; mgr.newLabel = ''; void loadCats(); }

/** 一次分类写操作：统一置忙、统一刷新字典与应用页（计数与筛选条都要跟着变）。 */
async function catOp(run: () => Promise<unknown>, okMsg: string, failMsg: string): Promise<boolean> {
  if (mgr.busy) return false;
  mgr.busy = true;
  try {
    await run();
    mgr.err = '';
    await loadCats();
    await load();
    Message.success(okMsg);
    return true;
  } catch (e) {
    // 后端守卫的原话就是下一步该做什么（"分类下仍有 N 个应用…"），原样呈现。
    const msg = `${failMsg}：${failReason(e)}`;
    Message.error(msg);
    // ★先刷新再写 err：loadCats 成功时不动 err，但它是异步的，
    // 顺序反过来的话弹窗里的红条会被这次刷新的时序吃掉，只剩一条转瞬即逝的 toast。
    await loadCats(); // 回到库里的真实状态，别把本地改了一半的输入留在表格里
    mgr.err = msg;
    return false;
  } finally {
    mgr.busy = false;
  }
}

function create() {
  const key = mgr.newKey.trim(), label = mgr.newLabel.trim();
  if (!key || !label) return;
  void catOp(
    () => api('/app-categories', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key, label }) }),
    `分类「${label}」已新增`, '新增分类失败'
  ).then((ok) => { if (ok) { mgr.newKey = ''; mgr.newLabel = ''; } });
}

function putCat(c: AppCategoryDef, label: string, sort: number) {
  return api(`/app-categories/${encodeURIComponent(c.key)}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label, sort })
  });
}

function rename(c: AppCategoryDef) {
  const label = c.label.trim();
  const was = prevLabel.get(c.key) ?? '';
  // 名字清空或没改动都不提交：前者后端本就会拒（400），后者每次失焦都会落一条
  // 「改名 X→X」的审计——审计只该记真的发生过的事。两种情况都把输入框还原成库里那份。
  if (!label || label === was) { c.label = was; return; }
  void catOp(() => putCat(c, label, c.sort), `分类已改名为「${label}」`, '改名失败');
}

/** 上移/下移：与相邻行交换 sort 后各提交一次（sort 是库里的真实列，不是前端排布）。 */
function move(i: number, dir: -1 | 1) {
  const j = i + dir;
  if (mgr.busy || j < 0 || j >= mgr.list.length) return;
  const a = mgr.list[i], b = mgr.list[j];
  // 两行 sort 相同时（历史数据可能如此）交换不会改变顺序，先拉开一档再交换。
  const sa = a.sort, sb = a.sort === b.sort ? b.sort + dir : b.sort;
  void catOp(async () => { await putCat(a, a.label, sb); await putCat(b, b.label, sa); }, '排序已更新', '调整排序失败');
}

/** 删除前先确认：这个图标常驻可见（不依赖 hover），点中即删的代价是一次不可撤销的字典变更。 */
function askRemove(c: AppCategoryDef) {
  Modal.confirm({
    title: '删除分类',
    content: `确认删除分类「${c.label}」（${c.key}）？分类下若仍有应用，后端会拒绝删除并说明还剩几个。`,
    okText: '删除', cancelText: '取消', okButtonProps: { status: 'danger' },
    onOk: () => remove(c)
  });
}

// 删掉的正好是当前筛选项时，筛选由 load() 里那道守卫统一拨回「全部应用」——
// 只写在这里的话，另一个管理员删掉同一个分类时本页仍会卡在空列表上。
async function remove(c: AppCategoryDef) {
  await catOp(
    () => api(`/app-categories/${encodeURIComponent(c.key)}`, { method: 'DELETE' }),
    `分类「${c.label}」已删除`, '删除失败'
  );
}

/** prevLabel 记住每行改动前的名称：用于「没变就不提交」与失败回滚显示。 */
const prevLabel = new Map<string, string>();
watch(() => mgr.list, (l) => { prevLabel.clear(); l.forEach((c) => prevLabel.set(c.key, c.label)); }, { deep: false });

onMounted(load);
</script>

<style scoped>
/* 本页独有的布局。按钮 / 链接 / 表格 / 提示条 / 表单节奏 / 抽屉底栏都在 app.css，这里不再抄。 */
.bd-cats { width: 210px; flex: none; padding: var(--bd-sp-3); }
.bd-cats__h { font-size: var(--bd-fs-sm); font-weight: 600; color: var(--bd-t3); padding: var(--bd-sp-1) var(--bd-sp-2) 10px; display: flex; align-items: center; justify-content: space-between; gap: var(--bd-sp-2); }
.bd-cats__mgr { display: inline-flex; align-items: center; gap: 3px; font-weight: 500; font-size: var(--bd-fs-sm); }
.bd-cat {
  width: 100%; display: flex; align-items: center; gap: 9px; height: 36px; padding: 0 var(--bd-sp-3); border: none; background: transparent;
  border-radius: var(--bd-radius-s); cursor: pointer; font-size: var(--bd-fs-md); color: var(--bd-t2);
  transition: background var(--bd-dur-fast) var(--bd-ease), color var(--bd-dur-fast) var(--bd-ease);
}
.bd-cat:hover { background: var(--bd-fill-2); }
.bd-cat.on { background: var(--bd-primary-1); color: var(--bd-primary); font-weight: 500; }
.bd-cat__ic { font-size: 15px; }
.bd-cat__t { flex: 1; text-align: left; }
.bd-cat__n { font-size: var(--bd-fs-xs); color: var(--bd-t3); font-variant-numeric: tabular-nums; }
.bd-cat.on .bd-cat__n { color: var(--bd-primary); }
.bd-apps__search { width: 240px; }
/* 未关联资源不是「授权了 0 人」而是「根本进不去」，用弱化色与虚线下划线区分开。 */
.bd-auth--none { color: var(--bd-t3); border-bottom: 1px dashed var(--bd-border); cursor: help; }
.bd-appic { width: 34px; height: 34px; border-radius: var(--bd-radius-s); display: inline-flex; align-items: center; justify-content: center; font-size: 17px; flex: none; }

/* 分类维护弹窗 */
.bd-catmgr__t td { vertical-align: middle; }
.bd-catmgr__mv { display: inline-flex; margin-right: var(--bd-sp-2); font-size: var(--bd-fs-md); }
.bd-catmgr__bi { margin-left: var(--bd-sp-2); color: var(--bd-t3); background: var(--bd-fill-2); }
.bd-catmgr__no { color: var(--bd-t4); }
.bd-catmgr__empty { color: var(--bd-t3); text-align: center; padding: var(--bd-sp-5) 0; }
.bd-catmgr__add { display: flex; gap: 10px; align-items: center; margin-top: var(--bd-sp-4); }
.bd-catmgr__add :deep(.arco-input-wrapper) { flex: 1; }
.bd-catmgr__foot { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin-top: 10px; line-height: var(--bd-lh-loose); }

/* 向导 */
.bd-wz { display: flex; flex-direction: column; height: 100%; }
.bd-wz__steps { padding: 6px 0 var(--bd-sp-5); }
.bd-wz__body { flex: 1; overflow-y: auto; padding-right: 2px; }
.bd-wz__hint { font-size: var(--bd-fs-md); color: var(--bd-t3); margin-bottom: var(--bd-sp-4); }
.bd-wz__summary-sub { margin-top: 6px; font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-mode-card {
  width: 100%; display: flex; align-items: center; gap: 14px; padding: var(--bd-sp-4); margin-bottom: var(--bd-sp-3);
  border: 1.5px solid var(--bd-border); border-radius: var(--bd-radius); background: var(--bd-bg-1); cursor: pointer; text-align: left;
  transition: border-color var(--bd-dur-fast) var(--bd-ease), background var(--bd-dur-fast) var(--bd-ease), box-shadow var(--bd-dur-base) var(--bd-ease);
}
.bd-mode-card:hover { border-color: var(--bd-primary-b); box-shadow: var(--bd-shadow-1); }
.bd-mode-card.on { border-color: var(--bd-primary); background: var(--bd-primary-1); }
.bd-mode-card__ic { width: 44px; height: 44px; border-radius: var(--bd-radius); display: flex; align-items: center; justify-content: center; font-size: 22px; flex: none; }
.bd-mode-card__txt b { font-size: var(--bd-fs-base); display: block; color: var(--bd-t1); }
.bd-mode-card__txt i { font-style: normal; font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-mode-card__chk { margin-left: auto; color: var(--bd-primary); font-size: 20px; }

.bd-sec2 { font-size: var(--bd-fs-md); font-weight: 600; margin: var(--bd-sp-5) 0 var(--bd-sp-3); }
.bd-chk-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: var(--bd-sp-3); }
.bd-wz__sub { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin: -6px 0 var(--bd-sp-4); }
.bd-wm { background: var(--bd-fill-2); padding: 2px 8px; border-radius: var(--bd-radius-xs); color: var(--bd-t2); }
.bd-wz__summary { margin-top: var(--bd-sp-2); margin-bottom: var(--bd-sp-4); background: var(--bd-primary-1); border: 1px solid var(--bd-primary-b); border-radius: var(--bd-radius-s); padding: var(--bd-sp-3) 14px; font-size: var(--bd-fs-md); }
.bd-wz__summary b { display: block; margin-bottom: 6px; }
.bd-wz__summary div { color: var(--bd-t2); font-size: var(--bd-fs-sm); }

/* 1280 视口：左栏收窄，搜索框跟随 */
@media (max-width: 1320px) {
  .bd-cats { width: 184px; }
  .bd-apps__search { width: 200px; }
}
</style>
