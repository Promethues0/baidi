<template>
  <div class="bd-page">
    <PageHeader title="资源策略 · 数据面授权" :live="live" off-text="数据未读取" off-color="red"
      subtitle="受 SPA 门控的后端资源（id→后端 + 角色/用户/用户组/组织细粒度授权）· control 托管，网关注册后周期热拉取生效">
      <button class="bd-btn" @click="openCreate"><icon-plus />新增资源</button>
    </PageHeader>

    <!-- 在线数据面网关 -->
    <div class="bd-card bd-gws">
      <!-- 计数同样是三态：首轮还在路上、或这一轮读失败，都写「—」。0 在这一格上是个
           确定结论（"一台网关都没注册"），而那恰恰是这两种处境下最不该说的一句话。 -->
      <div class="bd-card__h"><icon-storage /> 在线数据面网关 <em class="bd-gws__n">{{ !gwLoaded || gwErr ? '—' : gateways.length }}</em></div>
      <div class="bd-card__b">
        <!-- 首屏骨架：/gateways 回来之前不画「暂无网关注册」——请求还在路上时那句话是假的 -->
        <SkeletonBlock v-if="!gwLoaded" kind="card" :rows="2" />
        <!-- ★读取失败 ≠ 没有网关：这一格空着会被读成"数据面一台都没起"，
             而真实处境可能是网关全都好好跑着，只是控制面这一跳没答话。 -->
        <EmptyState v-else-if="gwErr" size="sm" tone="danger" title="网关列表未读取"
          :desc="`后端原话：${gwErr}　这里显示的不是「没有网关」——已注册的网关可能正在正常运行。`" />
        <EmptyState v-else-if="!gateways.length" size="sm" tone="warn" title="暂无网关注册">
          启动 <code>baidi-gateway -control http://…:8090</code> 即上线
        </EmptyState>
        <div v-else class="bd-gws__list">
          <div v-for="g in gateways" :key="g.id" class="bd-gw" :class="{ open: expanded.has(g.id) }">
            <div class="bd-gw__row" @click="toggleGw(g.id)">
              <span class="bd-gw__dot" :class="{ stale: isStale(g) }" />
              <div class="bd-gw__main">
                <div class="bd-gw__id">{{ g.id }}<span v-if="g.sessions?.length" class="bd-gw__badge">会话 {{ g.sessions.length }}</span></div>
                <div class="bd-gw__meta"><span class="bd-mono">proxy {{ g.proxy }}</span> · <span class="bd-mono">spa {{ g.spa }}</span></div>
                <div class="bd-gw__nums">已授权客户端 <b>{{ g.clients }}</b> · 活跃隧道 <b>{{ g.tunnels }}</b> · 运行 <b>{{ upt(g.uptime) }}</b> · 版本 <b>{{ g.version || '—' }}</b></div>
              </div>
              <span class="bd-gw__seen">{{ seenAgo(g.lastSeen) }}</span>
              <icon-down class="bd-gw__chev" :class="{ up: expanded.has(g.id) }" />
            </div>
            <div v-if="expanded.has(g.id)" class="bd-gw__sessions">
              <EmptyState v-if="!g.sessions?.length" size="sm" title="当前无活跃放行会话（无客户端敲门）" />
              <table v-else class="bd-table bd-table--dense bd-gw__stab">
                <thead><tr><th>用户</th><th>源 IP</th><th>角色</th><th>敲门时刻</th><th>在线时长</th></tr></thead>
                <tbody>
                  <tr v-for="s in g.sessions" :key="s.ip + s.user">
                    <td>{{ s.user || '—' }}</td>
                    <td class="bd-mono">{{ s.ip }}</td>
                    <td><span class="bd-tg" :class="roleTag(s.role)">{{ s.role || 'user' }}</span></td>
                    <td>{{ atOf(s.since) }}</td>
                    <td>{{ durOf(s.since) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 受控资源表 -->
    <div class="bd-tablecard">
      <div class="bd-toolbar">
        <!-- 计数三态：首轮还在路上写「读取中…」、读取失败写「未读取」。写「0 项」等于
             替一个还没回来（或已经失败）的请求下"库里是空的"这个结论——表体那边有骨架
             屏和空态守着，这一格此前照样在说 0。 -->
        <span class="bd-toolbar__c">受控资源 · <template v-if="!loaded">读取中…</template><template v-else-if="err">未读取</template><template v-else>{{ shown.length }} 项<template v-if="kw.trim()"> / 共 {{ resources.length }} 项</template></template></span>
        <div class="bd-toolbar__spacer" />
        <div class="bd-searchbox bd-res__search">
          <icon-search />
          <input v-model="kw" class="bd-searchbox__in" placeholder="按 id / 名称 / 后端搜索" />
        </div>
      </div>
      <!-- 首屏骨架：load() 回来之前不画表头下面的空白，也不画任何假行 -->
      <SkeletonBlock v-if="!loaded" kind="table" :rows="5" :cols="9" />
      <div v-else class="bd-tablewrap">
      <table class="bd-table">
        <thead>
          <tr><th>资源 id</th><th>名称</th><th>后端</th><th>可达性</th><th>敏感度</th><th>授权角色</th><th>授权用户</th><th>授权组织 / 用户组</th><th class="r">操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="r in shown" :key="r.id">
            <td><span class="bd-mono bd-rid">{{ r.id }}</span></td>
            <td>{{ r.name || '—' }}</td>
            <td>
              <span class="bd-mono">{{ r.backend }}</span>
              <a-tooltip v-if="r.addrRef || r.svcRef" :content="refLabel(r)">
                <span class="bd-tg bd-tg--blue bd-srctag"><icon-link />源自对象库</span>
              </a-tooltip>
            </td>
            <td>
              <!-- 网关侧真实拨测的聚合（60s 一轮随心跳上报）。★「未探测」是独立一态
                   （旧网关不上报 / 新资源未到下一轮），绝不能渲染成可达。 -->
              <a-tooltip v-if="reachOf(r.id)" :content="reachTip(r.id)">
                <span class="bd-tg bd-rtag" :class="reachTag(reachOf(r.id)!.status)">{{ reachLabel(reachOf(r.id)!.status) }}<template v-if="reachOf(r.id)!.status === 'ok'"> · {{ reachOf(r.id)!.ms }}ms</template></span>
              </a-tooltip>
              <span v-else class="bd-tg bd-tg--grey bd-rtag">未探测</span>
            </td>
            <td>
              <!-- 高敏是**可执行**的标记：终端被判降权的用户会从这一行的允许集合里被摘掉
                   （网关 denyUsers + 客户端剖面同步），不是一枚纯展示的标签。 -->
              <a-tooltip :content="sensTip(r.sensitivity)">
                <span class="bd-tg bd-rtag" :class="sensTag(r.sensitivity)">{{ sensLabel(r.sensitivity) }}</span>
              </a-tooltip>
            </td>
            <td>
              <template v-if="r.allowRoles && r.allowRoles.length">
                <span v-for="role in r.allowRoles" :key="role" class="bd-tg bd-rtag" :class="roleTag(role)">{{ role }}</span>
              </template>
              <span v-else class="bd-anyt">不限</span>
            </td>
            <td>
              <template v-if="r.allowUsers && r.allowUsers.length">
                <span v-for="u in r.allowUsers" :key="u" class="bd-tg bd-tg--purple bd-rtag">{{ u }}</span>
              </template>
              <span v-else class="bd-anyt">不限</span>
            </td>
            <td>
              <template v-if="(r.allowOrgs || []).length || (r.allowGroups || []).length">
                <span v-for="o in r.allowOrgs || []" :key="'o' + o" class="bd-tg bd-tg--green bd-rtag">
                  <icon-apps />{{ orgName(o) }}
                </span>
                <span v-for="g in r.allowGroups || []" :key="'g' + g" class="bd-tg bd-tg--gold bd-rtag">
                  <icon-user-group />{{ groupName(g) }}
                </span>
                <!-- ★把子树语义的实际影响显式写出来：授权「ACME 集团」看着只是一个标签，
                     实际覆盖的是整棵树上的所有人。数字与网关放行的那批人同源。 -->
                <a-tooltip :content="effectiveTip(r)">
                  <span class="bd-effect">生效 {{ effectiveOf(r).length }} 个账号</span>
                </a-tooltip>
              </template>
              <span v-else class="bd-anyt">未按组织/用户组授权</span>
            </td>
            <td class="r">
              <span class="bd-acts">
                <button type="button" class="bd-link" @click="openEdit(r)">编辑</button>
                <button type="button" class="bd-link bd-link--danger" @click="askDel(r)">删除</button>
              </span>
            </td>
          </tr>
          <!-- ★空态判据必须用**过滤后**的行数：用 resources.length 的话，有资源但关键字
               零命中时表体是整片空白，既没有行也没有"无匹配"那句话，看起来像页面坏了。 -->
          <tr v-if="!shown.length" class="bd-table__emptyrow">
            <td colspan="9">
              <!-- ★读取失败必须顶掉「暂无资源」：这一页是**授权面**，把一次读不到画成
                   「库里一条资源都没有」，管理员会据此以为数据面此刻什么都不放行。 -->
              <EmptyState v-if="err" size="md" tone="danger" title="资源列表未读取"
                :desc="`后端原话：${err}　这里显示的不是「没有资源」——受控资源与授权可能一切照旧，只是这一次没读到。`" />
              <EmptyState v-else-if="resources.length" size="md" :title="`没有匹配「${kw.trim()}」的资源`"
                :desc="`共 ${resources.length} 条，按 id / 名称 / 后端检索`" />
              <EmptyState v-else size="md" title="暂无资源" desc="点右上「新增资源」创建">
                <template #action><button class="bd-btn" @click="openCreate"><icon-plus />新增资源</button></template>
              </EmptyState>
            </td>
          </tr>
        </tbody>
      </table>
      </div>
    </div>

    <!-- 新增 / 编辑 资源 -->
    <a-modal v-model:visible="formOpen" :title="editing ? '编辑资源' : '新增资源'" :width="480" :footer="false" unmount-on-close>
      <div>
        <div class="bd-fld"><label>资源 id<i class="req">*</i></label>
          <a-input v-model="form.id" :disabled="editing" placeholder="如 oa（隧道前导 CONNECT &lt;id&gt; 引用）" />
        </div>
        <div class="bd-fld"><label>名称</label><a-input v-model="form.name" placeholder="如 OA 协同办公" /></div>
        <div class="bd-fld"><label>后端 host:port<i class="req">*</i></label>
          <a-input v-model="form.backend" placeholder="如 10.20.1.10:8080（仅源自此处，绝不取客户端值＝防 SSRF）" />
          <span class="bd-fld__d">backend 为权威拨号目标，选择对象仅自动回填、可手动覆盖（防 SSRF：数据面只认此值）</span>
        </div>
        <div class="bd-fld"><label>敏感度</label>
          <a-select v-model="form.sensitivity">
            <a-option value="low">low · 低敏（已评估，不敏感）</a-option>
            <a-option value="normal">normal · 普通（默认）</a-option>
            <a-option value="high">high · 高敏（终端降权时暂停访问）</a-option>
          </a-select>
          <span class="bd-fld__d">★这是**风险降权的唯一判据**：终端被判 degrade 的用户，high 资源会从网关允许集合与客户端剖面里同时摘除（普通资源与隧道不受影响），并在客户端显式告知原因。门户侧 high 资源默认走自助申请审批。</span>
        </div>
        <!-- 对象库读不到时，下面两个下拉会是**空的**——与"对象库里一个对象都没有"完全同形。
             backend 仍可手填（它才是权威拨号目标），但得说清为什么选不到东西。 -->
        <div v-if="objErr" class="bd-notice bd-notice--warn">
          <icon-exclamation-circle-fill />
          <span>对象库未读取：{{ objErr }}　下面两个引用下拉此刻是空的（不是「对象库里没有对象」），backend 可直接手填。</span>
        </div>
        <div class="bd-fld"><label>引用地址对象（可选）</label>
          <a-select v-model="form.addrRef" allow-clear placeholder="不引用（手填 backend host）" @change="onRefChange">
            <a-option v-for="a in addrs" :key="a.id" :value="a.id">{{ a.name }} · {{ a.value }}</a-option>
          </a-select>
        </div>
        <div class="bd-fld"><label>引用服务对象（可选）</label>
          <a-select v-model="form.svcRef" allow-clear placeholder="不引用（手填 backend port）" @change="onRefChange">
            <a-option v-for="s in services" :key="s.id" :value="s.id">{{ s.name }} · {{ s.proto }}/{{ s.ports }}</a-option>
          </a-select>
        </div>
        <div class="bd-fld"><label>授权角色（空＝不限）</label>
          <a-select v-model="form.allowRoles" multiple allow-clear placeholder="不限角色">
            <a-option value="admin">admin</a-option>
            <a-option value="user">user</a-option>
          </a-select>
        </div>
        <div class="bd-fld"><label>授权用户（逗号分隔，空＝不限）</label>
          <a-input v-model="usersText" placeholder="如 li.ming, zhang.wei" />
        </div>
        <div class="bd-fld"><label>授权组织（空＝不按组织授权）</label>
          <a-select v-model="form.allowOrgs" multiple allow-clear placeholder="不按组织授权">
            <a-option v-for="o in orgOpts" :key="o.id" :value="o.id">
              {{ indentOf(o) }}{{ o.name }} · {{ o.accounts.length }} 人
            </a-option>
          </a-select>
          <span class="bd-fld__d">★含子树：授权某组织即涵盖它**全部后代组织**的用户。括号里的人数已按子树算好（与网关实际放行口径同源）</span>
        </div>
        <div class="bd-fld"><label>授权用户组（空＝不按用户组授权）</label>
          <a-select v-model="form.allowGroups" multiple allow-clear placeholder="不按用户组授权">
            <a-option v-for="g in groupOpts" :key="g.id" :value="g.id">
              {{ g.name }}<template v-if="g.kind === 'role'"> · 角色派生</template> · {{ g.accounts.length }} 人
            </a-option>
          </a-select>
        </div>
        <div v-if="form.allowOrgs.length || form.allowGroups.length" class="bd-notice bd-notice--plain bd-effectbox">
          <icon-info-circle />
          <span>
            展开后生效账号 <b>{{ formEffective.length }}</b> 个
            <span v-if="formEffective.length">：{{ formEffective.slice(0, 8).join('、') }}<template v-if="formEffective.length > 8"> 等</template></span>
            <!-- 空集必须显式提示：控制面把它如实下发成「拒绝所有人」，
                 管理员若以为"选了组织就有人能进"，会一直查不到为什么连不上。 -->
            <em v-else>—— 所选组织/用户组当前没有任何成员，该资源将拒绝所有人（角色/账号维度另算）</em>
          </span>
        </div>
        <div class="bd-drawer__foot">
          <div class="bd-drawer__foot-spacer" />
          <button class="bd-btn bd-btn--ghost" @click="formOpen = false">取消</button>
          <button class="bd-btn" :disabled="saving" @click="save">{{ editing ? '保存' : '创建' }}并落库</button>
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { api, type Resource, type ResourcesResp, type SubjectOption, type GatewayReg, type GatewaysResp, type AddrObject, type ServiceObject, type ObjectBundle, failReason } from '@/lib/api';
import PageHeader from '@/components/PageHeader.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

/** 连接态**三态**：undefined = 首轮请求还在路上（页头不画标签）；true = 读到了；
 *  false = 这一轮确实失败。初值写 false 的话，进页面第一帧就宣告「数据未读取」——
 *  那是在说一件还没发生的事。 */
const live = ref<boolean | undefined>(undefined);
/** 首屏是否已完成一次加载（成功或失败都算）——只决定骨架屏何时让位，不改任何数据流。 */
const loaded = ref(false);
/** /gateways 单独记首屏：它排在 /resources 之后拉，共用 loaded 会有一小段
 *  「资源已到、网关还没拉」的窗口，那一瞬画出来的是「暂无网关注册」。 */
const gwLoaded = ref(false);
/** 两处读取失败的后端原话（唯一来源 failReason）。空串 = 这一轮读到了。
 *  ★没有这两个字段时，失败与"库里真的空着"在页面上完全同形。 */
const err = ref('');
const gwErr = ref('');
/** 对象库读取失败的后端原话：抽屉里两个引用下拉为空时用它解释"为什么选不到"。 */
const objErr = ref('');
const resources = ref<Resource[]>([]);
// 授权主体候选。accounts 由控制面**展开好**（组织那份已含全部后代组织的成员）——
// 前端只做集合并，不自己走组织树，见 SubjectOption 的说明。
const orgOpts = ref<SubjectOption[]>([]);
const groupOpts = ref<SubjectOption[]>([]);
const gateways = ref<GatewayReg[]>([]);
const addrs = ref<AddrObject[]>([]);
const services = ref<ServiceObject[]>([]);
const nowSec = ref(Math.floor(Date.now() / 1000));
const expanded = ref<Set<string>>(new Set());
let timer: ReturnType<typeof setInterval>;

/** 角色标签的语义色（admin 红 / gateway 紫 / 其余蓝），只走 .bd-tg 变体，不写十六进制。 */
function roleTag(r: string) { return r === 'admin' ? 'bd-tg--red' : r === 'gateway' ? 'bd-tg--purple' : 'bd-tg--blue'; }
function isStale(g: GatewayReg) { return nowSec.value - g.lastSeen > 60; }
function toggleGw(id: string) { const e = new Set(expanded.value); e.has(id) ? e.delete(id) : e.add(id); expanded.value = e; }
function atOf(unix: number) {
  if (!unix) return '—';
  const d = new Date(unix * 1000);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}
function durOf(unix: number) {
  if (!unix) return '—';
  const s = Math.max(0, nowSec.value - unix);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}
function upt(sec: number) {
  if (!sec || sec < 60) return `${sec || 0}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h`;
  return `${Math.floor(sec / 86400)}d`;
}
function seenAgo(ts: number) {
  const d = nowSec.value - ts;
  if (d < 5) return '刚刚';
  if (d < 60) return `${d}s 前`;
  if (d < 3600) return `${Math.floor(d / 60)} 分前`;
  return `${Math.floor(d / 3600)} 时前`;
}

/* ── 后端可达性（网关侧拨测聚合）── */
interface ReachAgg { status: 'ok' | 'partial' | 'fail' | 'unknown'; detail: string[]; ms: number }
const reach = ref<Record<string, ReachAgg>>({});
function reachOf(id: string): ReachAgg | undefined { return reach.value[id]; }
function reachLabel(st: string) {
  return st === 'ok' ? '可达' : st === 'partial' ? '部分不可达' : st === 'fail' ? '不可达' : '未探测';
}
function reachTag(st: string) {
  return st === 'ok' ? 'bd-tg--green' : st === 'partial' ? 'bd-tg--gold' : st === 'fail' ? 'bd-tg--red' : 'bd-tg--grey';
}
function reachTip(id: string) {
  const a = reach.value[id];
  return a && a.detail.length ? a.detail.join('；') : '暂无拨测详情';
}

async function load() {
  try {
    const r = await api<ResourcesResp>('/resources');
    resources.value = r.resources;
    orgOpts.value = r.orgs || []; groupOpts.value = r.groups || [];
    live.value = true; err.value = '';
  } catch (e) {
    // ★接住 e：失败的原话是这一页唯一能指导下一步的信息（403 少哪个权限、
    //   503 存储怎么了）。丢掉它就只剩一张自信的空表。
    live.value = false; err.value = failReason(e);
    resources.value = [];
  } finally { loaded.value = true; }
  try {
    const g = await api<GatewaysResp>('/gateways');
    gateways.value = g.gateways || [];
    gwErr.value = '';
  } catch (e) {
    // 网关列表失败不影响资源管理，但也绝不能画成「暂无网关注册」。
    gateways.value = []; gwErr.value = failReason(e);
  } finally { gwLoaded.value = true; }
  try {
    const o = await api<ObjectBundle>('/objects');
    addrs.value = o.addrs || []; services.value = o.services || [];
    objErr.value = '';
  } catch (e) {
    // 对象库失败不影响资源管理（backend 手填即可），但抽屉里那两个空下拉必须解释自己。
    objErr.value = failReason(e);
  }
  try {
    const rc = await api<{ items: Record<string, ReachAgg> }>('/resources/reach');
    reach.value = rc.items || {};
  } catch { reach.value = {}; /* 可达性拉不到 → 全部显示未探测（不编造可达） */ }
}

function refLabel(r: Resource) {
  const parts: string[] = [];
  if (r.addrRef) { const a = addrs.value.find((x) => x.id === r.addrRef); parts.push(`地址：${a ? `${a.name}（${a.value}）` : r.addrRef}`); }
  if (r.svcRef) { const s = services.value.find((x) => x.id === r.svcRef); parts.push(`服务：${s ? `${s.name}（${s.proto}/${s.ports}）` : r.svcRef}`); }
  return parts.join(' · ');
}

/* ── 授权主体：展示与展开 ──
   展开只做一件事：把选中主体的 accounts **求并集**。子树语义已经在服务端算进
   accounts 里了（授权 root 那条就已经含全树的人），前端再走一遍树等于把同一套
   语义实现两遍——两份实现一旦漂移，管理员看到的人数与网关实际放行的人就对不上。 */
function orgName(id: string) { return orgOpts.value.find((o) => o.id === id)?.name || id; }
function groupName(id: string) { return groupOpts.value.find((g) => g.id === id)?.name || id; }
function indentOf(o: SubjectOption) {
  const depth = Math.max(0, (o.path || '').split('/').filter(Boolean).length - 1);
  return '　'.repeat(depth);
}
function expandAccounts(orgIds: string[], groupIds: string[]) {
  const set = new Set<string>();
  for (const id of orgIds) orgOpts.value.find((o) => o.id === id)?.accounts.forEach((a) => set.add(a));
  for (const id of groupIds) groupOpts.value.find((g) => g.id === id)?.accounts.forEach((a) => set.add(a));
  return [...set].sort();
}
function effectiveOf(r: Resource) { return expandAccounts(r.allowOrgs || [], r.allowGroups || []); }

/* ── 敏感度（风险降权的判据）── */
function sensLabel(s?: string) { return s === 'high' ? '高敏' : s === 'low' ? '低敏' : '普通'; }
function sensTag(s?: string) { return s === 'high' ? 'bd-tg--red' : s === 'low' ? 'bd-tg--green' : 'bd-tg--grey'; }
function sensTip(s?: string) {
  return s === 'high'
    ? '终端被判降权（degrade）的用户会被暂停访问本资源；门户侧默认走自助申请审批'
    : '不受终端降权影响：降权只摘除高敏资源，普通/低敏资源与隧道照常';
}
function effectiveTip(r: Resource) {
  const list = effectiveOf(r);
  return list.length ? `组织/用户组展开后：${list.join('、')}` : '所选组织/用户组当前没有任何成员，该维度不会放行任何人';
}

const formOpen = ref(false);
const editing = ref(false);
const saving = ref(false);
const form = reactive<{ id: string; name: string; backend: string; sensitivity: 'low' | 'normal' | 'high'; allowRoles: string[]; allowGroups: string[]; allowOrgs: string[]; addrRef: string; svcRef: string }>(
  { id: '', name: '', backend: '', sensitivity: 'normal', allowRoles: [], allowGroups: [], allowOrgs: [], addrRef: '', svcRef: '' });
const usersText = ref('');
const formEffective = computed(() => expandAccounts(form.allowOrgs, form.allowGroups));

// 选择对象时自动回填 backend（保持可手动覆盖，backend 始终权威）
function onRefChange() {
  const addr = form.addrRef ? addrs.value.find((a) => a.id === form.addrRef) : undefined;
  const svc = form.svcRef ? services.value.find((s) => s.id === form.svcRef) : undefined;
  if (addr && svc) {
    form.backend = `${addr.value}:${svc.ports}`;
  } else if (addr) {
    const port = form.backend.includes(':') ? form.backend.slice(form.backend.lastIndexOf(':') + 1) : '';
    form.backend = port ? `${addr.value}:${port}` : addr.value;
  }
  // 清空选择仅清 ref，不动 backend（权威值）—— 由 a-select allow-clear 把 ref 置空后走此分支无操作
}

function openCreate() {
  editing.value = false;
  form.id = ''; form.name = ''; form.backend = ''; form.sensitivity = 'normal';
  form.allowRoles = []; form.allowGroups = []; form.allowOrgs = [];
  form.addrRef = ''; form.svcRef = ''; usersText.value = '';
  formOpen.value = true;
}
function openEdit(r: Resource) {
  editing.value = true;
  form.id = r.id; form.name = r.name; form.backend = r.backend;
  form.sensitivity = r.sensitivity || 'normal';
  form.allowRoles = [...(r.allowRoles || [])];
  form.allowGroups = [...(r.allowGroups || [])]; form.allowOrgs = [...(r.allowOrgs || [])];
  form.addrRef = r.addrRef || ''; form.svcRef = r.svcRef || '';
  usersText.value = (r.allowUsers || []).join(', ');
  formOpen.value = true;
}

async function save() {
  if (!form.id || !form.backend) { Message.warning('资源 id 与后端必填'); return; }
  saving.value = true;
  const allowUsers = usersText.value.split(',').map((s) => s.trim()).filter(Boolean);
  try {
    await api('/resources', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: form.id, name: form.name, backend: form.backend, sensitivity: form.sensitivity,
        allowRoles: form.allowRoles, allowUsers, allowGroups: form.allowGroups, allowOrgs: form.allowOrgs,
        addrRef: form.addrRef || undefined, svcRef: form.svcRef || undefined
      })
    });
    Message.success(`资源「${form.id}」已落库，网关下次轮询即生效`);
    formOpen.value = false;
    await load();
  } catch (e) { Message.error(`资源保存失败：${failReason(e)}`); } finally { saving.value = false; }
}

/**
 * 删除受控资源。不可撤销，且连带影响不止本行：引用它的应用会折叠成「未关联资源」
 * （与从未关联过同形，事后无从分辨），其上的 JIT 授予仍留在台账里显示失真的授权状态。
 * ★因此必须二次确认，并把后端算好的影响面回执原样呈现（Modal 而非会飘走的 toast）。
 */
function askDel(r: Resource) {
  Modal.confirm({
    title: '删除受控资源',
    content: `确认删除受控资源「${r.name || r.id}」（${r.id} → ${r.backend}）？\n` +
      '此操作不可撤销。引用它的应用与已发出的 JIT 授予**不会**被一并清理，' +
      '删除后会当面列出受影响的清单。',
    okText: '确认删除', cancelText: '取消',
    okButtonProps: { status: 'danger' },
    onOk: () => del(r)
  });
}

async function del(r: Resource) {
  try {
    const out = await api<{ ok: boolean; id: string; apps?: string[]; grants?: number; note?: string }>(
      `/resources/${r.id}`, { method: 'DELETE' });
    await load();
    // note 由后端生成——影响面是后端算的，前端再拼一份就会有两种说法。
    if (out.note) {
      Modal.info({
        title: `资源「${r.id}」已删除`,
        content: out.note,
        okText: '知道了'
      });
    } else {
      Message.success(`资源「${r.id}」已删除`);
    }
  } catch (e) { Message.error(`资源删除失败：${failReason(e)}`); }
}

/** 关键词检索。★过滤字段必须与搜索框占位文案逐字对应（id / 名称 / 后端）：
 *  搜得比说的少 = 管理员以为库里没有；多则搜出一堆解释不了的命中。 */
const kw = ref('');
const shown = computed(() => {
  const k = kw.value.trim().toLowerCase();
  if (!k) return resources.value;
  return resources.value.filter((r) => `${r.id} ${r.name ?? ''} ${r.backend ?? ''}`.toLowerCase().includes(k));
});

onMounted(() => {
  load();
  timer = setInterval(() => { nowSec.value = Math.floor(Date.now() / 1000); load(); }, 5000);
});
onUnmounted(() => clearInterval(timer));
</script>

<style scoped>
/* 本页独有：在线网关卡组、资源表里的多标签列。卡片头 / 表格 / 标签 / 表单节奏 / 空态都在共享件与 app.css 里。 */
.bd-gws { margin-bottom: var(--bd-sp-4); }
.bd-gws__n { font-style: normal; color: var(--bd-primary); font-weight: 700; }
.bd-gws__list { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: var(--bd-sp-3); }
.bd-gw { border: 1px solid var(--bd-border); border-radius: var(--bd-radius-s); background: var(--bd-fill-1); }
.bd-gw.open { grid-column: 1 / -1; }
.bd-gw__row { display: flex; align-items: center; gap: 10px; padding: 10px var(--bd-sp-3); cursor: pointer; }
.bd-gw__badge { font-size: var(--bd-fs-xs); font-weight: 600; color: var(--bd-primary); background: var(--bd-primary-1); padding: 1px 7px; border-radius: var(--bd-radius-pill); margin-left: 7px; }
.bd-gw__chev { font-size: 14px; color: var(--bd-t3); flex: none; transition: transform var(--bd-dur-base) var(--bd-ease); }
.bd-gw__chev.up { transform: rotate(180deg); }
.bd-gw__sessions { border-top: 1px dashed var(--bd-border); padding: var(--bd-sp-2) var(--bd-sp-3) var(--bd-sp-3); overflow-x: auto; }
.bd-gw__stab th:first-child, .bd-gw__stab td:first-child { padding-left: 0; }
.bd-gw__stab thead th { position: static; background: transparent; }
.bd-gw__dot { width: 8px; height: 8px; border-radius: 50%; background: var(--bd-success); box-shadow: 0 0 0 3px var(--bd-success-1); flex: none; }
.bd-gw__dot.stale { background: var(--bd-warning); box-shadow: 0 0 0 3px var(--bd-warning-1); }
.bd-gw__main { flex: 1; min-width: 0; }
.bd-gw__id { font-weight: 600; color: var(--bd-t1); }
.bd-gw__meta { font-size: var(--bd-fs-sm); color: var(--bd-t3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bd-gw__nums { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin-top: 3px; }
.bd-gw__nums b { color: var(--bd-primary); font-weight: 600; }
.bd-gw__seen { font-size: var(--bd-fs-sm); color: var(--bd-t3); flex: none; }

.bd-res__search { width: 240px; }
.bd-tablewrap { overflow-x: auto; }
.bd-rid { color: var(--bd-primary); font-weight: 600; }
/* 多标签列：标签带图标、彼此留间距 */
.bd-rtag { display: inline-flex; align-items: center; gap: 3px; margin-right: 6px; }
.bd-effect { display: inline-block; font-size: var(--bd-fs-sm); color: var(--bd-t3); border-bottom: 1px dashed var(--bd-border); cursor: default; }
.bd-effectbox b { color: var(--bd-primary); }
.bd-effectbox em { font-style: normal; color: var(--bd-warning); }
.bd-anyt { font-size: var(--bd-fs-sm); color: var(--bd-t4); }
.bd-srctag { display: inline-flex; align-items: center; gap: 3px; margin-left: var(--bd-sp-2); vertical-align: middle; cursor: default; }

@media (max-width: 1320px) {
  .bd-res__search { width: 200px; }
}
</style>
