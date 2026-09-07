<template>
  <div class="bd-page">
    <!-- ★副标题此前把三类对象一并说成"可被策略/资源/IPSec 复用"，
         而**时间对象一个消费方都没有**（后端 objects_usage.go 里写得很直白：
         `case "time": n = 0 // 时间对象暂无落库消费者`）。地址与服务是真被
         resources.addr_ref / svc_ref 与 ipsec_sites 引用的，时间对象不是。 -->
    <PageHeader title="对象库" subtitle="地址 / 服务对象可被资源与 IPSec 站点复用；时间对象目前只是台账登记（见下）" :live="live">
      <button class="bd-btn" :disabled="live !== true" :title="writeHint" @click="openCreate"><icon-plus />新增对象</button>
    </PageHeader>

    <!-- ★读取失败时，后端那句原话必须在页面上有地方看。改造前唯一的线索是页头右上
         那枚橙色「降级演示」标签与「新增对象」的置灰 tooltip——看得出"出事了"，
         看不到"是什么事"。这一页的三类演示对象与真实对象结构一致，误当成现场就会
         以为地址/服务对象已经建好，而资源那边引用不到。 -->
    <div v-if="live === false" class="bd-notice bd-notice--warn">
      <icon-exclamation-circle-fill />
      <div class="bd-notice__body">
        对象库未读取（后端原话：<b>{{ loadErr }}</b>），下面三个页签里的地址 / 服务 / 时间对象都是
        <b>内置演示数据</b>，<b>不代表现场情况</b>——写入入口已按此置灰，「被引用」一栏也不是真实反查结果。
      </div>
    </div>

    <!-- Tab 切换：真 button（可 Tab、可回车） -->
    <div class="bd-tabs" role="tablist">
      <button type="button" class="bd-tab" role="tab" :aria-selected="tab === 'addr'" @click="tab = 'addr'">地址对象 <em>{{ bundle.addrs.length }}</em></button>
      <button type="button" class="bd-tab" role="tab" :aria-selected="tab === 'service'" @click="tab = 'service'">服务对象 <em>{{ bundle.services.length }}</em></button>
      <button type="button" class="bd-tab" role="tab" :aria-selected="tab === 'time'" @click="tab = 'time'">时间对象 <em>{{ bundle.times.length }}</em></button>
    </div>

    <!-- ============ 地址对象 ============ -->
    <div v-show="tab === 'addr'" class="bd-tablecard">
      <div class="bd-toolbar">
        <span class="bd-toolbar__c">地址对象 · {{ shownAddrs.length }} 项</span>
        <div class="bd-toolbar__spacer" />
        <div class="bd-searchbox bd-obj__search">
          <icon-search />
          <input v-model="kw" class="bd-searchbox__in" placeholder="按名称 / 值搜索" />
        </div>
      </div>
      <SkeletonBlock v-if="!loaded" kind="table" :rows="4" :cols="6" />
      <table v-else class="bd-table">
        <thead>
          <tr><th>名称</th><th>类型</th><th>值</th><th>描述</th><th>被引用</th><th class="r">操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="o in shownAddrs" :key="o.id">
            <td><b class="bd-obj__name">{{ o.name }}</b></td>
            <td><span class="bd-tg" :class="addrKindTag(o.kind)">{{ addrKindText(o.kind) }}</span></td>
            <td><span class="bd-mono">{{ o.value }}</span></td>
            <td>{{ o.desc || '—' }}</td>
            <td>
              <a-popover v-if="refsOf(o.id).length" position="top">
                <span class="bd-tg bd-tg--gold bd-ref">被引用 {{ refsOf(o.id).length }}</span>
                <template #content>
                  <div class="bd-reflist">
                    <div v-for="(r, i) in refsOf(o.id)" :key="i" class="bd-reflist__i">{{ refLabel(r) }}</div>
                  </div>
                </template>
              </a-popover>
              <span v-else class="bd-ref-none">未被引用</span>
            </td>
            <td class="r">
              <span class="bd-acts">
                <button type="button" class="bd-link" @click="openEdit('addr', o)">编辑</button>
                <a-popconfirm content="确定删除该对象？" type="warning" @ok="del('addr', o.id)">
                  <button type="button" class="bd-link bd-link--danger">删除</button>
                </a-popconfirm>
              </span>
            </td>
          </tr>
          <tr v-if="!shownAddrs.length" class="bd-table__emptyrow">
            <td colspan="6">
              <EmptyState v-if="kw.trim()" size="md" title="无匹配对象" :desc="`按「${kw.trim()}」搜索名称、值与描述均无命中`" />
              <EmptyState v-else size="md" title="暂无对象" desc="点右上「新增对象」创建">
                <template #action><button class="bd-btn" :disabled="live !== true" :title="writeHint" @click="openCreate"><icon-plus />新增对象</button></template>
              </EmptyState>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- ============ 服务对象 ============ -->
    <div v-show="tab === 'service'" class="bd-tablecard">
      <div class="bd-toolbar">
        <span class="bd-toolbar__c">服务对象 · {{ shownServices.length }} 项</span>
        <div class="bd-toolbar__spacer" />
        <div class="bd-searchbox bd-obj__search">
          <icon-search />
          <input v-model="kw" class="bd-searchbox__in" placeholder="按名称 / 端口搜索" />
        </div>
      </div>
      <SkeletonBlock v-if="!loaded" kind="table" :rows="4" :cols="6" />
      <table v-else class="bd-table">
        <thead>
          <tr><th>名称</th><th>协议</th><th>端口</th><th>描述</th><th>被引用</th><th class="r">操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="o in shownServices" :key="o.id">
            <td><b class="bd-obj__name">{{ o.name }}</b></td>
            <td><span class="bd-tg" :class="protoTag(o.proto)">{{ o.proto.toUpperCase() }}</span></td>
            <td><span class="bd-mono">{{ o.ports || '—' }}</span></td>
            <td>{{ o.desc || '—' }}</td>
            <td>
              <a-popover v-if="refsOf(o.id).length" position="top">
                <span class="bd-tg bd-tg--gold bd-ref">被引用 {{ refsOf(o.id).length }}</span>
                <template #content>
                  <div class="bd-reflist">
                    <div v-for="(r, i) in refsOf(o.id)" :key="i" class="bd-reflist__i">{{ refLabel(r) }}</div>
                  </div>
                </template>
              </a-popover>
              <span v-else class="bd-ref-none">未被引用</span>
            </td>
            <td class="r">
              <span class="bd-acts">
                <button type="button" class="bd-link" @click="openEdit('service', o)">编辑</button>
                <a-popconfirm content="确定删除该对象？" type="warning" @ok="del('service', o.id)">
                  <button type="button" class="bd-link bd-link--danger">删除</button>
                </a-popconfirm>
              </span>
            </td>
          </tr>
          <tr v-if="!shownServices.length" class="bd-table__emptyrow">
            <td colspan="6">
              <EmptyState v-if="kw.trim()" size="md" title="无匹配对象" :desc="`按「${kw.trim()}」搜索名称、端口与描述均无命中`" />
              <EmptyState v-else size="md" title="暂无对象" desc="点右上「新增对象」创建">
                <template #action><button class="bd-btn" :disabled="live !== true" :title="writeHint" @click="openCreate"><icon-plus />新增对象</button></template>
              </EmptyState>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- ============ 时间对象 ============ -->
    <!-- ★时间对象**没有任何执行方**：后端引用复核对 time 恒返回 0（"暂无落库消费者"），
         它的「被引用」列结构性恒为"未被引用"，删除守卫恒放行。管理员照着旧副标题建一条
         「周一~周五 09:00-18:00」，以为能拿去卡访问时段，实际上只是一行谁也不读的记录。
         按时段限制访问的**真**执行方在认证策略的「非工作时间」规则里（offHours），
         那是另一套配置，名字还对不上。这条告警不能删——它是这一屏唯一说真话的地方。 -->
    <div v-show="tab === 'time'" class="bd-notice bd-notice--warn">
      <icon-exclamation-circle-fill />
      <div class="bd-notice__body">
        <b>时间对象目前没有执行方，仅作台账登记。</b>
        这里建的时间段不会被任何策略、资源或 IPSec 站点读取（后端的引用复核对时间对象恒返回
        「未被引用」），因此它<b>不会限制任何人的访问时段</b>。
        要按时段收紧访问，请用「认证源接入 → 认证策略」里的<b>非工作时间</b>规则：
        那条规则由服务器时间 + 策略里配置的工作日/时段判定，真的接在登录链路上。
      </div>
    </div>
    <div v-show="tab === 'time'" class="bd-tablecard">
      <div class="bd-toolbar">
        <span class="bd-toolbar__c">时间对象 · {{ shownTimes.length }} 项</span>
        <div class="bd-toolbar__spacer" />
        <div class="bd-searchbox bd-obj__search">
          <icon-search />
          <input v-model="kw" class="bd-searchbox__in" placeholder="按名称 / 规格搜索" />
        </div>
      </div>
      <SkeletonBlock v-if="!loaded" kind="table" :rows="4" :cols="6" />
      <table v-else class="bd-table">
        <thead>
          <tr><th>名称</th><th>类型</th><th>时间规格</th><th>描述</th><th>被引用</th><th class="r">操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="o in shownTimes" :key="o.id">
            <td><b class="bd-obj__name">{{ o.name }}</b></td>
            <td><span class="bd-tg" :class="timeKindTag(o.kind)">{{ timeKindText(o.kind) }}</span></td>
            <td><span class="bd-mono">{{ o.spec }}</span></td>
            <td>{{ o.desc || '—' }}</td>
            <td>
              <a-popover v-if="refsOf(o.id).length" position="top">
                <span class="bd-tg bd-tg--gold bd-ref">被引用 {{ refsOf(o.id).length }}</span>
                <template #content>
                  <div class="bd-reflist">
                    <div v-for="(r, i) in refsOf(o.id)" :key="i" class="bd-reflist__i">{{ refLabel(r) }}</div>
                  </div>
                </template>
              </a-popover>
              <span v-else class="bd-ref-none">未被引用</span>
            </td>
            <td class="r">
              <span class="bd-acts">
                <button type="button" class="bd-link" @click="openEdit('time', o)">编辑</button>
                <a-popconfirm content="确定删除该对象？" type="warning" @ok="del('time', o.id)">
                  <button type="button" class="bd-link bd-link--danger">删除</button>
                </a-popconfirm>
              </span>
            </td>
          </tr>
          <tr v-if="!shownTimes.length" class="bd-table__emptyrow">
            <td colspan="6">
              <EmptyState v-if="kw.trim()" size="md" title="无匹配对象" :desc="`按「${kw.trim()}」搜索名称、规格与描述均无命中`" />
              <EmptyState v-else size="md" title="暂无对象" desc="点右上「新增对象」创建">
                <template #action><button class="bd-btn" :disabled="live !== true" :title="writeHint" @click="openCreate"><icon-plus />新增对象</button></template>
              </EmptyState>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 新增 / 编辑 对象 -->
    <a-modal v-model:visible="formOpen" :title="modalTitle" :width="480" :footer="false" unmount-on-close>
      <div class="bd-fld"><label>名称<span class="req">*</span></label>
        <a-input v-model="form.name" placeholder="如 OA 服务器" />
      </div>

      <!-- 地址对象字段 -->
      <template v-if="form.kind === 'addr'">
        <div class="bd-fld"><label>类型</label>
          <a-select v-model="form.addrKind">
            <a-option value="ip">主机（ip）</a-option>
            <a-option value="cidr">网段（cidr）</a-option>
            <a-option value="range">范围（range）</a-option>
            <a-option value="domain">域名（domain）</a-option>
          </a-select>
        </div>
        <div class="bd-fld"><label>值<span class="req">*</span></label>
          <a-input v-model="form.value" :placeholder="addrValuePlaceholder" />
        </div>
      </template>

      <!-- 服务对象字段 -->
      <template v-else-if="form.kind === 'service'">
        <div class="bd-fld"><label>协议</label>
          <a-select v-model="form.proto">
            <a-option value="tcp">TCP</a-option>
            <a-option value="udp">UDP</a-option>
            <a-option value="icmp">ICMP</a-option>
            <a-option value="any">ANY</a-option>
          </a-select>
        </div>
        <div class="bd-fld"><label>端口</label>
          <a-input v-model="form.ports" placeholder="如 443 或 8000-8100 或 1521,3306" />
        </div>
      </template>

      <!-- 时间对象字段 -->
      <template v-else>
        <div class="bd-fld"><label>类型</label>
          <a-select v-model="form.timeKind">
            <a-option value="periodic">周期</a-option>
            <a-option value="absolute">绝对</a-option>
          </a-select>
        </div>
        <div class="bd-fld"><label>时间规格<span class="req">*</span></label>
          <a-input v-model="form.spec" :placeholder="timeSpecPlaceholder" />
        </div>
      </template>

      <div class="bd-fld"><label>描述</label>
        <a-input v-model="form.desc" placeholder="可选说明" />
      </div>

      <div class="bd-drawer__foot">
        <div class="bd-drawer__foot-spacer" />
        <button class="bd-btn bd-btn--ghost" @click="formOpen = false">取消</button>
        <button class="bd-btn" :disabled="saving" @click="save">{{ editing ? '保存' : '创建' }}并落库</button>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { api, type AddrObject, type ServiceObject, type TimeObject, type ObjectBundle, type ObjectRef, type ObjectUsageResp, failReason, failStatus } from '@/lib/api';
import PageHeader from '@/components/PageHeader.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

type Kind = 'addr' | 'service' | 'time';

/* ── 内置 mock（结构同后端 ObjectBundle）── */
const MOCK: ObjectBundle = {
  addrs: [
    { id: 'a1', name: 'OA 服务器', kind: 'ip', value: '10.20.1.10', desc: '协同办公主机' },
    { id: 'a2', name: '核心业务网段', kind: 'cidr', value: '10.20.0.0/16', desc: '核心区全部子网' },
    { id: 'a3', name: '研发地址池', kind: 'range', value: '10.20.1.1-10.20.1.99', desc: '研发部办公终端' },
    { id: 'a4', name: '企业门户域名', kind: 'domain', value: '*.corp.com', desc: '泛域名匹配' }
  ],
  services: [
    { id: 's1', name: 'HTTPS', proto: 'tcp', ports: '443', desc: 'Web 安全访问' },
    { id: 's2', name: '业务端口段', proto: 'tcp', ports: '8000-8100', desc: '微服务网关' },
    { id: 's3', name: '数据库', proto: 'tcp', ports: '1521,3306', desc: 'Oracle / MySQL' },
    { id: 's4', name: 'DNS', proto: 'udp', ports: '53', desc: '域名解析' },
    { id: 's5', name: 'Ping 探测', proto: 'icmp', ports: '', desc: '连通性检测' }
  ],
  times: [
    { id: 't1', name: '工作日上班', kind: 'periodic', spec: '周一~周五 09:00-18:00', desc: '常规办公时段' },
    { id: 't2', name: '夜间维护窗', kind: 'periodic', spec: '每日 02:00-04:00', desc: '运维变更窗口' },
    { id: 't3', name: '项目特批期', kind: 'absolute', spec: '2026-01-01 ~ 2026-12-31', desc: '限期授权区间' }
  ]
};

const tab = ref<Kind>('addr');
/** 连接态三态：undefined = 首轮请求还在路上（判不出来，PageHeader 此时不画标签）/
 *  true 已连 / false 降级演示。★初值写 false 的话，首屏那一瞬页头就挂上一枚橙色
 *  「降级演示」——把"还没探过"说成"确定离线"，而那一刻什么都还没发生。 */
const live = ref<boolean | undefined>(undefined);
/** 读取失败时后端那句原话（failReason 收口，前端不编造归因）。 */
const loadErr = ref('');
/** 写入入口的禁用说明。三态各说各的：判不出来时说「正在读取」，
 *  ★不许直接说「降级演示模式下不可写入」——首轮请求还没回来，那件事还没发生。 */
const writeHint = computed(() =>
  live.value === true ? '' : live.value === false ? '降级演示模式下不可写入' : '正在读取对象库，稍候可写入');
/** 首屏是否已完成第一次 load（成功或降级都算）：只决定骨架屏何时让位，不改任何数据流。 */
const loaded = ref(false);
const bundle = ref<ObjectBundle>({ addrs: [], services: [], times: [] });

/* ── 「被引用」反查（objectId -> 引用方列表）── */
const usage = ref<Record<string, ObjectRef[]>>({});
const refKindText: Record<ObjectRef['kind'], string> = { resource: '资源', ipsec: 'IPSec组网' };
function refsOf(id: string): ObjectRef[] { return usage.value[id] || []; }
function refLabel(r: ObjectRef) { return `${refKindText[r.kind]} · ${r.name}`; }

/* ── 关键词检索（按当前页签的相关字段过滤）── */
const kw = ref('');
function matches(...fields: string[]) {
  const k = kw.value.trim().toLowerCase();
  if (!k) return true;
  return fields.some((f) => (f || '').toLowerCase().includes(k));
}
const shownAddrs = computed(() => bundle.value.addrs.filter((o) => matches(o.name, o.value, o.desc)));
const shownServices = computed(() => bundle.value.services.filter((o) => matches(o.name, o.ports, o.desc)));
const shownTimes = computed(() => bundle.value.times.filter((o) => matches(o.name, o.spec, o.desc)));

/* 标签色只走 .bd-tg--* 语义变体（不写十六进制）：颜色只用来把同一列里的几种类型区分开，不承载安全语义。 */
function addrKindTag(k: AddrObject['kind']) { return k === 'ip' ? 'bd-tg--blue' : k === 'cidr' ? 'bd-tg--green' : k === 'range' ? 'bd-tg--gold' : 'bd-tg--purple'; }
function addrKindText(k: AddrObject['kind']) { return k === 'ip' ? '主机' : k === 'cidr' ? '网段' : k === 'range' ? '范围' : '域名'; }
function protoTag(p: ServiceObject['proto']) { return p === 'tcp' ? 'bd-tg--blue' : p === 'udp' ? 'bd-tg--green' : p === 'icmp' ? 'bd-tg--gold' : 'bd-tg--grey'; }
function timeKindTag(k: TimeObject['kind']) { return k === 'periodic' ? 'bd-tg--blue' : 'bd-tg--purple'; }
function timeKindText(k: TimeObject['kind']) { return k === 'periodic' ? '周期' : '绝对'; }

async function load() {
  try {
    const b = await api<ObjectBundle>('/objects');
    bundle.value = { addrs: b.addrs || [], services: b.services || [], times: b.times || [] };
    live.value = true;
    loadErr.value = '';
    try {
      const u = await api<ObjectUsageResp>('/objects/usage');
      usage.value = u.usage || {};
    } catch { usage.value = {}; }
  } catch (e) { bundle.value = MOCK; usage.value = {}; live.value = false; loadErr.value = failReason(e); }
  finally { loaded.value = true; }
}

/* ── 表单（单 reactive 容纳全字段）── */
const formOpen = ref(false);
const editing = ref(false);
const saving = ref(false);
const form = reactive<{
  kind: Kind; id: string; name: string; desc: string;
  addrKind: AddrObject['kind']; value: string;
  proto: ServiceObject['proto']; ports: string;
  timeKind: TimeObject['kind']; spec: string;
}>({
  kind: 'addr', id: '', name: '', desc: '',
  addrKind: 'ip', value: '',
  proto: 'tcp', ports: '',
  timeKind: 'periodic', spec: ''
});

const kindLabel: Record<Kind, string> = { addr: '地址对象', service: '服务对象', time: '时间对象' };
const modalTitle = computed(() => (editing.value ? '编辑' : '新增') + kindLabel[form.kind]);
const addrValuePlaceholder = computed(() =>
  form.addrKind === 'ip' ? '10.20.1.10'
    : form.addrKind === 'cidr' ? '10.20.0.0/16'
      : form.addrKind === 'range' ? '10.20.1.1-10.20.1.99'
        : '*.corp.com'
);
const timeSpecPlaceholder = computed(() =>
  form.timeKind === 'periodic' ? '周一~周五 09:00-18:00' : '2026-01-01 ~ 2026-12-31'
);

function resetForm(k: Kind) {
  form.kind = k; form.id = ''; form.name = ''; form.desc = '';
  form.addrKind = 'ip'; form.value = '';
  form.proto = 'tcp'; form.ports = '';
  form.timeKind = 'periodic'; form.spec = '';
}

function openCreate() {
  editing.value = false;
  resetForm(tab.value);
  formOpen.value = true;
}

function openEdit(k: Kind, o: AddrObject | ServiceObject | TimeObject) {
  editing.value = true;
  resetForm(k);
  form.id = o.id; form.name = o.name; form.desc = o.desc;
  if (k === 'addr') { const a = o as AddrObject; form.addrKind = a.kind; form.value = a.value; }
  else if (k === 'service') { const s = o as ServiceObject; form.proto = s.proto; form.ports = s.ports; }
  else { const t = o as TimeObject; form.timeKind = t.kind; form.spec = t.spec; }
  formOpen.value = true;
}

async function save() {
  // ★归因不自拟：原文案写死「未连接后端」，而对象库读不到也可能是 403（这一页归系统管理员一权）。
  //   loadErr 是 failReason(e) 存下的后端原话，有就带上。
  if (live.value !== true) { Message.warning(`${writeHint.value}${loadErr.value ? `：${loadErr.value}` : ''}`); return; }
  if (!form.name) { Message.warning('名称必填'); return; }
  if (form.kind === 'addr' && !form.value) { Message.warning('地址对象的值必填'); return; }
  if (form.kind === 'time' && !form.spec) { Message.warning('时间对象的规格必填'); return; }

  let body: AddrObject | ServiceObject | TimeObject;
  if (form.kind === 'addr') {
    body = { id: form.id, name: form.name, kind: form.addrKind, value: form.value, desc: form.desc };
  } else if (form.kind === 'service') {
    body = { id: form.id, name: form.name, proto: form.proto, ports: form.ports, desc: form.desc };
  } else {
    body = { id: form.id, name: form.name, kind: form.timeKind, spec: form.spec, desc: form.desc };
  }

  saving.value = true;
  try {
    await api(`/objects/${form.kind}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    Message.success(`${kindLabel[form.kind]}「${form.name}」已落库`);
    formOpen.value = false;
    await load();
  } catch (e) { Message.error(`对象保存失败：${failReason(e)}`); } finally { saving.value = false; }
}

async function del(k: Kind, id: string) {
  // ★归因不自拟：原文案写死「未连接后端」，而对象库读不到也可能是 403（这一页归系统管理员一权）。
  //   loadErr 是 failReason(e) 存下的后端原话，有就带上。
  if (live.value !== true) { Message.warning(`${writeHint.value}${loadErr.value ? `：${loadErr.value}` : ''}`); return; }
  /* 主动防护：已被引用则拦截，不下发 DELETE */
  const refs = refsOf(id);
  if (refs.length) {
    Modal.warning({
      title: '对象被引用，无法删除',
      content: `被 ${refs.length} 处引用，无法删除：${refs.map(refLabel).join('、')}；请先在引用方解除引用`
    });
    return;
  }
  try {
    await api(`/objects/${k}/${id}`, { method: 'DELETE' });
    Message.success(`${kindLabel[k]}已删除`);
    await load();
  } catch (e) {
    /* 兜底：后端 409 表示在前端那道引用检查之后、DELETE 之前又出现了新引用。
       ★判状态码必须用 failStatus：`e.message.includes('409')` 是死分支——api() 抛的
         message 是后端中文原文，永远不含状态码数字。于是真正的 409 一直落进 else，
         被说成「删除失败，请检查权限或后端连接」：管理员去查网络、去重登，
         而后端说的是"它还被谁引用着"，那才是唯一能指导下一步动作的信息。
       弹窗标题保留（它决定用哪种呈现方式），正文一律用后端原话——后端点得出
       具体引用方，前端这份手抄的泛泛描述点不出来。 */
    if (failStatus(e) === 409) {
      Modal.warning({ title: '对象被引用，无法删除', content: failReason(e) });
    } else {
      Message.error(`删除失败：${failReason(e)}`);
    }
  }
}

onMounted(load);
</script>

<style scoped>
/* 本页独有的布局。页头 / 表格卡 / 搜索框 / 标签 / 操作列 / 空态 / 提示条 / 表单字段 / 弹窗底栏都在共享件与 app.css 里。 */


.bd-obj__search { width: 240px; }
.bd-obj__name { color: var(--bd-t1); font-weight: 500; }

/* 「被引用」指示 */
.bd-ref { cursor: pointer; }
.bd-ref-none { font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-reflist { min-width: 140px; max-width: 280px; }
.bd-reflist__i { font-size: var(--bd-fs-sm); color: var(--bd-t1); padding: 3px 0; line-height: var(--bd-lh); }
.bd-reflist__i + .bd-reflist__i { border-top: 1px solid var(--bd-border-2); }

@media (max-width: 1320px) {
  .bd-obj__search { width: 200px; }
}
</style>
