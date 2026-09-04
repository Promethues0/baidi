<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">对象库</div>
        <!-- ★副标题此前把三类对象一并说成"可被策略/资源/IPSec 复用"，
             而**时间对象一个消费方都没有**（后端 objects_usage.go 里写得很直白：
             `case "time": n = 0 // 时间对象暂无落库消费者`）。地址与服务是真被
             resources.addr_ref / svc_ref 与 ipsec_sites 引用的，时间对象不是。 -->
        <div class="bd-page__sub">地址 / 服务对象可被资源与 IPSec 站点复用；时间对象目前只是台账登记（见下）</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <button class="bd-btn" :disabled="!live" :title="live ? '' : '降级演示模式下不可写入'" @click="openCreate"><icon-plus />新增对象</button>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'addr' }" @click="tab = 'addr'">地址对象 ({{ bundle.addrs.length }})</span>
      <span class="bd-tab" :class="{ on: tab === 'service' }" @click="tab = 'service'">服务对象 ({{ bundle.services.length }})</span>
      <span class="bd-tab" :class="{ on: tab === 'time' }" @click="tab = 'time'">时间对象 ({{ bundle.times.length }})</span>
    </div>

    <!-- ============ 地址对象 ============ -->
    <div v-show="tab === 'addr'" class="bd-tablecard">
      <div class="bd-toolbar">
        <span class="bd-toolbar__c">地址对象 · {{ shownAddrs.length }} 项</span>
        <div style="flex: 1" />
        <div class="bd-searchbox" style="width: 240px">
          <icon-search />
          <input v-model="kw" class="bd-searchbox__in" placeholder="按名称 / 值搜索" />
        </div>
      </div>
      <table class="bd-table">
        <thead>
          <tr><th>名称</th><th>类型</th><th>值</th><th>描述</th><th>被引用</th><th class="r">操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="o in shownAddrs" :key="o.id">
            <td><b style="color: var(--bd-t1); font-weight: 500">{{ o.name }}</b></td>
            <td><span class="bd-tg" :style="tagStyle(addrKindColor(o.kind))">{{ addrKindText(o.kind) }}</span></td>
            <td><span class="bd-mono">{{ o.value }}</span></td>
            <td>{{ o.desc || '—' }}</td>
            <td>
              <a-popover v-if="refsOf(o.id).length" position="top">
                <span class="bd-tg bd-ref" :style="tagStyle('#FF7D00')">被引用 {{ refsOf(o.id).length }}</span>
                <template #content>
                  <div class="bd-reflist">
                    <div v-for="(r, i) in refsOf(o.id)" :key="i" class="bd-reflist__i">{{ refLabel(r) }}</div>
                  </div>
                </template>
              </a-popover>
              <span v-else class="bd-ref-none">未被引用</span>
            </td>
            <td class="r">
              <span class="bd-link" @click="openEdit('addr', o)">编辑</span>
              <a-popconfirm content="确定删除该对象？" type="warning" @ok="del('addr', o.id)">
                <span class="bd-link bd-link--danger" style="margin-left: 12px">删除</span>
              </a-popconfirm>
            </td>
          </tr>
          <tr v-if="!shownAddrs.length"><td colspan="6" class="bd-empty">{{ kw ? '无匹配对象' : '暂无对象，点右上「新增对象」创建' }}</td></tr>
        </tbody>
      </table>
    </div>

    <!-- ============ 服务对象 ============ -->
    <div v-show="tab === 'service'" class="bd-tablecard">
      <div class="bd-toolbar">
        <span class="bd-toolbar__c">服务对象 · {{ shownServices.length }} 项</span>
        <div style="flex: 1" />
        <div class="bd-searchbox" style="width: 240px">
          <icon-search />
          <input v-model="kw" class="bd-searchbox__in" placeholder="按名称 / 端口搜索" />
        </div>
      </div>
      <table class="bd-table">
        <thead>
          <tr><th>名称</th><th>协议</th><th>端口</th><th>描述</th><th>被引用</th><th class="r">操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="o in shownServices" :key="o.id">
            <td><b style="color: var(--bd-t1); font-weight: 500">{{ o.name }}</b></td>
            <td><span class="bd-tg" :style="tagStyle(protoColor(o.proto))">{{ o.proto.toUpperCase() }}</span></td>
            <td><span class="bd-mono">{{ o.ports || '—' }}</span></td>
            <td>{{ o.desc || '—' }}</td>
            <td>
              <a-popover v-if="refsOf(o.id).length" position="top">
                <span class="bd-tg bd-ref" :style="tagStyle('#FF7D00')">被引用 {{ refsOf(o.id).length }}</span>
                <template #content>
                  <div class="bd-reflist">
                    <div v-for="(r, i) in refsOf(o.id)" :key="i" class="bd-reflist__i">{{ refLabel(r) }}</div>
                  </div>
                </template>
              </a-popover>
              <span v-else class="bd-ref-none">未被引用</span>
            </td>
            <td class="r">
              <span class="bd-link" @click="openEdit('service', o)">编辑</span>
              <a-popconfirm content="确定删除该对象？" type="warning" @ok="del('service', o.id)">
                <span class="bd-link bd-link--danger" style="margin-left: 12px">删除</span>
              </a-popconfirm>
            </td>
          </tr>
          <tr v-if="!shownServices.length"><td colspan="6" class="bd-empty">{{ kw ? '无匹配对象' : '暂无对象，点右上「新增对象」创建' }}</td></tr>
        </tbody>
      </table>
    </div>

    <!-- ============ 时间对象 ============ -->
    <!-- ★时间对象**没有任何执行方**：后端引用复核对 time 恒返回 0（"暂无落库消费者"），
         它的「被引用」列结构性恒为"未被引用"，删除守卫恒放行。管理员照着旧副标题建一条
         「周一~周五 09:00-18:00」，以为能拿去卡访问时段，实际上只是一行谁也不读的记录。
         按时段限制访问的**真**执行方在认证策略的「非工作时间」规则里（offHours），
         那是另一套配置，名字还对不上。这条告警不能删——它是这一屏唯一说真话的地方。 -->
    <div v-show="tab === 'time'" class="bd-timewarn">
      <icon-exclamation-circle-fill />
      <div>
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
        <div style="flex: 1" />
        <div class="bd-searchbox" style="width: 240px">
          <icon-search />
          <input v-model="kw" class="bd-searchbox__in" placeholder="按名称 / 规格搜索" />
        </div>
      </div>
      <table class="bd-table">
        <thead>
          <tr><th>名称</th><th>类型</th><th>时间规格</th><th>描述</th><th>被引用</th><th class="r">操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="o in shownTimes" :key="o.id">
            <td><b style="color: var(--bd-t1); font-weight: 500">{{ o.name }}</b></td>
            <td><span class="bd-tg" :style="tagStyle(timeKindColor(o.kind))">{{ timeKindText(o.kind) }}</span></td>
            <td><span class="bd-mono">{{ o.spec }}</span></td>
            <td>{{ o.desc || '—' }}</td>
            <td>
              <a-popover v-if="refsOf(o.id).length" position="top">
                <span class="bd-tg bd-ref" :style="tagStyle('#FF7D00')">被引用 {{ refsOf(o.id).length }}</span>
                <template #content>
                  <div class="bd-reflist">
                    <div v-for="(r, i) in refsOf(o.id)" :key="i" class="bd-reflist__i">{{ refLabel(r) }}</div>
                  </div>
                </template>
              </a-popover>
              <span v-else class="bd-ref-none">未被引用</span>
            </td>
            <td class="r">
              <span class="bd-link" @click="openEdit('time', o)">编辑</span>
              <a-popconfirm content="确定删除该对象？" type="warning" @ok="del('time', o.id)">
                <span class="bd-link bd-link--danger" style="margin-left: 12px">删除</span>
              </a-popconfirm>
            </td>
          </tr>
          <tr v-if="!shownTimes.length"><td colspan="6" class="bd-empty">{{ kw ? '无匹配对象' : '暂无对象，点右上「新增对象」创建' }}</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 新增 / 编辑 对象 -->
    <a-modal v-model:visible="formOpen" :title="modalTitle" :width="480" :footer="false" unmount-on-close>
      <div class="bd-uform">
        <div class="bd-uform__f"><label>名称<i class="req">*</i></label>
          <a-input v-model="form.name" placeholder="如 OA 服务器" />
        </div>

        <!-- 地址对象字段 -->
        <template v-if="form.kind === 'addr'">
          <div class="bd-uform__f"><label>类型</label>
            <a-select v-model="form.addrKind">
              <a-option value="ip">主机（ip）</a-option>
              <a-option value="cidr">网段（cidr）</a-option>
              <a-option value="range">范围（range）</a-option>
              <a-option value="domain">域名（domain）</a-option>
            </a-select>
          </div>
          <div class="bd-uform__f"><label>值<i class="req">*</i></label>
            <a-input v-model="form.value" :placeholder="addrValuePlaceholder" />
          </div>
        </template>

        <!-- 服务对象字段 -->
        <template v-else-if="form.kind === 'service'">
          <div class="bd-uform__f"><label>协议</label>
            <a-select v-model="form.proto">
              <a-option value="tcp">TCP</a-option>
              <a-option value="udp">UDP</a-option>
              <a-option value="icmp">ICMP</a-option>
              <a-option value="any">ANY</a-option>
            </a-select>
          </div>
          <div class="bd-uform__f"><label>端口</label>
            <a-input v-model="form.ports" placeholder="如 443 或 8000-8100 或 1521,3306" />
          </div>
        </template>

        <!-- 时间对象字段 -->
        <template v-else>
          <div class="bd-uform__f"><label>类型</label>
            <a-select v-model="form.timeKind">
              <a-option value="periodic">周期</a-option>
              <a-option value="absolute">绝对</a-option>
            </a-select>
          </div>
          <div class="bd-uform__f"><label>时间规格<i class="req">*</i></label>
            <a-input v-model="form.spec" :placeholder="timeSpecPlaceholder" />
          </div>
        </template>

        <div class="bd-uform__f"><label>描述</label>
          <a-input v-model="form.desc" placeholder="可选说明" />
        </div>

        <div class="bd-uform__foot">
          <button class="bd-btn bd-btn--ghost" @click="formOpen = false">取消</button>
          <button class="bd-btn" :disabled="saving" @click="save">{{ editing ? '保存' : '创建' }}并落库</button>
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { api, type AddrObject, type ServiceObject, type TimeObject, type ObjectBundle, type ObjectRef, type ObjectUsageResp, failReason, failStatus } from '@/lib/api';

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
const live = ref(false);
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

function tagStyle(color: string) { return { color, background: color + '14' }; }
function addrKindColor(k: AddrObject['kind']) { return k === 'ip' ? '#165DFF' : k === 'cidr' ? '#0FC6C2' : k === 'range' ? '#FF7D00' : '#722ED1'; }
function addrKindText(k: AddrObject['kind']) { return k === 'ip' ? '主机' : k === 'cidr' ? '网段' : k === 'range' ? '范围' : '域名'; }
function protoColor(p: ServiceObject['proto']) { return p === 'tcp' ? '#165DFF' : p === 'udp' ? '#0FC6C2' : p === 'icmp' ? '#FF7D00' : '#86909C'; }
function timeKindColor(k: TimeObject['kind']) { return k === 'periodic' ? '#165DFF' : '#722ED1'; }
function timeKindText(k: TimeObject['kind']) { return k === 'periodic' ? '周期' : '绝对'; }

async function load() {
  try {
    const b = await api<ObjectBundle>('/objects');
    bundle.value = { addrs: b.addrs || [], services: b.services || [], times: b.times || [] };
    live.value = true;
    try {
      const u = await api<ObjectUsageResp>('/objects/usage');
      usage.value = u.usage || {};
    } catch { usage.value = {}; }
  } catch { bundle.value = MOCK; usage.value = {}; live.value = false; }
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
  if (!live.value) { Message.warning('当前为降级演示，未连接后端，无法写入'); return; }
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
  if (!live.value) { Message.warning('当前为降级演示，未连接后端，无法写入'); return; }
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
.bd-timewarn {
  display: flex; gap: 10px; align-items: flex-start; padding: 12px 16px; margin-bottom: 12px;
  background: var(--bd-tag-gold-bg); border: 1px solid #FFCF8B; border-radius: var(--bd-radius);
  font-size: 12.5px; color: var(--bd-t2); line-height: 1.85;
}
.bd-timewarn > :first-child { color: var(--bd-warning); font-size: 16px; flex: none; margin-top: 2px; }

/* tabs（对齐 Gateway.vue） */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

/* toolbar 计数文案 */
.bd-toolbar__c { font-size: 13px; font-weight: 600; color: var(--bd-t1); }

/* 搜索框输入 */
.bd-searchbox__in { border: none; outline: none; background: transparent; flex: 1; min-width: 0; font-size: 13px; color: var(--bd-t1); }
.bd-searchbox__in::placeholder { color: var(--bd-t3); }

/* 降级演示下禁用写入按钮 */
.bd-btn:disabled { opacity: .5; cursor: not-allowed; }

/* 空表 */
.bd-empty { text-align: center; color: var(--bd-t3, #86909c); padding: 28px 0; }

/* 「被引用」指示 */
.bd-ref { cursor: pointer; }
.bd-ref-none { font-size: 12px; color: var(--bd-t3, #86909c); }
.bd-reflist { min-width: 140px; max-width: 280px; }
.bd-reflist__i { font-size: 12.5px; color: var(--bd-t1); padding: 3px 0; line-height: 1.5; }
.bd-reflist__i + .bd-reflist__i { border-top: 1px solid var(--bd-fill-2); }

/* 表单（对齐 Resources.vue 的 .bd-uform） */
.bd-uform { padding: 2px 0; }
.bd-uform__f { margin-bottom: 16px; }
.bd-uform__f label { display: block; font-size: 13px; color: var(--bd-t2); margin-bottom: 7px; }
.bd-uform__f .req { color: var(--bd-danger, #f53f3f); margin-left: 2px; font-style: normal; }
.bd-uform__foot { display: flex; justify-content: flex-end; gap: 12px; margin-top: 8px; }
</style>
