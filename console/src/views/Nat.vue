<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">地址转换</div>
        <div class="bd-page__sub">
          把网关复用为出口 / 发布路由设备 · SNAT 代理上网与 DNAT 资源发布 · 规则由控制面编译后灌入网关内核
        </div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '未连' }}</a-tag>
        <button class="bd-btn" :disabled="!ifaceReady" :style="{ opacity: ifaceReady ? 1 : .5 }" @click="openWizard()">
          <icon-plus />新增策略
        </button>
      </div>
    </div>

    <!-- 风险提示（FR-NAT-12/11/16）：文案由后端下发，前端不自行编写——
         这几条是安全结论，写在前端就会与后端的实际行为脱节。 -->
    <div v-for="(w, i) in warnings" :key="i" class="bd-natwarn">
      <icon-exclamation-circle-fill /><span>{{ w }}</span>
    </div>

    <div v-if="err" class="bd-natwarn bd-natwarn--err"><icon-close-circle-fill /><span>{{ err }}</span></div>

    <div class="bd-two">
      <!-- 网卡台账 -->
      <div class="bd-card bd-ifaces">
        <div class="bd-ifaces__h">
          <span>网关网卡</span>
          <i>实测上报</i>
        </div>
        <div v-if="!ifaces.length" class="bd-ifaces__empty">
          还没有网关上报网卡。<br />网卡清单随网关 mTLS 心跳上报，需网关运行 v0.4 及以上版本。
        </div>
        <div v-for="g in ifaceGroups" :key="g.gatewayId" class="bd-ifgrp">
          <div class="bd-ifgrp__h"><icon-storage />{{ g.gatewayId }}</div>
          <div v-for="f in g.list" :key="f.name" class="bd-ifrow">
            <div class="bd-ifrow__l">
              <b class="bd-mono">{{ f.name }}</b>
              <span v-if="!f.up" class="bd-tg bd-tg--sm bd-ifdown">未启用</span>
              <i class="bd-mono">{{ f.addrs.join(' · ') || '无 IPv4 地址' }}</i>
            </div>
            <!-- 用包裹层定宽而不是给 a-select 加 class：Arco 的 .arco-select 自带
                 width:100% 且选择器特异性更高，直接写 .bd-iftype{width:116px} 会被顶掉，
                 后果是下拉框撑满整行、把左边的网卡名与 IP 压成 0 宽（本页第一版就是这样）。 -->
            <div class="bd-iftype">
              <a-select :model-value="f.type" size="mini" :disabled="busy"
                @update:model-value="(v: unknown) => setType(f, String(v))">
                <a-option value="">未定性</a-option>
                <a-option value="lan">LAN 口（对内）</a-option>
                <a-option value="wan">WAN 口（对外）</a-option>
              </a-select>
            </div>
          </div>
        </div>
        <div class="bd-ifaces__note">
          LAN/WAN 由管理员指定：网关没有可靠依据自动分辨哪张卡对公网（有默认路由 ≠ 对公网）。
          未定性的网卡不能出现在策略里。
        </div>
      </div>

      <!-- 策略表 -->
      <div class="bd-tablecard" style="flex: 1; min-width: 0">
        <div class="bd-toolbar">
          <span class="bd-toolbar__c">共 {{ policies.length }} 条策略</span>
          <div style="flex: 1" />
        </div>
        <table class="bd-table">
          <thead>
            <tr>
              <th>策略名称</th><th>类型</th><th>网关</th><th>匹配</th><th>转换后</th><th>状态</th><th class="r">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in policies" :key="p.id">
              <td><b>{{ p.name }}</b></td>
              <td>
                <span class="bd-tg" :style="tagStyle(p.type === 'snat' ? '#165DFF' : '#722ED1')">
                  {{ p.type === 'snat' ? 'SNAT 代理上网' : 'DNAT 资源发布' }}
                </span>
              </td>
              <td class="bd-mono">{{ p.gatewayId }}</td>
              <td class="bd-mono bd-natmatch">
                {{ p.srcIface }} {{ p.srcAddr }}
                <icon-arrow-right />
                {{ p.dstIface }} {{ p.dstAddr }}<template v-if="p.type === 'dnat' && p.dstPort">:{{ p.dstPort }}</template>
                <span v-if="p.type === 'dnat'" class="bd-tg bd-tg--sm" style="margin-left: 6px">{{ p.protocol.toUpperCase() }}</span>
              </td>
              <td class="bd-mono">
                <template v-if="p.type === 'dnat'">
                  {{ p.translatedAddr }}<template v-if="p.translatedPort">:{{ p.translatedPort }}</template>
                </template>
                <span v-else class="bd-dim">—（源地址转换为出口地址）</span>
              </td>
              <td>
                <a-switch :model-value="p.enabled" size="small" :disabled="busy"
                  @update:model-value="(v: unknown) => toggle(p, Boolean(v))" />
              </td>
              <td class="r">
                <button type="button" class="bd-link" @click="openWizard(p)">编辑</button>
                <button type="button" class="bd-link bd-link--danger" style="margin-left: 12px" @click="askRemove(p)">删除</button>
              </td>
            </tr>
            <tr v-if="!policies.length">
              <td colspan="7" class="bd-natempty">
                尚无地址转换策略。<template v-if="!ifaceReady">先在左侧给网关网卡指定 LAN/WAN 类型，才能新增策略。</template>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 策略向导：按 SNAT/DNAT 动态显隐字段（FR-NAT-03/09/10） -->
    <a-drawer v-model:visible="wz.open" :width="640" :title="wz.id ? '编辑地址转换策略' : '新增地址转换策略'" :footer="false" unmount-on-close>
      <div class="bd-wz">
        <div class="bd-wz__body">
          <div class="bd-fld"><label>策略名称</label><a-input v-model="wz.name" :max-length="64" placeholder="如：内网代理上网" /></div>

          <div class="bd-fld"><label>转换类型</label>
            <a-radio-group v-model="wz.type" type="button" @change="onTypeChange">
              <a-radio value="snat">SNAT · 代理上网</a-radio>
              <a-radio value="dnat">DNAT · 资源发布</a-radio>
            </a-radio-group>
            <span class="bd-fld__d">{{ wz.type === 'snat'
              ? '内网网段经网关统一出口访问外部：源接口选 LAN 口，目的接口选 WAN 口。'
              : '把公网 IP:端口映射到内网真实业务地址：源接口选 WAN 口，目的接口选 LAN 口。' }}</span>
          </div>

          <div class="bd-fld"><label>下发到网关</label>
            <a-select v-model="wz.gatewayId" placeholder="选择网关" @change="wz.srcIface = ''; wz.dstIface = ''">
              <a-option v-for="g in gatewayIds" :key="g" :value="g">{{ g }}</a-option>
            </a-select>
            <span class="bd-fld__d">地址转换是设备本地能力，规则只灌到选中的这台网关。</span>
          </div>

          <div class="bd-fld"><label>源接口（{{ wz.type === 'snat' ? 'LAN 口' : 'WAN 口' }}）</label>
            <a-select v-model="wz.srcIface" placeholder="选择网卡" :disabled="!wz.gatewayId">
              <a-option v-for="f in pickable(wz.type === 'snat' ? 'lan' : 'wan')" :key="f.name" :value="f.name">
                {{ f.name }} · {{ f.addrs.join(',') || '无地址' }}
              </a-option>
            </a-select>
          </div>
          <div class="bd-fld"><label>源地址</label>
            <a-input v-model="wz.srcAddr" class="bd-mono" :placeholder="wz.type === 'snat' ? '5.5.0.0/16（需代理上网的内网网段）' : '0.0.0.0/0（允许访问的公网来源）'" />
            <span v-if="wz.type === 'dnat'" class="bd-fld__d">默认 0.0.0.0/0 全放行；改成具体网段可收敛来源，只有该网段能访问被发布的服务。</span>
          </div>

          <div class="bd-fld"><label>目的接口（{{ wz.type === 'snat' ? 'WAN 口' : 'LAN 口' }}）</label>
            <a-select v-model="wz.dstIface" placeholder="选择网卡" :disabled="!wz.gatewayId">
              <a-option v-for="f in pickable(wz.type === 'snat' ? 'wan' : 'lan')" :key="f.name" :value="f.name">
                {{ f.name }} · {{ f.addrs.join(',') || '无地址' }}
              </a-option>
            </a-select>
          </div>
          <div class="bd-fld"><label>{{ wz.type === 'snat' ? '目的地址（出口网段）' : '对外发布地址' }}</label>
            <a-input v-model="wz.dstAddr" class="bd-mono" :placeholder="wz.type === 'snat' ? '155.155.0.0/16' : '5.5.10.102'" />
          </div>

          <!-- 转换后数据仅 DNAT 出现（FR-NAT-10 + 18.5 动态显隐要求） -->
          <template v-if="wz.type === 'dnat'">
            <div class="bd-fld"><label>协议</label>
              <a-radio-group v-model="wz.protocol" type="button" size="small">
                <a-radio value="tcp">TCP</a-radio><a-radio value="udp">UDP</a-radio>
                <a-radio value="icmp">ICMP</a-radio><a-radio value="all">所有协议</a-radio>
              </a-radio-group>
            </div>
            <template v-if="wz.protocol !== 'icmp'">
              <div class="bd-fld"><label>对外发布端口</label>
                <a-input-number v-model="wz.dstPort" :min="1" :max="65535" placeholder="9999" />
              </div>
            </template>
            <div class="bd-sec2">转换后数据</div>
            <div class="bd-fld"><label>目的地址转换为</label>
              <a-input v-model="wz.translatedAddr" class="bd-mono" placeholder="155.155.235.212（业务系统真实内网 IP）" />
            </div>
            <div v-if="wz.protocol !== 'icmp'" class="bd-fld"><label>端口转换为</label>
              <a-input-number v-model="wz.translatedPort" :min="0" :max="65535" placeholder="8081（留空=与对外端口相同）" />
            </div>
          </template>

          <div class="bd-fld bd-fld--row">
            <div><label>启用</label><span class="bd-fld__d">停用的策略不会下发给网关</span></div>
            <a-switch v-model="wz.enabled" />
          </div>

          <div class="bd-wz__note">
            <icon-info-circle />
            保存后规则由网关编译进内核（需网关以 -nat 启动且具备 root）。零信任隧道与敲门流量已自动从 SNAT 中排除。
          </div>
        </div>
        <div class="bd-wz__foot">
          <div style="flex: 1" />
          <button class="bd-btn bd-btn--ghost" @click="wz.open = false">取消</button>
          <button class="bd-btn" :disabled="busy || !canSave" :style="{ opacity: busy || !canSave ? .5 : 1 }" @click="save">保存</button>
        </div>
      </div>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { api, type NATBundle, type NATPolicy, type GatewayIface, type NATType, type NATProto } from '@/lib/api';

const live = ref(false);
const busy = ref(false);
const err = ref('');
const policies = ref<NATPolicy[]>([]);
const ifaces = ref<GatewayIface[]>([]);
const warnings = ref<string[]>([]);

/* 这一页刻意没有降级演示数据：编造的 NAT 策略与真实规则在页面上无法区分，
   而它决定的是「哪些内网端口对公网可达」。连不上就说连不上。 */

const gatewayIds = computed(() => [...new Set(ifaces.value.map((f) => f.gatewayId))].sort());
const ifaceGroups = computed(() => gatewayIds.value.map((id) => ({
  gatewayId: id, list: ifaces.value.filter((f) => f.gatewayId === id)
})));
/** 有没有可用于建策略的网卡：至少一台网关同时有 LAN 与 WAN 口。 */
const ifaceReady = computed(() => gatewayIds.value.some((id) => {
  const mine = ifaces.value.filter((f) => f.gatewayId === id);
  return mine.some((f) => f.type === 'lan') && mine.some((f) => f.type === 'wan');
}));

function pickable(want: 'lan' | 'wan'): GatewayIface[] {
  return ifaces.value.filter((f) => f.gatewayId === wz.gatewayId && f.type === want);
}
function tagStyle(color: string) { return { color, background: color + '14' }; }

const wz = reactive({
  open: false, id: '', name: '', type: 'snat' as NATType, gatewayId: '',
  srcIface: '', srcAddr: '', dstIface: '', dstAddr: '',
  protocol: 'tcp' as NATProto, dstPort: 0, translatedAddr: '', translatedPort: 0, enabled: true
});

const canSave = computed(() =>
  !!wz.name.trim() && !!wz.gatewayId && !!wz.srcIface && !!wz.srcAddr && !!wz.dstIface && !!wz.dstAddr &&
  (wz.type === 'snat' || (!!wz.translatedAddr && (wz.protocol === 'icmp' || wz.dstPort > 0)))
);

// 切换类型时清空接口选择：SNAT 与 DNAT 对源/目的的方向要求相反，
// 留着上一次的选择会让管理员保存时才被后端以「方向选反」拒绝。
function onTypeChange() {
  wz.srcIface = ''; wz.dstIface = '';
  if (wz.type === 'dnat' && !wz.srcAddr) wz.srcAddr = '0.0.0.0/0';
}

function openWizard(p?: NATPolicy) {
  err.value = '';
  if (p) {
    Object.assign(wz, { ...p, open: true });
  } else {
    Object.assign(wz, {
      open: true, id: '', name: '', type: 'snat' as NATType,
      gatewayId: gatewayIds.value[0] ?? '', srcIface: '', srcAddr: '',
      dstIface: '', dstAddr: '', protocol: 'tcp' as NATProto,
      dstPort: 0, translatedAddr: '', translatedPort: 0, enabled: true
    });
  }
}

async function save() {
  busy.value = true; err.value = '';
  try {
    const r = await api<{ warnings?: string[] }>('/nat/policies', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: wz.id, name: wz.name, type: wz.type, gatewayId: wz.gatewayId,
        srcIface: wz.srcIface, srcAddr: wz.srcAddr, dstIface: wz.dstIface, dstAddr: wz.dstAddr,
        protocol: wz.type === 'snat' ? 'all' : wz.protocol,
        dstPort: wz.dstPort, translatedAddr: wz.translatedAddr, translatedPort: wz.translatedPort,
        enabled: wz.enabled
      })
    });
    wz.open = false;
    Message.success(wz.id ? '策略已更新' : '策略已创建');
    // 保存那一刻当面给出风险提示：这是管理员最需要知道「这条 DNAT 让 SPA 对该端口失效」
    // 的时刻，而不是下次打开页面时。
    const w = r.warnings ?? [];
    if (w.length) Modal.warning({ title: '策略已保存，请注意以下影响', content: w.join('\n\n'), width: 560 });
    await load();
  } catch (e) {
    err.value = (e as Error).message || '保存失败';
  } finally { busy.value = false; }
}

async function toggle(p: NATPolicy, v: boolean) {
  busy.value = true; err.value = '';
  try {
    await api('/nat/policies', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...p, enabled: v })
    });
    await load();
  } catch (e) {
    err.value = (e as Error).message || '切换失败';
  } finally { busy.value = false; }
}

function askRemove(p: NATPolicy) {
  Modal.confirm({
    title: '删除地址转换策略',
    content: `确定删除「${p.name}」？删除后网关下一轮策略拉取即从内核移除对应规则。`,
    okText: '删除', cancelText: '取消', okButtonProps: { status: 'danger' },
    onOk: async () => {
      try {
        await api(`/nat/policies/${encodeURIComponent(p.id)}`, { method: 'DELETE' });
        Message.success(`已删除策略「${p.name}」`);
        await load();
      } catch (e) { err.value = (e as Error).message || '删除失败'; }
    }
  });
}

async function setType(f: GatewayIface, t: string) {
  busy.value = true; err.value = '';
  try {
    await api(`/nat/ifaces/${encodeURIComponent(f.gatewayId)}/${encodeURIComponent(f.name)}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: t })
    });
    await load();
  } catch (e) {
    err.value = (e as Error).message || '设置网卡类型失败';
  } finally { busy.value = false; }
}

async function load() {
  try {
    const b = await api<NATBundle>('/nat');
    policies.value = b.policies ?? [];
    ifaces.value = b.ifaces ?? [];
    warnings.value = b.warnings ?? [];
    live.value = true;
  } catch (e) {
    live.value = false;
    err.value = (e as Error).message || '无法读取地址转换配置';
  }
}
onMounted(load);
</script>

<style scoped>
/* 表单与抽屉的排版类在本项目里是**每个视图各自 scoped 定义**的（不是全局）：
   只写类名不写样式，页面会渲染成「说明文字挤在控件同一行」的样子——本页第一版就是。
   与 Apps.vue 的定义保持一致，避免两页表单看起来不像同一个产品。 */
.bd-wz { display: flex; flex-direction: column; height: 100%; }
.bd-wz__body { flex: 1; overflow-y: auto; padding-right: 2px; }
.bd-wz__foot { display: flex; align-items: center; gap: 10px; padding-top: 16px; border-top: 1px solid var(--bd-fill-2); }
.bd-fld { margin-bottom: 16px; }
.bd-fld > label { display: block; font-size: 13px; font-weight: 500; color: var(--bd-t1); margin-bottom: 7px; }
.bd-fld :deep(.arco-input-wrapper), .bd-fld :deep(.arco-select-view), .bd-fld :deep(.arco-input-number) { width: 100%; }
.bd-fld--row { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.bd-fld--row label { display: block; margin-bottom: 2px; }
/* block 而非 inline：说明文字必须换行到控件下方，否则会和单选按钮挤在一行。 */
.bd-fld__d { display: block; margin-top: 6px; font-size: 12px; color: var(--bd-t3); line-height: 1.6; }
.bd-fld--row .bd-fld__d { margin-top: 0; }

.bd-natwarn {
  display: flex; align-items: flex-start; gap: 8px; margin-bottom: 10px; padding: 10px 12px;
  border-radius: 8px; font-size: 12.5px; line-height: 1.6;
  color: #A8620E; background: #FFF7E8; border: 1px solid #FFD08A;
}
.bd-natwarn--err { color: var(--bd-danger); background: var(--bd-tag-red-bg); border-color: #FFC2C2; }
.bd-natwarn > :first-child { flex: none; margin-top: 2px; font-size: 14px; }

.bd-ifaces { width: 320px; flex: none; padding: 14px; }
.bd-ifaces__h { display: flex; align-items: baseline; gap: 8px; font-size: 13px; font-weight: 600; margin-bottom: 10px; }
.bd-ifaces__h i { font-style: normal; font-size: 11px; color: var(--bd-t3); }
.bd-ifaces__empty, .bd-natempty { color: var(--bd-t3); font-size: 12.5px; line-height: 1.8; padding: 18px 4px; text-align: center; }
.bd-ifgrp { margin-bottom: 12px; }
.bd-ifgrp__h { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--bd-t2); margin-bottom: 6px; }
.bd-ifrow { display: flex; align-items: center; gap: 8px; padding: 6px 0; border-top: 1px solid var(--bd-line); }
.bd-ifrow__l { flex: 1; min-width: 0; }
.bd-ifrow__l b { font-size: 12.5px; }
.bd-ifrow__l i { display: block; font-style: normal; font-size: 11px; color: var(--bd-t3); margin-top: 2px; }
.bd-ifdown { color: var(--bd-t3); background: var(--bd-fill-2); }
.bd-iftype { width: 116px; flex: none; }
.bd-ifaces__note { margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--bd-line); font-size: 11px; color: var(--bd-t3); line-height: 1.7; }
.bd-natmatch { font-size: 11.5px; }
.bd-natmatch svg { margin: 0 4px; color: var(--bd-t3); }
.bd-dim { color: var(--bd-t3); }
.bd-sec2 { font-size: 12px; font-weight: 600; color: var(--bd-t2); margin: 14px 0 8px; padding-top: 12px; border-top: 1px solid var(--bd-line); }
.bd-wz__note {
  display: flex; align-items: flex-start; gap: 7px; margin-top: 16px; padding: 10px;
  border-radius: 8px; font-size: 12px; line-height: 1.6; color: var(--bd-t2); background: var(--bd-fill-2);
}
.bd-wz__note svg { flex: none; margin-top: 2px; }
</style>
