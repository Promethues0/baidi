<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">高可用（HA）<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">主备 / 双活集群 · VRRP 虚 IP 漂移 · 会话同步保证故障切换不掉线 · 脑裂保护</div>
      </div>
      <div style="display:flex;gap:8px">
        <a-button size="small" status="warning" @click="manualSwitch" :disabled="!c.enabled">手动主备切换</a-button>
        <a-button type="primary" size="small" @click="save"><template #icon><icon-save /></template>保存配置</a-button>
      </div>
    </div>

    <!-- 集群拓扑 -->
    <div class="zl-card zl-card__pad" style="margin-bottom:16px">
      <div class="card-head"><div class="zl-card__title">集群高可用</div><a-switch v-model="c.enabled" /></div>
      <div class="ha-topo" :class="{dim: !c.enabled}">
        <div class="ha-node primary">
          <div class="ha-node__role">主 (MASTER)</div>
          <div class="ha-node__host data">{{ localHost }}</div>
          <div class="ha-node__st"><span class="d up" />运行中</div>
        </div>
        <div class="ha-link">
          <div class="ha-vip">VIP {{ c.vip }}</div>
          <div class="ha-hb">❤ 心跳 {{ c.heartbeatInterval }}ms · {{ c.heartbeatNic }}</div>
          <div class="ha-sync" v-if="c.sessionSync">⇄ 会话同步</div>
        </div>
        <div class="ha-node standby">
          <div class="ha-node__role">备 (BACKUP)</div>
          <div class="ha-node__host data">{{ c.peerHost }}</div>
          <div class="ha-node__st"><span class="d idle" />热备就绪</div>
        </div>
      </div>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1fr 1fr;">
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title" style="margin-bottom:12px">集群参数</div>
        <div class="cfg" :class="{dim: !c.enabled}">
          <div class="cfg-row"><label>工作模式</label>
            <a-select v-model="c.mode" size="small" style="width:220px">
              <a-option value="active-standby">主备（Active-Standby）</a-option>
              <a-option value="dual-active">双活（Active-Active）</a-option>
            </a-select>
          </div>
          <div class="cfg-row"><label>本机角色</label>
            <a-select v-model="c.role" size="small" style="width:220px">
              <a-option value="主">主（MASTER）</a-option><a-option value="备">备（BACKUP）</a-option>
            </a-select>
          </div>
          <div class="cfg-row"><label>虚 IP (VIP)</label><a-input v-model="c.vip" size="small" style="width:220px" placeholder="10.8.0.1" /></div>
          <div class="cfg-row"><label>对端地址</label><a-input v-model="c.peerHost" size="small" style="width:220px" placeholder="10.8.0.3" /></div>
        </div>
      </div>

      <div class="zl-card zl-card__pad">
        <div class="zl-card__title" style="margin-bottom:12px">心跳与切换</div>
        <div class="cfg" :class="{dim: !c.enabled}">
          <div class="cfg-row"><label>心跳网卡</label><a-input v-model="c.heartbeatNic" size="small" style="width:220px" placeholder="eth1" /></div>
          <div class="cfg-row"><label>心跳间隔</label><a-input-number v-model="c.heartbeatInterval" size="small" style="width:220px"><template #suffix>ms</template></a-input-number></div>
          <div class="cfg-row"><label>切换超时</label><a-input-number v-model="c.failoverTimeout" size="small" style="width:220px"><template #suffix>ms</template></a-input-number></div>
          <div class="kv-row"><div><b>会话同步</b><span>故障切换时已建隧道不掉线</span></div><a-switch v-model="c.sessionSync" size="small" /></div>
          <div class="kv-row"><div><b>抢占模式</b><span>主恢复后自动夺回 VIP</span></div><a-switch v-model="c.preempt" size="small" /></div>
          <div class="kv-row"><div><b>脑裂保护</b><span>仲裁防双主（建议开启）</span></div><a-switch v-model="c.splitBrainGuard" size="small" /></div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

const live = ref(false);
const c = reactive<any>({
  mode: 'active-standby', enabled: true, role: '主', vip: '10.8.0.1', peerHost: '10.8.0.3',
  heartbeatNic: 'eth1', heartbeatInterval: 1000, failoverTimeout: 5000,
  sessionSync: true, preempt: false, splitBrainGuard: true, lastSwitch: '—'
});
const localHost = computed(() => '10.8.0.2');

async function load() {
  try {
    const r = await fetch('/ctl/api/coll?kind=syscfg');
    if (!r.ok) throw new Error();
    const docs = await r.json();
    const d = docs.find((x: any) => x.key === 'ha');
    if (d) Object.assign(c, d);
    live.value = true;
  } catch { live.value = false; }
}
onMounted(load);

async function save() {
  if (live.value) {
    try {
      const r = await fetch('/ctl/api/coll?kind=syscfg', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ key: 'ha', doc: { key: 'ha', ...c } })
      });
      if (!r.ok) throw new Error();
    } catch { return Message.error('保存失败：控制面不可达'); }
  }
  Message.success('高可用配置已保存' + (live.value ? ' · 已持久化' : '（mock）'));
}
function manualSwitch() {
  Modal.warning({
    title: '手动主备切换',
    content: '将触发 VIP 从当前主节点漂移到备节点。已建会话经会话同步保持不掉线，但仍建议在维护窗口操作。',
    okText: '确认切换', hideCancel: false,
    onOk: () => { c.role = c.role === '主' ? '备' : '主'; Message.success('已触发主备切换 · VIP 漂移中'); }
  });
}
</script>

<style scoped>
.card-head { display: flex; align-items: center; justify-content: space-between; padding-bottom: 12px; margin-bottom: 14px; border-bottom: 1px solid var(--line); }
.ha-topo { display: flex; align-items: stretch; gap: 0; transition: opacity .2s; }
.ha-topo.dim { opacity: .4; }
.ha-node { flex: 1; max-width: 240px; border: 1.5px solid var(--line); border-radius: var(--r-md); padding: 16px; text-align: center; }
.ha-node.primary { border-color: var(--accent-line); background: var(--accent-soft); }
.ha-node.standby { border-style: dashed; }
.ha-node__role { font-size: 12px; font-weight: 700; color: var(--ink-2); }
.ha-node.primary .ha-node__role { color: var(--accent-2); }
.ha-node__host { font-size: 16px; font-weight: 700; color: var(--ink); margin: 8px 0; }
.ha-node__st { font-size: 12px; color: var(--ink-3); display: flex; align-items: center; justify-content: center; gap: 6px; }
.ha-node__st .d { width: 7px; height: 7px; border-radius: 50%; } .d.up { background: var(--ok); } .d.idle { background: var(--warn); }
.ha-link { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px; position: relative; }
.ha-link::before { content: ''; position: absolute; top: 50%; left: 8px; right: 8px; height: 2px; background: repeating-linear-gradient(90deg, var(--accent-line) 0 8px, transparent 8px 14px); z-index: 0; }
.ha-vip, .ha-hb, .ha-sync { position: relative; z-index: 1; background: var(--surface); padding: 2px 10px; border-radius: var(--r-pill); font-size: 11.5px; }
.ha-vip { font-weight: 700; color: var(--accent-2); border: 1px solid var(--accent-line); }
.ha-hb { color: var(--danger); } .ha-sync { color: var(--ok); }

.cfg { display: flex; flex-direction: column; gap: 12px; transition: opacity .2s; }
.cfg.dim { opacity: .4; pointer-events: none; }
.cfg-row { display: flex; align-items: center; gap: 16px; }
.cfg-row label { font-size: 12.5px; font-weight: 600; color: var(--ink-2); width: 90px; flex: none; }
.kv-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 8px 0; }
.kv-row + .kv-row { border-top: 1px solid var(--line); }
.kv-row b { display: block; font-size: 13px; color: var(--ink); font-weight: 600; }
.kv-row span { display: block; font-size: 11px; color: var(--ink-3); margin-top: 2px; }
</style>
