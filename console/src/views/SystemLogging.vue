<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">日志外发（Syslog / SNMP）<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">审计日志外发至 SIEM / 日志中心 · 等保合规要求（日志留存 ≥180 天 + 异地备份）· RFC5424 / SNMP Trap</div>
      </div>
      <a-button type="primary" size="small" @click="save"><template #icon><icon-save /></template>保存配置</a-button>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1fr 1fr;">
      <!-- Syslog -->
      <div class="zl-card zl-card__pad">
        <div class="card-head"><div class="zl-card__title">Syslog 外发</div><a-switch v-model="c.syslogEnabled" /></div>
        <div class="cfg" :class="{dim: !c.syslogEnabled}">
          <div class="cfg-row"><label>传输协议</label>
            <a-select v-model="c.syslogProto" size="small" style="width:200px">
              <a-option value="udp">UDP（不可靠）</a-option>
              <a-option value="tcp">TCP</a-option>
              <a-option value="tcp-tls">TCP + TLS（加密）</a-option>
            </a-select>
          </div>
          <div class="cfg-row"><label>服务器地址</label><a-input v-model="c.syslogHost" size="small" style="width:200px" placeholder="10.8.0.30" /></div>
          <div class="cfg-row"><label>端口</label><a-input-number v-model="c.syslogPort" size="small" style="width:200px" /></div>
          <div class="cfg-row"><label>消息格式</label>
            <a-select v-model="c.syslogFormat" size="small" style="width:200px">
              <a-option value="rfc5424">RFC 5424（推荐）</a-option>
              <a-option value="rfc3164">RFC 3164（BSD）</a-option>
              <a-option value="cef">CEF（ArcSight）</a-option>
              <a-option value="leef">LEEF（QRadar）</a-option>
            </a-select>
          </div>
          <div class="cfg-row"><label>Facility</label>
            <a-select v-model="c.syslogFacility" size="small" style="width:200px">
              <a-option v-for="f in ['local0','local1','local2','local3','local4','local5']" :key="f" :value="f">{{ f }}</a-option>
            </a-select>
          </div>
          <a-button size="mini" style="margin-top:6px" @click="test('syslog')">发送测试日志</a-button>
        </div>
      </div>

      <!-- SNMP -->
      <div class="zl-card zl-card__pad">
        <div class="card-head"><div class="zl-card__title">SNMP Trap</div><a-switch v-model="c.snmpEnabled" /></div>
        <div class="cfg" :class="{dim: !c.snmpEnabled}">
          <div class="cfg-row"><label>版本</label>
            <a-select v-model="c.snmpVersion" size="small" style="width:200px">
              <a-option value="v2c">v2c</a-option><a-option value="v3">v3（推荐，认证加密）</a-option>
            </a-select>
          </div>
          <div class="cfg-row"><label>Trap 接收地址</label><a-input v-model="c.snmpHost" size="small" style="width:200px" placeholder="10.8.0.31" /></div>
          <div class="cfg-row"><label>Community / 用户</label><a-input v-model="c.snmpCommunity" size="small" style="width:200px" placeholder="v3 填用户名" /></div>
          <a-button size="mini" style="margin-top:6px" @click="test('snmp')">发送测试 Trap</a-button>
        </div>
      </div>
    </div>

    <!-- 审计外发 + 本地留存 -->
    <div class="zl-card zl-card__pad" style="margin-top:16px">
      <div class="card-head"><div class="zl-card__title">审计事件外发</div><a-switch v-model="c.auditForward" /></div>
      <div class="cfg" :class="{dim: !c.auditForward}">
        <div class="cfg-row" style="align-items:flex-start"><label style="padding-top:4px">外发类别</label>
          <a-checkbox-group v-model="c.forwardCategories" style="max-width:520px">
            <a-checkbox v-for="cat in allCats" :key="cat" :value="cat">{{ cat }}</a-checkbox>
          </a-checkbox-group>
        </div>
      </div>
      <div class="cfg" style="margin-top:8px;border-top:1px solid var(--line);padding-top:14px">
        <div class="cfg-row"><label>日志级别</label>
          <a-select v-model="c.level" size="small" style="width:200px">
            <a-option v-for="l in ['debug','info','warn','error']" :key="l" :value="l">{{ l }}</a-option>
          </a-select>
        </div>
        <div class="cfg-row"><label>本地留存天数</label>
          <a-input-number v-model="c.localRetainDays" size="small" style="width:200px"><template #suffix>天</template></a-input-number>
        </div>
        <div class="cfg-hint">等保三级要求审计日志留存 ≥180 天；外发至独立日志中心可满足异地备份。</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { Message } from '@arco-design/web-vue';

const live = ref(false);
const allCats = ['登录认证', '策略变更', '配置变更', '会话审计', '管理操作', '系统告警'];
const c = reactive<any>({
  level: 'info', localRetainDays: 90,
  syslogEnabled: true, syslogProto: 'tcp-tls', syslogHost: '10.8.0.30', syslogPort: 6514, syslogFormat: 'rfc5424', syslogFacility: 'local0',
  snmpEnabled: false, snmpVersion: 'v3', snmpHost: '10.8.0.31', snmpCommunity: '',
  auditForward: true, forwardCategories: ['登录认证', '策略变更', '配置变更', '会话审计']
});

async function load() {
  try {
    const r = await fetch('/ctl/api/coll?kind=syscfg');
    if (!r.ok) throw new Error();
    const docs = await r.json();
    const d = docs.find((x: any) => x.key === 'logging');
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
        body: JSON.stringify({ key: 'logging', doc: { key: 'logging', ...c } })
      });
      if (!r.ok) throw new Error();
    } catch { return Message.error('保存失败：控制面不可达'); }
  }
  Message.success('日志外发配置已保存' + (live.value ? ' · 已持久化' : '（mock）'));
}
const test = (k: string) => Message.info(`已向 ${k === 'syslog' ? c.syslogHost : c.snmpHost} 发送测试${k === 'syslog' ? '日志' : ' Trap'} ·（演示）`);
</script>

<style scoped>
.card-head { display: flex; align-items: center; justify-content: space-between; padding-bottom: 12px; margin-bottom: 12px; border-bottom: 1px solid var(--line); }
.cfg { display: flex; flex-direction: column; gap: 12px; transition: opacity .2s; }
.cfg.dim { opacity: .4; pointer-events: none; }
.cfg-row { display: flex; align-items: center; gap: 16px; }
.cfg-row label { font-size: 12.5px; font-weight: 600; color: var(--ink-2); width: 110px; flex: none; }
.cfg-hint { font-size: 11px; color: var(--ink-3); line-height: 1.5; margin-top: 2px; }
</style>
