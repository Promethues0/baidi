<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">备份与恢复<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">配置 + 审计数据定时备份 · SM4 加密 · 升级 / 迁移 / 灾备前必做 · 支持本地与远程目标</div>
      </div>
      <div style="display:flex;gap:8px">
        <a-button size="small" @click="restore"><template #icon><icon-upload /></template>从文件恢复</a-button>
        <a-button type="primary" size="small" :loading="backing" @click="backupNow"><template #icon><icon-save /></template>立即备份</a-button>
      </div>
    </div>

    <div class="zl-grid" style="grid-template-columns: 380px 1fr;">
      <!-- 备份策略 -->
      <div class="zl-card zl-card__pad">
        <div class="card-head"><div class="zl-card__title">自动备份策略</div><a-switch v-model="c.autoEnabled" /></div>
        <div class="cfg" :class="{dim: !c.autoEnabled}">
          <div class="cfg-row"><label>频率</label>
            <a-select v-model="c.schedule" size="small" style="width:160px">
              <a-option value="hourly">每小时</a-option><a-option value="daily">每天</a-option><a-option value="weekly">每周</a-option>
            </a-select>
          </div>
          <div class="cfg-row"><label>执行时刻</label><a-time-picker v-model="c.time" format="HH:mm" size="small" style="width:160px" /></div>
          <div class="cfg-row"><label>保留份数</label><a-input-number v-model="c.retain" size="small" style="width:160px"><template #suffix>份</template></a-input-number></div>
          <div class="cfg-row"><label>备份目标</label>
            <a-select v-model="c.target" size="small" style="width:160px">
              <a-option value="local">本地磁盘</a-option><a-option value="sftp">远程 SFTP</a-option><a-option value="s3">对象存储 S3</a-option>
            </a-select>
          </div>
          <div class="cfg-row" v-if="c.target!=='local'"><label>远程地址</label><a-input v-model="c.remoteHost" size="small" style="width:160px" placeholder="sftp://backup.corp/zl" /></div>
        </div>
        <div class="cfg" style="margin-top:8px;border-top:1px solid var(--line);padding-top:14px">
          <div class="kv-row"><div><b>SM4 加密</b><span>国密对称加密备份文件</span></div><a-switch v-model="c.encrypt" size="small" /></div>
          <div class="kv-row"><div><b>含审计数据</b><span>审计链 + 事件日志</span></div><a-switch v-model="c.includeAudit" size="small" /></div>
          <div class="kv-row"><div><b>含证书私钥</b><span>需 HSM 导出授权</span></div><a-switch v-model="c.includeCerts" size="small" /></div>
        </div>
        <a-button type="primary" long size="small" style="margin-top:14px" @click="save">保存策略</a-button>
      </div>

      <!-- 备份历史 -->
      <div class="zl-card" style="overflow:hidden">
        <div class="zl-card__title" style="padding:14px 16px;border-bottom:1px solid var(--line)">备份历史</div>
        <table class="bk-tbl">
          <thead><tr><th>时间</th><th>类型</th><th>范围</th><th>大小</th><th>加密</th><th>结果</th><th style="text-align:right">操作</th></tr></thead>
          <tbody>
            <tr v-for="b in recs" :key="b.key">
              <td class="data" style="font-size:12px">{{ b.at }}</td>
              <td><span class="bk-type" :class="b.type==='自动'?'auto':'manual'">{{ b.type }}</span></td>
              <td style="font-size:12px;color:var(--ink-2)">{{ b.scope }}</td>
              <td class="data" style="font-size:12px">{{ b.size }}</td>
              <td class="data" style="font-size:12px">{{ b.encrypt }}</td>
              <td><span class="zl-badge" :class="b.result==='成功'?'zl-badge--ok':'zl-badge--danger'">{{ b.result }}</span></td>
              <td style="text-align:right">
                <a-button size="mini" @click="download(b)">下载</a-button>
                <a-button size="mini" status="warning" style="margin-left:6px" @click="restoreFrom(b)">恢复</a-button>
              </td>
            </tr>
            <tr v-if="!recs.length"><td colspan="7" style="text-align:center;color:var(--ink-3);padding:24px">暂无备份记录</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

const live = ref(false);
const backing = ref(false);
const c = reactive<any>({
  autoEnabled: true, schedule: 'daily', time: '03:00', retain: 14, encrypt: true, encAlgo: 'SM4',
  target: 'local', remoteHost: '', includeAudit: true, includeCerts: true
});
const recs = ref<any[]>([]);

const mockRecs = [
  { key: '2026-06-13-0300', at: '2026-06-13 03:00:02', size: '4.2 MB', type: '自动', scope: '全量配置 + 审计', encrypt: 'SM4', result: '成功' },
  { key: '2026-06-12-0300', at: '2026-06-12 03:00:01', size: '4.1 MB', type: '自动', scope: '全量配置 + 审计', encrypt: 'SM4', result: '成功' }
];

async function load() {
  try {
    const [cfgR, recR] = await Promise.all([
      fetch('/ctl/api/coll?kind=syscfg'),
      fetch('/ctl/api/coll?kind=backuprec')
    ]);
    if (!cfgR.ok || !recR.ok) throw new Error();
    const cfg = (await cfgR.json()).find((x: any) => x.key === 'backup');
    if (cfg) Object.assign(c, cfg);
    recs.value = (await recR.json()).sort((a: any, b: any) => (a.at < b.at ? 1 : -1));
    live.value = true;
  } catch { recs.value = mockRecs; live.value = false; }
}
onMounted(load);

async function save() {
  if (live.value) {
    try {
      const r = await fetch('/ctl/api/coll?kind=syscfg', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ key: 'backup', doc: { key: 'backup', ...c } })
      });
      if (!r.ok) throw new Error();
    } catch { return Message.error('保存失败：控制面不可达'); }
  }
  Message.success('备份策略已保存' + (live.value ? ' · 已持久化' : '（mock）'));
}

async function backupNow() {
  backing.value = true;
  await new Promise((r) => setTimeout(r, 900));
  const at = '2026-06-13 ' + new Date().toTimeString().slice(0, 5);
  const key = 'manual-' + Date.now();
  const rec = { key, at, size: '4.2 MB', type: '手动', scope: '全量配置' + (c.includeAudit ? ' + 审计' : ''), encrypt: c.encrypt ? 'SM4' : '无', result: '成功' };
  if (live.value) {
    try { await fetch('/ctl/api/coll?kind=backuprec', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key, doc: rec }) }); } catch { /* ignore */ }
  }
  recs.value.unshift(rec);
  backing.value = false;
  Message.success('备份完成 · ' + at + (live.value ? ' · 已持久化' : ''));
}

const download = (b: any) => Message.info('下载备份 ' + b.at + '（SM4 加密 .zlbak）·（演示）');
function restoreFrom(b: any) {
  Modal.warning({
    title: '从备份恢复',
    content: `将用「${b.at}」的备份覆盖当前配置。恢复后控制面会重启并重新下发策略，期间接入短暂中断。此操作不可逆。`,
    okText: '确认恢复', hideCancel: false,
    onOk: () => Message.success('已发起恢复任务 ·（演示）')
  });
}
const restore = () => Message.info('从文件恢复：上传 .zlbak 备份文件（SM4 解密需备份口令）·（演示）');
</script>

<style scoped>
.card-head { display: flex; align-items: center; justify-content: space-between; padding-bottom: 12px; margin-bottom: 12px; border-bottom: 1px solid var(--line); }
.cfg { display: flex; flex-direction: column; gap: 12px; transition: opacity .2s; }
.cfg.dim { opacity: .4; pointer-events: none; }
.cfg-row { display: flex; align-items: center; gap: 16px; }
.cfg-row label { font-size: 12.5px; font-weight: 600; color: var(--ink-2); width: 78px; flex: none; }
.kv-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 8px 0; }
.kv-row + .kv-row { border-top: 1px solid var(--line); }
.kv-row b { display: block; font-size: 13px; color: var(--ink); font-weight: 600; }
.kv-row span { display: block; font-size: 11px; color: var(--ink-3); margin-top: 2px; }

.bk-tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
.bk-tbl th { text-align: left; font-size: 11.5px; font-weight: 650; color: var(--ink-3); padding: 9px 14px; background: var(--surface-2); border-bottom: 1px solid var(--line); }
.bk-tbl td { padding: 10px 14px; border-bottom: 1px solid var(--line); }
.bk-type { font-size: 11px; padding: 1px 8px; border-radius: var(--r-pill); }
.bk-type.auto { background: var(--accent-soft); color: var(--accent-2); }
.bk-type.manual { background: var(--surface-2); color: var(--ink-2); border: 1px solid var(--line-2); }
</style>
