<template>
  <div class="dg">
    <div class="dg__head">
      <div>
        <div class="dk-page__title">自助诊断</div>
        <div class="dk-page__sub">终端侧真实探测 · 控制中心 / 网关隧道口 / 隧道内解析器逐项实测</div>
      </div>
      <button class="dk-btn" :disabled="running" @click="run"><icon-play-arrow />{{ running ? '诊断中…' : '一键诊断' }}</button>
    </div>

    <!-- 未接入时多数项不适用：先说清楚，免得用户把满屏「不适用」当成诊断没跑 -->
    <div v-if="!tun.running" class="dg__note">
      <icon-info-circle />
      <span>当前未接入。网关隧道口与隧道内解析器只在接入后才可探测——<b>未敲门时业务对本机隐身，连不上正是预期行为</b>。</span>
    </div>

    <div class="dk-card dg__list">
      <div v-for="c in checks" :key="c.key" class="dg__row">
        <span class="dg__ic" :class="c.state">
          <icon-loading v-if="c.state === 'running'" spin />
          <icon-check-circle-fill v-else-if="c.state === 'pass'" />
          <icon-close-circle-fill v-else-if="c.state === 'fail'" />
          <icon-exclamation-circle-fill v-else-if="c.state === 'warn'" />
          <icon-minus-circle v-else />
        </span>
        <div class="dg__main">
          <div class="dg__label">{{ c.label }}</div>
          <div class="dg__desc">{{ c.detail || c.desc }}</div>
        </div>
        <span class="dg__res" :class="c.state">{{ c.say || stateText(c.state) }}</span>
      </div>
    </div>

    <div class="dg__foot">
      <button class="dk-btn dk-btn--ghost" :disabled="collecting" @click="collect">
        <icon-download />{{ collecting ? '生成中…' : '生成诊断报告' }}
      </button>
      <span class="dg__hint">
        纯文本报告落到桌面，凭据已脱敏——<b>发给管理员之前可以自己先打开看一眼</b>
      </span>
    </div>
    <div v-if="reportPath" class="dg__done">
      <icon-check-circle-fill />报告已生成：<code class="dg__path">{{ reportPath }}</code>
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * 自助诊断页（wave7 行动 10 起为真探测）。
 *
 * 改造前这里是全客户端最陈旧的一段假代码：五项检查里只有「控制中心」是真的，
 * 「网关连通」与「专用 DNS 解析」直接 `state = 'ok'` 恒绿，「SPA/隧道」读的是
 * UI 标志位 session.connected 而非进程状态，收集日志则只弹一句 toast、
 * 连文件都不生成（而 Rust 侧的 collect_diag 早就写好并注册了，一直没人调）。
 *
 * 假绿诊断比没有诊断更糟：它替坏链路背书，而本项目最难查的失败形态恰恰是
 * 「显示已接入、实际不通」。判定规则（含几条反直觉的语义翻转）在 lib/diagnose.ts。
 */
import { reactive, ref, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { invoke } from '@tauri-apps/api/core';
import { ping } from '@/lib/api';
import { tunnelStatus, effectiveDNS } from '@/lib/tunnel';
import { config } from '@/lib/store';
import {
  judgeGateway, judgeDNS, judgeTunnel, judgeKnock, overall, explainControlFailure,
  type DiagState, type DiagVerdict, type TcpProbe, type DnsProbe
} from '@/lib/diagnose';

interface Chk { key: string; label: string; desc: string; state: DiagState; say?: string; detail?: string }
const checks = reactive<Chk[]>([
  { key: 'ctl', label: '控制中心可达', desc: '真实命中免认证 API（/api/v1/auth/domains）并核对回的是 JSON', state: 'idle' },
  { key: 'tun', label: 'SSL 访问隧道', desc: '数据面进程与隧道就绪状态', state: 'idle' },
  { key: 'spa', label: 'SPA 敲门保活', desc: '放行窗口是否在持续续期', state: 'idle' },
  { key: 'gw', label: '网关隧道口连通', desc: '真实拨测网关落点（不发任何字节）', state: 'idle' },
  { key: 'dns', label: '隧道内 DNS 解析', desc: '向隧道内解析器发一次真实查询', state: 'idle' }
]);
const running = ref(false);
const collecting = ref(false);
const reportPath = ref('');
const tun = reactive({ running: false, ready: false, keepalive: false, denied: false, deniedReason: '', error: '', gateway: '' });

function put(key: string, v: DiagVerdict) {
  const c = checks.find((x) => x.key === key);
  if (c) { c.state = v.state; c.say = v.say; c.detail = v.detail; }
}
function mark(key: string, s: DiagState) {
  const c = checks.find((x) => x.key === key);
  if (c) { c.state = s; c.say = ''; c.detail = ''; }
}
function stateText(s: DiagState) {
  return s === 'running' ? '检测中' : s === 'skip' ? '不适用' : '待检';
}

/** 刷新真实接入态（诊断的判定基准，必须来自进程状态而非 UI 标志位）。 */
async function refreshTun() {
  try {
    const s = await tunnelStatus();
    Object.assign(tun, {
      running: s.running, ready: s.ready, keepalive: s.keepalive,
      denied: s.denied, deniedReason: s.deniedReason, error: s.error, gateway: s.gateway
    });
  } catch {
    Object.assign(tun, { running: false, ready: false, keepalive: false });
  }
}

async function run() {
  running.value = true;
  reportPath.value = '';
  checks.forEach((c) => { c.state = 'idle'; c.say = ''; c.detail = ''; });
  await refreshTun();

  // 1) 控制中心（唯一一项与接入态无关：它走管理网，不经隧道）
  mark('ctl', 'running');
  const ctlOK = await ping();
  put('ctl', ctlOK
    ? { state: 'pass', say: '正常', detail: `${config.control || '（默认地址）'} 健康检查通过` }
    : { state: 'fail', say: '不可达', detail: await explainCtl() });

  // 2) 隧道 / 3) 敲门保活：读真实进程状态
  mark('tun', 'running');
  put('tun', judgeTunnel(tun));
  mark('spa', 'running');
  put('spa', judgeKnock(tun));

  // 4) 网关隧道口：★只在已接入时真探。未接入时连不上是隐身在生效，
  //    而且未敲门的连接会被网关记成一次「未敲门直连隧道口」安全事件——
  //    诊断不该把用户自己刷进控制台的攻击源榜单。
  mark('gw', 'running');
  const addr = tun.gateway || '';
  if (tun.running && tun.ready && addr) {
    const [host, portStr] = splitHostPort(addr);
    const raw = await probeTCP(host, Number(portStr) || 18443);
    put('gw', judgeGateway(tun, addr, raw));
  } else {
    put('gw', judgeGateway(tun, addr));
  }

  // 5) 隧道内 DNS：正例（记录表里真实存在的名字）+ 反例（必然不存在的名字）。
  //    只探正例分不清"隧道内解析器答的"与"系统解析器碰巧也能解析"。
  mark('dns', 'running');
  const dns = effectiveDNS(tun.running);
  if (tun.running && tun.ready && dns.server && dns.firstName) {
    const hit = await probeDNS(dns.server, dns.firstName);
    const miss = await probeDNS(dns.server, MISS_NAME);
    put('dns', judgeDNS(tun, { server: dns.server, name: dns.firstName }, hit, miss));
  } else {
    put('dns', judgeDNS(tun, { server: dns.server, name: dns.firstName }));
  }

  running.value = false;
  const o = overall(checks.map((c) => c.state));
  if (o.level === 'fail') Message.error(o.say);
  else if (o.level === 'warn') Message.warning(o.say);
  else Message.success(o.say);
}

/** 反例域名：.invalid 是 RFC 2606 保留后缀，永远不会是真实业务域名，
 *  也就永远不该出现在隧道内解析器的记录表里。 */
const MISS_NAME = 'baidi-diag-probe.invalid';

function splitHostPort(addr: string): [string, string] {
  const i = addr.lastIndexOf(':');
  return i > 0 ? [addr.slice(0, i), addr.slice(i + 1)] : [addr, ''];
}

async function probeTCP(host: string, port: number): Promise<TcpProbe | undefined> {
  try {
    return await invoke<TcpProbe>('probe_tcp', { host, port });
  } catch {
    return undefined;
  }
}
/** 控制中心不可达时的归因：先 TCP 探一次，再决定该说「改地址」还是「导证书」。
 *  ★这一项此前一律说「先在设置里核对控制中心地址与网络」，而按 install-remote.sh
 *  部署出来的控制面用的是自签证书——最常见的那种失败地址恰恰是对的。 */
async function explainCtl(): Promise<string> {
  const u = config.control.trim();
  const m = u.match(/^(https?):\/\/([^/:]+)(?::(\d+))?/i);
  const probe = m
    ? await probeTCP(m[2], m[3] ? Number(m[3]) : (m[1].toLowerCase() === 'https' ? 443 : 80))
    : undefined;
  return explainControlFailure(u, probe);
}

async function probeDNS(server: string, name: string): Promise<DnsProbe | undefined> {
  try {
    return await invoke<DnsProbe>('probe_dns', { server, name });
  } catch {
    return undefined;
  }
}

/**
 * 生成诊断报告：调 Rust 侧 collect_diag（它早就写好且注册了，只是此前没人调）。
 * 那边会把前端这份 report、数据面日志、终端环境汇成一份**脱敏后的纯文本**落到桌面。
 */
async function collect() {
  collecting.value = true;
  try {
    await refreshTun();
    const report = JSON.stringify({
      生成时刻: new Date().toISOString(),
      接入态: { 运行中: tun.running, 已就绪: tun.ready, 敲门保活: tun.keepalive, 网关落点: tun.gateway, 上次错误: tun.error },
      诊断项: checks.map((c) => ({ 项: c.label, 结论: c.state, 说明: c.say, 细节: c.detail }))
    }, null, 2);
    const path = await invoke<string>('collect_diag', { report });
    reportPath.value = path;
    Message.success('诊断报告已生成');
  } catch (e) {
    Message.error(`生成失败：${e instanceof Error ? e.message : String(e)}`);
  } finally {
    collecting.value = false;
  }
}

onMounted(refreshTun);
</script>

<style scoped>
.dg { padding: 22px 24px; }
.dg__head { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 18px; }
.dg__note {
  display: flex; align-items: flex-start; gap: 8px; padding: 10px 14px; margin-bottom: 14px;
  background: var(--bd-tag-blue-bg, #E8F3FF); border-radius: 8px; font-size: 12.5px; color: var(--bd-t2); line-height: 1.6;
}
.dg__list { padding: 4px 0; }
.dg__row { display: flex; align-items: center; gap: 12px; padding: 14px 18px; border-bottom: 1px solid var(--bd-fill-1); }
.dg__row:last-child { border-bottom: none; }
.dg__ic { font-size: 18px; flex: none; color: var(--bd-t4); }
.dg__ic.pass { color: var(--bd-success); }
.dg__ic.fail { color: var(--bd-danger); }
.dg__ic.warn { color: var(--bd-warning); }
.dg__ic.running { color: var(--bd-primary); }
.dg__main { flex: 1; min-width: 0; }
.dg__label { font-size: 13.5px; font-weight: 500; color: var(--bd-t1); }
.dg__desc { font-size: 12px; color: var(--bd-t3); margin-top: 2px; line-height: 1.6; }
.dg__res { font-size: 12.5px; color: var(--bd-t3); flex: none; }
.dg__res.pass { color: var(--bd-success); }
.dg__res.fail { color: var(--bd-danger); }
.dg__res.warn { color: var(--bd-warning); }
.dg__res.running { color: var(--bd-primary); }
.dg__foot { display: flex; align-items: center; gap: 12px; margin-top: 16px; flex-wrap: wrap; }
.dg__hint { font-size: 12px; color: var(--bd-t3); }
.dg__done { margin-top: 10px; font-size: 12.5px; color: var(--bd-success); display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.dg__path { font-family: ui-monospace, monospace; font-size: 12px; color: var(--bd-t2); word-break: break-all; }
</style>
