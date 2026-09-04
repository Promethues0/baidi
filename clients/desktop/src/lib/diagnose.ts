/**
 * 自助诊断 · 判定层（wave7 行动 10）。
 *
 * 探测在 Rust 侧（src-tauri/src/probe.rs），判定全在这里的纯函数里。分开的理由是
 * **这套规则有几条反直觉的语义翻转**，必须能被读懂、也必须能被单测钉住：
 *
 *  ★ 未接入时连不上网关隧道口，是**正确行为**而不是故障。
 *    白帝的业务对未授权者隐身：没敲门时内核态直接 DROP（firewall/baidi-pf.conf），
 *    connect 表现为超时，与"网关挂了"在网络层本就无法区分——那正是隐身要达到的效果。
 *    把它涂红，等于让诊断页在一切正常时长期亮红；用户学会忽略之后，真故障那次也看不见了。
 *
 *  ★ 判据是「立刻 EOF」还是「挂住」，不是「有没有读到数据」。
 *    TLS/TLCP 都是 client-speaks-first：探测端一字不发时，**已敲门**的连接会被网关
 *    挂在那里等 ClientHello（proxy.go 给了 8s），**未敲门**的连接则被立即 Close。
 *    若按"读到字节=网关活着"来写，三种情况会全判成故障。
 *
 *  ★ 只在**已接入态**探网关口。除了上面那条语义，还有一个现实副作用：
 *    未敲门的连接会被网关记成 `proxy-unauth` 安全事件，经心跳上报落成控制面
 *    verdict=deny 审计并累加攻击源统计（中文名就叫「未敲门直连隧道口」）。
 *    未接入时探测 = 用户每点一次「一键诊断」就把自己刷进控制台的「SPA 攻击源 TOP」。
 *    已接入时本机 IP 在放行窗口内，走的是放行分支，不会产生该事件。
 */

/** 四态。'skip' 必须与 'pass' 分开——把"不适用"涂成绿色正是这个页面原来的假绿本身。 */
export type DiagState = 'idle' | 'running' | 'pass' | 'warn' | 'fail' | 'skip';

export interface DiagVerdict {
  state: DiagState;
  /** 行尾结论（人话，不出现 EOF/RST 这类词）。 */
  say: string;
  /** 展开的技术细节，给排障用（可含术语）。 */
  detail?: string;
}

/** 接入态。必须来自 tunnelStatus()，不要用 store 里的 session.connected 标志位——
 *  那只是 UI 记的一个 bool，隧道在它背后死掉时它不会变。 */
export interface TunState {
  running: boolean;
  ready: boolean;
}
const isUp = (t: TunState) => t.running && t.ready;

/* ── 一、网关隧道口 ─────────────────────────────────────────── */

/** Rust `probe_tcp` 的返回（见 src-tauri/src/probe.rs）。 */
export interface TcpProbe {
  kind: 'closed-immediately' | 'held-open' | 'server-spoke' | 'refused' | 'timeout' | 'error';
  ms: number;
  head?: string;
  err?: string;
}

export function judgeGateway(tun: TunState, addr: string, raw?: TcpProbe): DiagVerdict {
  if (!addr) {
    return { state: 'skip', say: '未探测', detail: '接入剖面里没有网关落点，无从探测（先登录并拉取剖面）' };
  }
  if (!isUp(tun)) {
    // ★不是"没测出来"，是"此时本就该连不上"。文案要把这层意思说穿，
    //   否则用户会以为诊断偷懒了，转头去手工 telnet 那个端口——然后得到一个
    //   "连不上"的结论，白白怀疑网络半天。
    return {
      state: 'skip',
      say: '未接入 · 不适用',
      detail: `未敲门时业务对本机隐身，${addr} 连不上正是预期行为。接入之后此项才有诊断意义。`
    };
  }
  if (!raw) return { state: 'skip', say: '未探测' };
  switch (raw.kind) {
    case 'held-open':
      return { state: 'pass', say: `正常 · ${raw.ms}ms`, detail: `${addr} 已放行本机，连接保持中（网关正在等待 TLS 握手）` };
    case 'closed-immediately':
      return {
        state: 'warn',
        say: '连接被立即断开',
        detail: `${addr} 上有服务在听，但它立刻断开了本机的连接——多半是 SPA 放行窗口刚过期或本账号被强制下线。重新接入通常即可恢复。`
      };
    case 'server-spoke':
      return {
        state: 'warn',
        say: '对端不像白帝网关',
        detail: `${addr} 在本机一字未发时就先送来了数据（首字节 0x${raw.head || '??'}）。白帝隧道口不会先说话——该端口可能被别的服务占用，或流量被中间设备劫持。`
      };
    case 'refused':
      return { state: 'fail', say: '端口无人监听', detail: `${addr} ${raw.err || '拒绝连接'}——网关进程可能没起来，或落点地址配错了。` };
    case 'timeout':
      return {
        state: 'fail',
        say: '无回应',
        detail: `隧道已接入，但 ${addr} 对本机没有任何回应。已接入却连不上隧道口，说明放行窗口与数据面状态不一致（网关侧异常或中途丢包）。`
      };
    default:
      return { state: 'fail', say: '探测失败', detail: raw.err || '未知错误' };
  }
}

/* ── 二、隧道内 DNS 解析 ────────────────────────────────────── */

/** Rust `probe_dns` 的返回。 */
export interface DnsProbe {
  kind: 'answered' | 'refused' | 'nxdomain' | 'empty' | 'timeout' | 'error';
  ms: number;
  addr?: string;
  err?: string;
}

/** 探测输入：解析器 VIP 与一个**记录表里真实存在**的名字。
 *  ★两者都必须取自 baidi-tun 拉起那一刻的快照（tunnel.ts 的 startedOpts），
 *  不是当前剖面：拿刚获批的新域名去探运行中的隧道必然 REFUSED，那是"需重连才生效"，
 *  不是解析器故障，判成红色会把用户引向完全错误的排查方向。 */
export interface DnsInput {
  server: string;
  name: string;
}

export function judgeDNS(tun: TunState, input: DnsInput, hit?: DnsProbe, miss?: DnsProbe): DiagVerdict {
  if (!input.server) {
    // 最常见的正常形态：资源后端全是 IP，控制面压根没下发解析器（buildDNSPlan 返回空）。
    return {
      state: 'skip',
      say: '未启用',
      detail: '本次接入没有需要域名解析的资源，控制面未下发隧道内解析器——这是正常配置，不是故障。'
    };
  }
  if (!isUp(tun)) {
    return {
      state: 'skip',
      say: '未接入 · 不适用',
      detail: `解析器 ${input.server} 活在隧道内部，没有隧道就没有到它的路由。接入之后此项才有诊断意义。`
    };
  }
  if (!hit) return { state: 'skip', say: '未探测' };

  if (hit.kind !== 'answered') {
    const why: Record<string, string> = {
      refused: `解析器拒答了 ${input.name}——它在记录表里应当有值，多半是隧道拉起后授权变过（需重新接入让新记录生效）。`,
      nxdomain: `解析器称 ${input.name} 不存在。答话的可能不是隧道内解析器（白帝对未知名字回 REFUSED 而非 NXDOMAIN）。`,
      empty: `解析器认得 ${input.name} 但没给出 A 记录。`,
      timeout: `${input.server}:53 无回应——隧道虽在，查询没能送达解析器。`,
      error: hit.err || '探测失败'
    };
    return { state: 'fail', say: hit.kind === 'timeout' ? '解析器无回应' : '解析异常', detail: why[hit.kind] };
  }

  // 正例答对了，再看反例：一个必然不在记录表里的名字。
  // ★这一步不是多余：只探正例无法区分"隧道内解析器答的"与"系统解析器碰巧也能解析"。
  //   白帝的解析器对未知名字回 REFUSED（刻意不做递归转发），系统解析器则会 NXDOMAIN
  //   或真去递归——差别正好用来确认查询真的走进了隧道。
  const base: DiagVerdict = {
    state: 'pass',
    say: `正常 · ${hit.ms}ms`,
    detail: `${input.name} → ${hit.addr}（由隧道内解析器 ${input.server} 应答）`
  };
  if (!miss) return base;
  if (miss.kind === 'refused') {
    return { ...base, detail: `${base.detail}；未知域名被如实拒答，确认查询走的是隧道内解析器。` };
  }
  return {
    state: 'warn',
    say: '解析未走隧道',
    detail: `${input.name} 解析成功，但对一个不存在的域名也得到了应答（${miss.kind}）——说明系统把查询发给了本机的其它解析器，隧道内解析器可能没有被真正接管。`
  };
}

/* ── 三、隧道与敲门（改读真实进程状态，不再读 UI 标志位）───────── */

export function judgeTunnel(tun: TunState & { error?: string; denied?: boolean; deniedReason?: string }): DiagVerdict {
  if (tun.denied) {
    return { state: 'fail', say: '接入被拒绝', detail: tun.deniedReason || '控制面拒绝了本次接入（账号被禁用或强制下线）' };
  }
  if (!tun.running) {
    // 没接入不是故障——用户可能就是没点接入。
    return { state: 'skip', say: '未接入', detail: tun.error ? `上次接入失败：${tun.error}` : '数据面未运行' };
  }
  if (!tun.ready) {
    // 健康行带 err 时把数据面的原话交出去（指纹不匹配 / 取令牌失败 / 拨号超时…），
    // 没有才落到中性的「尚未报告」——不再说「尚未打印数据面就绪」：判据早已不是那行启动日志。
    return {
      state: 'warn',
      say: '建立中 / 未就绪',
      detail: tun.error
        ? `数据面报告：${tun.error}`
        : '数据面尚未报告隧道拨通——可能仍在建立，或建立失败但进程未退出。'
    };
  }
  return { state: 'pass', say: '正常', detail: '数据面进程在跑，隧道已就绪' };
}

export function judgeKnock(tun: TunState & { keepalive?: boolean }): DiagVerdict {
  if (!tun.running) {
    return { state: 'skip', say: '未接入', detail: '敲门发生在接入时，未接入时无从判定' };
  }
  if (!tun.keepalive) {
    return {
      state: 'warn',
      say: '未见保活',
      detail: '数据面在跑，但尚未报告敲门成功——放行窗口（默认 30s）到期后隧道会断。多见于控制面不可达，换不到新的短时效敲门令牌。'
    };
  }
  return { state: 'pass', say: '正常', detail: '敲门保活在跑，放行窗口持续续期' };
}

/* ── 汇总 ──────────────────────────────────────────────────── */

/** 整体结论：fail 优先于 warn，全 skip 时如实说"未接入，多数项不适用"。 */
export function overall(states: DiagState[]): { level: 'fail' | 'warn' | 'pass' | 'skip'; say: string } {
  const n = (s: DiagState) => states.filter((x) => x === s).length;
  if (n('fail')) return { level: 'fail', say: `诊断完成：${n('fail')} 项异常` };
  if (n('warn')) return { level: 'warn', say: `诊断完成：${n('warn')} 项需要留意` };
  if (n('pass') === 0) return { level: 'skip', say: '诊断完成：未接入，多数检查项不适用' };
  return { level: 'pass', say: `诊断完成：${n('pass')} 项正常${n('skip') ? `，${n('skip')} 项不适用` : ''}` };
}

/* ── 三、控制中心连不上时，到底是哪一环 ───────────────────────── */

/**
 * 控制面请求失败的**归因**。
 *
 * ★为什么必须归因：webview 的 `fetch` 对 TLS 失败与连不上给的是同一个
 * `TypeError: Failed to fetch`——浏览器故意不告诉你原因。于是客户端此前统一说
 * 「无法连接控制中心（检查「设置」里的控制中心地址）」，而**最常见的那种失败地址恰恰是对的**：
 * `deploy/install-remote.sh` 给每台新部署签的是**自签证书**，WebView2 / WKWebView 都按
 * 系统信任库校验，于是第一次接入的人必然撞墙，然后被这句话支去改一个本来就正确的设置。
 * 2026-08-18 首次真机验证就是这么卡住的：地址、网络、端口全对，UAC 因此从未弹出。
 *
 * 判据很简单，且只用现成材料：TCP 连得上而 HTTPS 请求失败 ⇒ 传输层没问题，
 * 问题在 TLS。**探不到就不猜**：TCP 探测本身失败时如实回落到通用文案。
 *
 * ★serverSaid：后端**答复过**的那句话（有 HTTP 应答就有它，哪怕是 403）。
 *   非空时本函数一个字都不许自己编——这是一道结构性的闸，不是约定。
 *   改造前它没有这个参数，而 Connect.vue 的 doLogin 是 bare catch，把**任何**登录失败
 *   都送进来做传输层归因。最坏的一例是防爆破锁定：lockout.go 在口令校验之前回 403，
 *   此时 TCP 当然是通的、HTTPS 请求也"失败"了，于是这里给出下面那句写得笃定又可执行的
 *   「**地址是对的，问题在证书**：请把该站点证书导入本机受信任的根证书颁发机构」——
 *   方向完全相反，而用户会照着真的去动系统根证书库，动完仍然登不进去
 *   （锁 15 分钟，期间每试一次还在续锁）。让"后端说了什么"成为入参并排在最前面，
 *   下一个调用方就没法再绕过它了。
 */
export function explainControlFailure(control: string, probe?: TcpProbe, serverSaid = ''): string {
  const said = serverSaid.trim();
  if (said) return said;
  const u = control.trim();
  if (!u) return '未配置控制中心地址';
  const https = /^https:/i.test(u);
  if (!probe || probe.kind === 'error') {
    return `无法连接控制中心 ${u}——请在「运维诊断」里跑一次探测看是哪一环`;
  }
  if (probe.kind === 'refused' || probe.kind === 'timeout') {
    return `连不上 ${u}：TCP 都没通（${probe.kind === 'refused' ? '连接被拒' : '超时'}）——` +
      '这才是地址 / 网络 / 防火墙的问题，先核对「设置」里的控制中心地址。';
  }
  // TCP 通了，HTTP 层却失败。
  if (https) {
    return `${u} 的 TCP 端口连得通（${probe.ms}ms），但 HTTPS 请求失败——` +
      '**地址是对的，问题在证书**：按 install-remote.sh 部署出来的控制面用的是**自签证书**，' +
      '系统不信任它，浏览器内核会直接掐断请求。解法二选一：' +
      '① 把该站点证书导入本机受信任的根证书颁发机构；② 给控制面换一张受信任的证书。';
  }
  return `${u} 的 TCP 端口连得通（${probe.ms}ms），但 HTTP 请求失败——` +
    '端口是通的，说明那头有东西在听，但它可能不是 baidi-control（端口写错？被别的服务占了？）。';
}
