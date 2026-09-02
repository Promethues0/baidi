/**
 * 接入态解析单测：判据必须来自数据面健康行，不能是两行启动日志。
 *
 * 背景（提交 796ac0f 只做了 Go/Rust 半边）：dataplane.logHealth 打健康行、main.rs 捞进
 * TunStatus.health，而 tunnel.ts 的 parseHealth 定义后零调用、ready 仍判 /数据面就绪/、
 * error 仍是 `!running && …`——于是指纹钉扎失败（疑似中间人）/ 敲门被拒 / 隧道拨不通
 * 三类故障在接入页一律绿色「已接入」，App.vue 的 session.connected 也跟着放行。
 * 这批用例把 TS 这半边钉住；改回只用旧正则，前三组必须变红。
 */
import { describe, expect, it, vi } from 'vitest';

// tunnel.ts 顶层 import 了 Tauri 运行时与 store（store 在模块加载时就读 localStorage）；
// 被测的是纯解析逻辑，两者都换成最小桩——不为它们引 jsdom。
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('./store', () => ({
  config: { control: 'http://127.0.0.1:8090', gateway: '127.0.0.1', spaPort: '18201', proxyPort: '18443', route: '10.99.0.0/24', ip: '10.99.0.2', gm: false },
  session: { token: 't', user: 'u', connected: false },
  profile: { data: null, loadedAt: '', error: '' },
  device: { id: '' }
}));

import { classifyFail, nextDataplaneNotice, parseHealth, parseTunStatus, type DataplaneNotice, type TunStatusRaw, type TunView } from './tunnel';

/** 数据面启动期那两行 + 一条引流日志：改造前光凭它们就会被判成「已接入 · 保活中」。 */
const BOOT_LOG = [
  'time=2026-09-02T10:00:00.000+08:00 level=INFO msg=数据面就绪 dev=utun7 ip=10.99.0.2 route=10.99.0.0/24',
  'time=2026-09-02T10:00:00.100+08:00 level=INFO msg=敲门保活 interval=15s',
  'time=2026-09-02T10:00:03.000+08:00 level=INFO msg=引流 dst=10.99.0.10:443'
].join('\n');

const SLOG = 'time=2026-09-02T10:00:05.000+08:00 level=INFO msg=数据面健康 ';

function raw(over: Partial<TunStatusRaw>): TunStatusRaw {
  return { running: true, pid: '4242', log: BOOT_LOG, ...over };
}

describe('parseTunStatus · 健康行是真判据', () => {
  it('knock=false → 不算 ready、也不算保活，哪怕启动日志两行都在', () => {
    const v = parseTunStatus(raw({ health: SLOG + 'knock=false tunnel=false err="取敲门令牌失败：dial tcp 127.0.0.1:8090: connect: connection refused"' }));
    expect(v.running).toBe(true);
    expect(v.ready).toBe(false);
    expect(v.keepalive).toBe(false);
    expect(v.error).toContain('取敲门令牌失败');
  });

  it('运行中 tunnel=false → error 非空且写明原因（改造前运行中恒为空串）', () => {
    const v = parseTunStatus(raw({ health: SLOG + 'knock=true tunnel=false err="网关证书指纹不匹配（疑似中间人）：期望 abc 实得 def"' }));
    expect(v.ready).toBe(false);
    expect(v.keepalive).toBe(true);       // 敲门包确实发出去过
    expect(v.error).toBe('网关证书指纹不匹配（疑似中间人）：期望 abc 实得 def');
  });

  it('隧道曾拨通、随后每次都失败（err 挂着）→ 不是「已接入」', () => {
    const v = parseTunStatus(raw({ health: SLOG + 'knock=true tunnel=true err="隧道拨号失败（未敲门成功/网关隐身?）"' }));
    expect(v.ready).toBe(false);
    expect(v.error).toContain('隧道拨号失败');
  });

  it('knock=true tunnel=true err=- → ready，error 为空，tunnelUsed=true', () => {
    const v = parseTunStatus(raw({ health: SLOG + 'knock=true tunnel=true err=-' }));
    expect(v.ready).toBe(true);
    expect(v.keepalive).toBe(true);
    expect(v.error).toBe('');
    expect(v.tunnelUsed).toBe(true);
  });

  it('★空闲健康态 knock=true tunnel=false err=- 且运行中 → ready、error 空（tunnel 位不是必要条件）', () => {
    // Go 侧 markTunnel() 只在第一条业务流拨通时才置位，Run() 启动期只敲门不预拨：
    // 用户打开第一个应用之前，一次完全正常的接入健康行恒为这一行。
    // 复核发现：把 tunnel 当必要条件 → 接入停在「接入中」25s 后报猜的归因，
    // session.connected 恒 false → 应用页拒绝「访问」→ 永远产生不出第一条流 → 死锁。
    const v = parseTunStatus(raw({ health: SLOG + 'knock=true tunnel=false err=-' }));
    expect(v.ready).toBe(true);
    expect(v.keepalive).toBe(true);
    expect(v.error).toBe('');
    expect(v.tunnelUsed).toBe(false);   // 展示用：「已就绪 · 尚无业务流量」
  });

  it('健康行说一切正常、但启动日志早被业务流量挤出尾巴 → 仍是 ready（判据不再依赖尾巴）', () => {
    const busy = Array.from({ length: 40 }, (_, i) => `time=… level=INFO msg=引流 dst=10.99.0.${i}:443`).join('\n');
    const v = parseTunStatus(raw({ log: busy, health: SLOG + 'knock=true tunnel=true err=-' }));
    expect(v.ready).toBe(true);
    expect(v.keepalive).toBe(true);
  });

  it('进程已退出：健康行的 ready/keepalive 不作数（旧日志残留），error 仍报原因', () => {
    const v = parseTunStatus(raw({ running: false, health: SLOG + 'knock=true tunnel=true err="SPA 拨号失败：network is unreachable"' }));
    expect(v.ready).toBe(false);
    expect(v.keepalive).toBe(false);
    expect(v.error).toBe('SPA 拨号失败：network is unreachable');
  });

  it('进程已退出且健康行无错 → 退回日志尾巴里最近一条失败', () => {
    const log = BOOT_LOG + '\ntime=2026-09-02T10:00:09.000+08:00 level=WARN msg="接入被控制面拒绝，数据面退出"';
    const v = parseTunStatus(raw({ running: false, log, health: SLOG + 'knock=true tunnel=true err=-' }));
    expect(v.error).toBe('接入被控制面拒绝，数据面退出');
  });
});

describe('parseTunStatus · 无健康行时回落旧判据（逐字不变）', () => {
  it.each([undefined, null, ''])('health=%s：两行启动日志在 → ready + keepalive；运行中 error 恒空；tunnelUsed 不可判定', (health) => {
    const v = parseTunStatus(raw({ health: health as TunStatusRaw['health'] }));
    expect(v.ready).toBe(true);
    expect(v.keepalive).toBe(true);
    expect(v.error).toBe('');
    expect(v.tunnelUsed).toBeNull();
  });

  it('旧判据：启动日志缺席 → 不 ready', () => {
    const v = parseTunStatus(raw({ log: 'time=… level=INFO msg=创建 utun dev=utun7' }));
    expect(v.ready).toBe(false);
    expect(v.keepalive).toBe(false);
    expect(v.dev).toBe('utun7');
  });

  it('旧判据：运行中日志里有「失败」也不报 error（改造前行为，仅回落路径保留）', () => {
    const v = parseTunStatus(raw({ log: BOOT_LOG + '\ntime=… level=WARN msg=隧道拨号失败（未敲门成功/网关隐身?） dst=10.99.0.10:443 err=timeout' }));
    expect(v.ready).toBe(true);
    expect(v.error).toBe('');
  });

  it('旧判据：进程已退出 → 取最近一条失败并去掉 slog 前缀', () => {
    const v = parseTunStatus(raw({ running: false, log: BOOT_LOG + '\ntime=… level=ERROR msg="创建 utun 失败: operation not permitted"' }));
    expect(v.ready).toBe(false);
    expect(v.error).toBe('创建 utun 失败: operation not permitted');
  });

  it('健康行缺 tunnel 字段（残缺行）→ 视同没有健康行，回落旧判据', () => {
    const v = parseTunStatus(raw({ health: SLOG + 'knock=false' }));
    expect(v.ready).toBe(true);   // 旧判据：两行启动日志在
  });
});

describe('parseHealth · 格式容错', () => {
  it('标准 slog 行', () => {
    expect(parseHealth(SLOG + 'knock=true tunnel=false err=-')).toEqual({ knock: true, tunnel: false, err: '' });
  });

  it('多余空白与字段乱序', () => {
    expect(parseHealth('  tunnel=true   knock=false\terr=x  ')).toEqual({ knock: false, tunnel: true, err: 'x' });
  });

  it('缺 err 字段 → 无错误', () => {
    expect(parseHealth('knock=true tunnel=true')).toEqual({ knock: true, tunnel: true, err: '' });
  });

  it('未知键不影响解析', () => {
    expect(parseHealth(SLOG + 'gateway=gw-a knock=true tunnel=true rtt=3ms err=-')).toEqual({ knock: true, tunnel: true, err: '' });
  });

  it('slog 引号包起来的 err 会被还原，内部转义引号也还原', () => {
    const h = parseHealth(SLOG + 'knock=true tunnel=false err="取敲门令牌失败：Get \\"http://c/knock-token\\": dial tcp: refused"');
    expect(h?.err).toBe('取敲门令牌失败：Get "http://c/knock-token": dial tcp: refused');
  });

  it('未加引号的中文 err 原样保留', () => {
    expect(parseHealth('knock=true tunnel=false err=隧道拨号失败')?.err).toBe('隧道拨号失败');
  });

  it('strconv.Quote 的全部转义都还原：\\r \\n \\t \\xNN \\uNNNN \\\\（改造前 \\r 与 \\xNN 字面量原样上屏）', () => {
    // Windows 侧系统错误文本常带 \r\n；控制字符（如 ESC）被 Quote 成 \x1b；不可打印的非 ASCII 码点成 \uNNNN。
    const h = parseHealth(SLOG + 'knock=true tunnel=false err="SPA 拨号失败：line1\\r\\nline2\\tesc\\x1bnbsp\\u00a0back\\\\slash"');
    expect(h?.err).toBe('SPA 拨号失败：line1\r\nline2\tesc\x1bnbsp\u00a0back\\slash');
  });

  it('认不出的转义序列（\\U、\\a）不猜，原样保留', () => {
    expect(parseHealth('knock=true tunnel=false err="a\\U0001F600b\\ac"')?.err).toBe('a\\U0001F600b\\ac');
  });

  it('缺 knock 或 tunnel、非 true/false、空/null/undefined → null（让调用方回落，不猜）', () => {
    expect(parseHealth('knock=true err=-')).toBeNull();
    expect(parseHealth('tunnel=true err=-')).toBeNull();
    expect(parseHealth('knock=yes tunnel=no')).toBeNull();
    expect(parseHealth('')).toBeNull();
    expect(parseHealth(null)).toBeNull();
    expect(parseHealth(undefined)).toBeNull();
  });

  // 键名必须整词匹配：两条各自成立，合成一条断言时任一侧的正则松掉都会被另一侧的 null 掩住。
  it('整词匹配：reknock=true 不算 knock（tunnel 在、knock 缺 → null）', () => {
    expect(parseHealth('reknock=true tunnel=false')).toBeNull();
  });

  it('整词匹配：retunnel=false 不算 tunnel（knock 在、tunnel 缺 → null）', () => {
    expect(parseHealth('knock=true retunnel=false')).toBeNull();
  });
});

/** 一份运行中的 TunView，只关心 running / error / tunnelUsed 三项。 */
function view(over: Partial<TunView>): TunView {
  return {
    ...parseTunStatus(raw({ health: SLOG + 'knock=true tunnel=false err=-' })),
    ...over
  };
}

const PIN_ERR = '网关证书指纹不匹配（疑似中间人）：期望 abc 实得 def';

describe('nextDataplaneNotice · 隧道类失败不被保活敲门擦掉', () => {
  it('classifyFail：Go 侧两个固定前缀是 knock 类，其余（含认不出的）一律 tunnel 类', () => {
    expect(classifyFail('取敲门令牌失败：dial tcp: refused')).toBe('knock');
    expect(classifyFail('SPA 拨号失败：network is unreachable')).toBe('knock');
    expect(classifyFail(PIN_ERR)).toBe('tunnel');
    expect(classifyFail('隧道拨号失败（未敲门成功/网关隐身?）')).toBe('tunnel');
    expect(classifyFail('完全不认识的一句话')).toBe('tunnel');
  });

  it('运行中出现失败 → 生成提示，带类别、时刻与失败当时的 tunnel 位', () => {
    const n = nextDataplaneNotice(null, view({ error: PIN_ERR, tunnelUsed: false }), 1000);
    expect(n).toEqual({ text: PIN_ERR, at: 1000, cls: 'tunnel', tunnelUsedAtFail: false });
  });

  it('★隧道类失败：15s 后保活敲门把 err 擦成空 → 提示**粘住**（同一行分不出被谁清掉）', () => {
    // 复核发现：Go 侧 markKnock 不分类别清 lastErr，按 err 直接渲染时中间人告警只闪 ≤15s。
    const n0 = nextDataplaneNotice(null, view({ error: PIN_ERR, tunnelUsed: false }), 1000);
    const n1 = nextDataplaneNotice(n0, view({ error: '', tunnelUsed: false }), 16000);
    expect(n1).toBe(n0);
    // 之后每一轮轮询都保持
    expect(nextDataplaneNotice(n1, view({ error: '', tunnelUsed: false }), 60000)).toBe(n0);
  });

  it('隧道类失败后观察到 tunnel 位 false→true = 真拨通了 → 收起', () => {
    const n0 = nextDataplaneNotice(null, view({ error: PIN_ERR, tunnelUsed: false }), 1000);
    expect(nextDataplaneNotice(n0, view({ error: '', tunnelUsed: true }), 5000)).toBeNull();
  });

  it('失败当时 tunnel 已是 true（此前拨通过）→ 之后 err 清空本机判不了 → 粘住等用户关', () => {
    const n0 = nextDataplaneNotice(null, view({ error: PIN_ERR, tunnelUsed: true }), 1000);
    expect(nextDataplaneNotice(n0, view({ error: '', tunnelUsed: true }), 5000)).toBe(n0);
  });

  it('knock 类失败：err 清空就是一次成功敲门 → 真恢复 → 收起', () => {
    const n0 = nextDataplaneNotice(null, view({ error: '取敲门令牌失败：dial tcp 127.0.0.1:8090: connection refused', tunnelUsed: false }), 1000);
    expect(n0?.cls).toBe('knock');
    expect(nextDataplaneNotice(n0, view({ error: '', tunnelUsed: false }), 16000)).toBeNull();
  });

  it('同一失败再次出现 → 刷新时刻（提示写的是「最近一次」）；换了失败 → 换文本', () => {
    const n0 = nextDataplaneNotice(null, view({ error: PIN_ERR }), 1000);
    const n1 = nextDataplaneNotice(n0, view({ error: PIN_ERR }), 30000);
    expect(n1).toMatchObject({ text: PIN_ERR, at: 30000 });
    const n2 = nextDataplaneNotice(n1, view({ error: '隧道拨号失败（未敲门成功/网关隐身?）' }), 31000);
    expect(n2?.text).toContain('隧道拨号失败');
  });

  it('进程未运行 → null（退出后的原因走「数据面退出」那条路，不归提示条）', () => {
    const prev: DataplaneNotice = { text: PIN_ERR, at: 1, cls: 'tunnel', tunnelUsedAtFail: false };
    expect(nextDataplaneNotice(prev, view({ running: false, error: PIN_ERR }), 2)).toBeNull();
  });

  it('无失败且无历史 → null', () => {
    expect(nextDataplaneNotice(null, view({}), 1)).toBeNull();
  });
});
