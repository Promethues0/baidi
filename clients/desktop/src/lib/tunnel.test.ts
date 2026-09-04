/**
 * 接入态解析单测：判据必须来自数据面健康行，不能是两行启动日志。
 *
 * 背景（提交 796ac0f 只做了 Go/Rust 半边）：dataplane.logHealth 打健康行、main.rs 捞进
 * TunStatus.health，而 tunnel.ts 的 parseHealth 定义后零调用、ready 仍判 /数据面就绪/、
 * error 仍是 `!running && …`——于是指纹钉扎失败（疑似中间人）/ 敲门被拒 / 隧道拨不通
 * 三类故障在接入页一律绿色「已接入」，App.vue 的 session.connected 也跟着放行。
 * 这批用例把 TS 这半边钉住；改回只用旧正则，前三组必须变红。
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';

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
// 跨轨契约用例要摆一份三落点剖面：store 已被上面的 vi.mock 换成最小桩，这里拿到的就是那个对象。
import { profile } from './store';
import type { ProfileGateway } from './api';

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
    expect(parseHealth(SLOG + 'knock=true tunnel=false err=-')).toEqual({ knock: true, tunnel: false, terr: null, err: '' });
  });

  it('多余空白与字段乱序', () => {
    expect(parseHealth('  tunnel=true   knock=false\terr=x  ')).toEqual({ knock: false, tunnel: true, terr: null, err: 'x' });
  });

  it('缺 err 字段 → 无错误', () => {
    expect(parseHealth('knock=true tunnel=true')).toEqual({ knock: true, tunnel: true, terr: null, err: '' });
  });

  it('未知键不影响解析', () => {
    expect(parseHealth(SLOG + 'gateway=gw-a knock=true tunnel=true rtt=3ms err=-')).toEqual({ knock: true, tunnel: true, terr: null, err: '' });
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

describe('parseHealth · Go 侧 wave10 起多带的 terr= 键', () => {
  // Go 侧（gateway/internal/dataplane/dataplane.go logHealth）从 wave10 起把失败按 knock/tunnel 分记，
  // 健康行形如 `knock=true tunnel=false terr=- err="…"`，terr 刻意排在 err 之前。
  // TS 侧现已消费 terr（三态：缺席=null 不可判定 / '' 无失败 / 非空 仍挂着），
  // 且 err 的取值绝不能被 terr= 里的文本污染——这里把两件事都钉住。
  it('terr= 排在 err= 前：err 仍取 err= 之后的自由文本，且还原 Go 引号', () => {
    const h = parseHealth('knock=true tunnel=false terr=- err="SPA 拨号失败：网络不可达"');
    expect(h).toEqual({ knock: true, tunnel: false, terr: '', err: 'SPA 拨号失败：网络不可达' });
  });
  it('terr= 有值而 err=- 时：err 为空（不把隧道类历史失败当成当前错误）', () => {
    const h = parseHealth('knock=true tunnel=true terr=网关证书指纹不匹配 err=-');
    expect(h).toEqual({ knock: true, tunnel: true, terr: '网关证书指纹不匹配', err: '' });
  });
  it('terr= 带引号含空格也不影响 err 的定位', () => {
    const h = parseHealth('knock=true tunnel=false terr="拨号超时 5s" err="取敲门令牌失败：403"');
    expect(h?.err).toBe('取敲门令牌失败：403');
    expect(h?.terr).toBe('拨号超时 5s');
  });

  it('terr= 缺席 → terr 为 null（不可判定），不是空字符串', () => {
    // 老数据面（wave10 之前）不打这个键。压成 '' 会让上层把「不可判定」读成「隧道类没有失败」，
    // 于是每 15s 宣告一次隧道已恢复——把粘性提示条存在的意义抹掉，方向与 fail-closed 相反。
    expect(parseHealth(SLOG + 'knock=true tunnel=false err=-')?.terr).toBeNull();
  });
});

describe('parseHealth · 取值按引号语义分词（值里的 key= 子串不得污染邻键）', () => {
  // ★这一组是主防线。改造前 err 用 `/(?:^|\s)err=(.*)$/` 取「第一个 ` err=` 到行尾」，
  // 完全不理会 slog 的引号语义：只要 terr 的值里出现过一个 ` err=` 子串（后端错误原文里很常见），
  // 正则就命中引号**内部**那处，err 被解析成一段跨了两个键的拼接文本，而它看起来仍像一条正常错误。
  it('terr 的值里含 " err=" 子串 → 不污染 err（改造前 err 会被解析成 terr 的尾巴）', () => {
    const line = SLOG + 'knock=true tunnel=false terr="拨号失败：upstream said err=connection refused" err="真正的当前错误"';
    const h = parseHealth(line);
    expect(h?.err).toBe('真正的当前错误');
    expect(h?.terr).toBe('拨号失败：upstream said err=connection refused');
  });

  it('err 带引号含空格：整段还原，且不吞掉后面的键', () => {
    const h = parseHealth(SLOG + 'knock=true tunnel=false terr=- err="SPA 拨号失败：dial udp 10.0.0.1:18201 i/o timeout" rtt=3ms');
    expect(h?.err).toBe('SPA 拨号失败：dial udp 10.0.0.1:18201 i/o timeout');
    expect(h?.terr).toBe('');
  });

  it('terr 带引号含空格：整段还原，err 独立取值', () => {
    const h = parseHealth(SLOG + 'knock=true tunnel=true terr="网关证书指纹不匹配（疑似中间人）：期望 abc 实得 def" err=-');
    expect(h?.terr).toBe('网关证书指纹不匹配（疑似中间人）：期望 abc 实得 def');
    expect(h?.err).toBe('');
  });

  it('terr 的值里含 " knock=false" 子串 → 不污染 knock（错在这一侧的是 ready，不只是文案）', () => {
    // ★键序刻意打乱把 terr 排在 knock 之前：parseHealth 的契约明写「字段顺序不影响」，
    // 而按行内第一个匹配取值的正则实现在这一序下会命中引号**内部**那个 knock=false，
    // 把一台健康的终端判成「没敲门成功」→ ready 恒 false → 应用页「访问」闸锁死。
    // 真实 Go 健康行 knock 排在最前，正好把这个洞盖住，故必须用乱序才测得出来。
    const h = parseHealth(SLOG + 'terr="握手失败：peer said knock=false" tunnel=false knock=true err=-');
    expect(h?.knock).toBe(true);
    expect(h?.terr).toBe('握手失败：peer said knock=false');
    expect(h?.err).toBe('');
  });

  it('引号内的转义引号不算闭合：err 不会被从值中间截断', () => {
    const h = parseHealth(SLOG + 'knock=true tunnel=false terr="Get \\"http://gw/ err=1\\" 失败" err="当前错误"');
    expect(h?.terr).toBe('Get "http://gw/ err=1" 失败');
    expect(h?.err).toBe('当前错误');
  });
});

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

describe('nextDataplaneNotice · terr 可判定时按它判隧道类真恢复（比 tunnel 位准）', () => {
  it('terr=- 且 tunnel 早已为 true → 提示条清掉（改前这一格永远只能靠用户手动关）', () => {
    // tunnel 是「**曾**拨通」的粘性位：失败当时它已是 true 时它永远不会再翻转，
    // 改前的 false→true 判据在这一格完全失效。terr 由 markTunnel（真拨通）清空，没有这个盲区。
    const n0 = nextDataplaneNotice(null, view({ error: PIN_ERR, tunnelUsed: true, tunnelErr: PIN_ERR }), 1000);
    expect(n0?.text).toBe(PIN_ERR);
    expect(nextDataplaneNotice(n0, view({ error: '', tunnelUsed: true, tunnelErr: '' }), 20000)).toBeNull();
  });

  it('err 被保活敲门清空但 terr 仍非空 → 粘住（这正是 terr 存在的理由）', () => {
    const n0 = nextDataplaneNotice(null, view({ error: PIN_ERR, tunnelUsed: true, tunnelErr: PIN_ERR }), 1000);
    expect(nextDataplaneNotice(n0, view({ error: '', tunnelUsed: true, tunnelErr: PIN_ERR }), 16000)).toBe(n0);
  });

  it('terr 非空时 tunnel 位翻转也不清（terr 说了算，不回落到旧判据）', () => {
    const n0 = nextDataplaneNotice(null, view({ error: PIN_ERR, tunnelUsed: false, tunnelErr: PIN_ERR }), 1000);
    expect(nextDataplaneNotice(n0, view({ error: '', tunnelUsed: true, tunnelErr: PIN_ERR }), 5000)).toBe(n0);
  });

  it('knock 类不受影响：err 清空即真恢复，与 terr 无关', () => {
    const n0 = nextDataplaneNotice(null, view({ error: '取敲门令牌失败：403', tunnelUsed: false, tunnelErr: PIN_ERR }), 1000);
    expect(n0?.cls).toBe('knock');
    expect(nextDataplaneNotice(n0, view({ error: '', tunnelUsed: false, tunnelErr: PIN_ERR }), 16000)).toBeNull();
  });

  it('健康行无 terr 键（老数据面）→ 行为与接 terr 之前逐字一致：只看 tunnel 位翻转', () => {
    // 同时是「缺席不得按空处理」的反例守卫：把 null 当成 '' 的话，下面第二次调用会返回 null。
    const stale = view({ error: PIN_ERR, tunnelUsed: true });
    expect(stale.tunnelErr).toBeNull();
    const n0 = nextDataplaneNotice(null, stale, 1000);
    expect(nextDataplaneNotice(n0, view({ error: '', tunnelUsed: true }), 60000)).toBe(n0);
    // false→true 仍是老判据下唯一的自动收起条件
    const n1 = nextDataplaneNotice(null, view({ error: PIN_ERR, tunnelUsed: false }), 1000);
    expect(nextDataplaneNotice(n1, view({ error: '', tunnelUsed: true }), 5000)).toBeNull();
  });
});

/* ────────────────────────────────────────────────────────────────────────────
 * 跨轨契约：Go 数据面打的落点状态行 ⇄ 这边的 parseEndpoint。
 *
 * ★为什么必须读 Go 侧的 testdata 而不是自己手抄一行：
 *   `endpoint=<i>/<n> id= addr= reason=` 四个键是两条轨道之间唯一的接头，两边的注释都
 *   写着「改键名要同步改那边」，但此前**没有任何用例把两侧拴住**——Go 侧的 failover_test.go
 *   一次都没断言过键名，这边喂的是手写示例行。实测变异：把 Go 侧的 "endpoint" 改成 "ep"，
 *   `go test ./internal/dataplane/` 全绿、`npm test` 56 passed，两轨都不红。
 *   现场后果：下面这些正则一条都不匹配 → 静默回落成「第 1 个落点 / pin = 首选落点的指纹」。
 *   故障转移到第 2 台之后，接入页仍显示第 1 台的 id 与地址，并按第 1 台的指纹渲染
 *   「证书钉扎」——**未钉扎的运行中隧道被显示成已钉扎**，而隧道是通的、页面是「已接入」的。
 *
 * 样本行由 gateway/internal/dataplane/failover_test.go 捕获 logCurrent 的**真实输出**
 * 落盘，两边读同一份文件：任一侧改键名/改形制，另一侧当场红。
 * ────────────────────────────────────────────────────────────────────────── */
const ENDPOINT_GOLDEN = readFileSync(
  new URL('../../../../gateway/internal/dataplane/testdata/endpoint_log.txt', import.meta.url),
  'utf8'
).trim();

/** 与样本行同一套落点：第 2 台（gw-b）刻意没有指纹——切过去就是一次真实降级。 */
function gw(id: string, host: string, tunnelPin: string): ProfileGateway {
  return { id, host, spaPort: '18201', proxyPort: '18443', tunnelPin, online: true };
}
function useThreeGateways(): void {
  const gws = [gw('gw-a', '10.0.0.1', 'aa11'), gw('gw-b', '10.0.0.2', ''), gw('gw-c', '10.0.0.3', 'cc33')];
  profile.data = {
    generatedAt: '2026-09-04T10:00:00+08:00', user: 'u',
    gateway: gws[0], gateways: gws,
    vipCidr: '10.99.0.0/24', tunIp: '10.99.0.2',
    routes: ['10.99.0.0/24'], apps: [], resmap: {}
  };
}

describe('parseEndpoint · 跨轨契约（喂 Go 侧 logCurrent 的真实输出）', () => {
  afterEach(() => { profile.data = null; });

  it('样本行本身就是数据面的真实形制（键齐、单行）', () => {
    expect(ENDPOINT_GOLDEN.split('\n')).toHaveLength(1);
    expect(ENDPOINT_GOLDEN).toMatch(/endpoint=\d+\/\d+/);
  });

  it('四个键都解析得出来：第几落点 / id / 地址 / 切换原因', () => {
    useThreeGateways();
    const v = parseTunStatus(raw({ endpoint: ENDPOINT_GOLDEN, health: SLOG + 'knock=true tunnel=true err=""' }));
    expect(v.endpointIndex).toBe(2);
    expect(v.endpointTotal).toBe(3);
    expect(v.endpointId).toBe('gw-b');
    // 网关地址必须是**此刻真正在用的那个落点**，不是首选落点
    expect(v.gateway).toBe('10.0.0.2:18443');
    // reason 带空格 → Go 侧 slog 会加引号，这里要脱引号后拿到完整原文
    expect(v.endpointReason).toBe('首选落点拨号失败：dial tcp 10.0.0.1:18443: i/o timeout');
  });

  it('钉扎按**当前落点**算：切到没上报指纹的备用网关后不得再显示「证书钉扎」', () => {
    useThreeGateways();
    // 没有落点行时是首选落点 gw-a（有指纹）→ 已钉扎
    const first = parseTunStatus(raw({ health: SLOG + 'knock=true tunnel=true err=""' }));
    expect(first.cipher).toContain('证书钉扎');
    // 切到 gw-b（无指纹）后必须翻成「未钉扎」——这正是本契约断掉时被掩盖掉的那件事
    const after = parseTunStatus(raw({ endpoint: ENDPOINT_GOLDEN, health: SLOG + 'knock=true tunnel=true err=""' }));
    expect(after.cipher).toContain('未钉扎');
  });
});
