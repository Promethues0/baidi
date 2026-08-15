//! 终端侧真实探测（自助诊断的执行方，wave7 行动 10）。
//!
//! 替换掉 Diagnostics.vue 里那两个恒 `ok` 的假检查项。假绿诊断比没有诊断更糟：
//! 它替坏链路背书，而本项目最难查的失败形态恰恰是「显示已接入、实际不通」。
//!
//! ★这里只做**探测**，不做判定。判定（什么算正常、什么算故障）全在前端
//! `lib/diagnose.ts` 的纯函数里——理由是判定规则里有几条反直觉的语义翻转
//! （未接入时连不上是**正确行为**），那种逻辑必须能被单测钉住，而 Tauri 命令
//! 依赖真实网络，测不了。
//!
//! 两条探针共同的纪律：
//!   - **一个字节都不写**。TLS/TLCP 都是 client-speaks-first，写了就触发真握手：
//!     已敲门时会收到 ServerHello（把干净的三分判据搅成四分），未敲门时内核 Close
//!     会发 RST 而不是 FIN（「立即 EOF」这条判据随机塌掉）。
//!   - 读超时必须**远小于**网关自己的握手超时（proxy.go 给了 8s）。否则已敲门的连接
//!     也会等来 EOF，与未敲门完全同形，判据整个失效。

use serde::Serialize;
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

/// TCP 探测结果。`kind` 是给判定层的**机读分类**，不是给人看的文案。
#[derive(Debug, Serialize, PartialEq)]
pub struct TcpProbe {
    /// closed-immediately | held-open | server-spoke | refused | timeout | error
    pub kind: String,
    pub ms: u64,
    /// server-spoke 时的首字节十六进制（诊断"对面不是白帝隧道口"用）。
    #[serde(skip_serializing_if = "String::is_empty")]
    pub head: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub err: String,
}

impl TcpProbe {
    fn of(kind: &str, ms: u64) -> Self {
        TcpProbe { kind: kind.into(), ms, head: String::new(), err: String::new() }
    }
    fn failed(kind: &str, ms: u64, err: String) -> Self {
        TcpProbe { kind: kind.into(), ms, head: String::new(), err }
    }
}

/// classify_io 把 connect/read 的 io 错误归成机读类别 + 中文原因。
///
/// 分开 refused 与 timeout 不是洁癖：**内核态隐身（pf/nft DROP）不回 RST**，
/// 表现为 timeout；而 refused 说明端口上没有监听、包却到得了那台机器。
/// 两者指向完全不同的排查动作。
fn classify_io(e: &std::io::Error) -> (&'static str, String) {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => ("refused", "对端拒绝连接（端口没有服务在监听）".into()),
        TimedOut | WouldBlock => ("timeout", "连接超时（无任何回应）".into()),
        HostUnreachable | NetworkUnreachable => ("error", "网络不可达（路由不通）".into()),
        ConnectionReset => ("closed-immediately", "连接被重置".into()),
        _ => ("error", e.to_string()),
    }
}

/// probe_tcp_inner 同步实现（命令层用 spawn_blocking 包起来）。
///
/// 判据是「立刻 EOF」还是「挂住」：
///   - 读到 0 字节 = 对端 FIN = 连上了但被立即断开（白帝语义：未敲门被网关踢掉）；
///   - 读超时 = 连接被保持着（白帝语义：网关正在等 ClientHello，即身份已放行）；
///   - 读到字节 = 对面先说话了 = 那不是白帝隧道口（TLS/TLCP 服务端不会先发言）。
pub fn probe_tcp_inner(host: &str, port: u16, timeout_ms: u64, read_ms: u64) -> TcpProbe {
    let start = Instant::now();
    let elapsed = |s: &Instant| s.elapsed().as_millis() as u64;

    let addr = match (host, port).to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return TcpProbe::failed("error", elapsed(&start), format!("{host} 解析不出任何地址")),
        },
        Err(e) => return TcpProbe::failed("error", elapsed(&start), format!("{host} 域名解析失败：{e}")),
    };

    let mut s = match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
        Ok(s) => s,
        Err(e) => {
            let (kind, why) = classify_io(&e);
            return TcpProbe::failed(kind, elapsed(&start), why);
        }
    };
    let connect_ms = elapsed(&start);

    if s.set_read_timeout(Some(Duration::from_millis(read_ms))).is_err() {
        return TcpProbe::failed("error", connect_ms, "无法设置读超时".into());
    }
    let mut buf = [0u8; 1];
    match s.read(&mut buf) {
        Ok(0) => TcpProbe::of("closed-immediately", connect_ms),
        Ok(_) => {
            let mut p = TcpProbe::of("server-spoke", connect_ms);
            p.head = format!("{:02x}", buf[0]);
            p
        }
        Err(e) => {
            let (kind, why) = classify_io(&e);
            // 读超时是**期望内**的正常形态（连接被保持），不是错误。
            if kind == "timeout" {
                TcpProbe::of("held-open", connect_ms)
            } else {
                TcpProbe::failed(kind, connect_ms, why)
            }
        }
    }
}

/// DNS 探测结果。
#[derive(Debug, Serialize, PartialEq)]
pub struct DnsProbe {
    /// answered | refused | nxdomain | empty | timeout | error
    pub kind: String,
    pub ms: u64,
    /// 命中的第一条 A 记录（answered 时有值）。
    #[serde(skip_serializing_if = "String::is_empty")]
    pub addr: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub err: String,
}

impl DnsProbe {
    fn of(kind: &str, ms: u64) -> Self {
        DnsProbe { kind: kind.into(), ms, addr: String::new(), err: String::new() }
    }
    fn failed(err: String, ms: u64) -> Self {
        DnsProbe { kind: "error".into(), ms, addr: String::new(), err }
    }
}

/// build_query 组装一个最小 A 查询报文（RFC 1035）。
///
/// 手写而不引 crate：本仓库自研 DNS 服务端已在 gateway/internal/dataplane/dns.go，
/// 客户端这边只需要发一条查询、认得 RCODE 与第一条 A 记录，几十行的事。
pub fn build_query(id: u16, name: &str) -> Result<Vec<u8>, String> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // 标准查询 + RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR COUNT
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            return Err(format!("域名 {name} 含空标签"));
        }
        if label.len() > 63 {
            return Err(format!("域名 {name} 的标签超过 63 字节"));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // 根标签
    q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    Ok(q)
}

/// skip_name 跳过一个（可能被指针压缩的）NAME 字段，返回其后的偏移。
///
/// 越界一律回 Err 而不是 panic：应答来自网络，畸形报文是常态而非意外。
fn skip_name(buf: &[u8], mut i: usize) -> Result<usize, String> {
    let mut hops = 0;
    loop {
        let b = *buf.get(i).ok_or("应答截断（NAME 越界）")?;
        if b & 0xC0 == 0xC0 {
            // 压缩指针：占 2 字节，后面直接是记录字段，不必真的跟过去
            buf.get(i + 1).ok_or("应答截断（压缩指针越界）")?;
            return Ok(i + 2);
        }
        if b == 0 {
            return Ok(i + 1);
        }
        i += 1 + b as usize;
        hops += 1;
        if hops > 128 {
            return Err("应答的 NAME 标签过多（疑似构造报文）".into());
        }
    }
}

/// parse_answer 解析应答：认 RCODE，并在 answer 段里找第一条 A 记录。
///
/// ★RCODE 必须分辨：白帝隧道内解析器对**未知域名回 REFUSED**（刻意不做递归转发，
/// 见 dataplane/dns.go），那是正常行为而不是故障；系统解析器则会回 NXDOMAIN 或真去递归。
/// 判定层正是靠这个差别确认"答话的到底是不是隧道内那个解析器"。
pub fn parse_answer(buf: &[u8], want_id: u16) -> Result<(String, String), String> {
    if buf.len() < 12 {
        return Err("应答过短（不足 12 字节头部）".into());
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != want_id {
        return Err("应答的事务 id 与查询不符（疑似串包）".into());
    }
    let rcode = buf[3] & 0x0F;
    match rcode {
        0 => {}
        3 => return Ok(("nxdomain".into(), String::new())),
        5 => return Ok(("refused".into(), String::new())),
        n => return Err(format!("解析器返回 RCODE={n}")),
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if an == 0 {
        // NOERROR + 0 条应答：名字存在但没有该类型的记录（白帝对 AAAA 命中就是这样答的）
        return Ok(("empty".into(), String::new()));
    }
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(buf, i)?;
        i = i.checked_add(4).ok_or("应答截断（question 越界）")?;
    }
    for _ in 0..an {
        i = skip_name(buf, i)?;
        let end = i.checked_add(10).ok_or("应答截断（记录头越界）")?;
        if end > buf.len() {
            return Err("应答截断（记录头越界）".into());
        }
        let rtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let rdlen = u16::from_be_bytes([buf[i + 8], buf[i + 9]]) as usize;
        let rdata = end.checked_add(rdlen).ok_or("应答截断（rdata 越界）")?;
        if rdata > buf.len() {
            return Err("应答截断（rdata 越界）".into());
        }
        if rtype == 1 && rdlen == 4 {
            let a = &buf[end..rdata];
            return Ok(("answered".into(), format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])));
        }
        i = rdata;
    }
    Ok(("empty".into(), String::new()))
}

/// probe_dns_inner 向指定解析器发一次真实 A 查询。
pub fn probe_dns_inner(server: &str, port: u16, name: &str, timeout_ms: u64) -> DnsProbe {
    let start = Instant::now();
    let ms = |s: &Instant| s.elapsed().as_millis() as u64;

    // 事务 id 用时间低位：这条探针不参与安全判定，无需密码学随机；
    // 但仍要校验应答 id 相符，防的是同一 socket 上串到别的包。
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
        & 0xFFFF) as u16;
    let q = match build_query(id, name) {
        Ok(q) => q,
        Err(e) => return DnsProbe::failed(e, ms(&start)),
    };
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => return DnsProbe::failed(format!("本地 UDP 端口打不开：{e}"), ms(&start)),
    };
    let dur = Duration::from_millis(timeout_ms);
    if sock.set_read_timeout(Some(dur)).is_err() {
        return DnsProbe::failed("无法设置读超时".into(), ms(&start));
    }
    if let Err(e) = sock.send_to(&q, (server, port)) {
        // 隧道不在时这里就会失败（VIP 无路由），是最常见的正常形态之一
        return DnsProbe::failed(format!("发不出查询（解析器 {server}:{port} 无路由？）：{e}"), ms(&start));
    }
    let mut buf = [0u8; 1500];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => match parse_answer(&buf[..n], id) {
            Ok((kind, addr)) => {
                let mut p = DnsProbe::of(&kind, ms(&start));
                p.addr = addr;
                p
            }
            Err(e) => DnsProbe::failed(e, ms(&start)),
        },
        Err(e) => {
            if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) {
                DnsProbe::of("timeout", ms(&start))
            } else {
                DnsProbe::failed(e.to_string(), ms(&start))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn tcp_立即断开与保持连接可区分() {
        // 立即断开：accept 后直接 drop（对端收到 FIN）——白帝未敲门时的形态
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ln.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in ln.incoming().take(1) {
                drop(c.unwrap());
            }
        });
        let p = probe_tcp_inner("127.0.0.1", addr.port(), 2000, 800);
        assert_eq!(p.kind, "closed-immediately", "accept 后立即关应判为立即断开");

        // 保持连接：accept 后不说话也不关——白帝已敲门、正在等 ClientHello 的形态
        let ln2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = ln2.local_addr().unwrap();
        let held = std::thread::spawn(move || {
            let c = ln2.incoming().next().unwrap().unwrap();
            std::thread::sleep(Duration::from_millis(1200));
            drop(c);
        });
        let p2 = probe_tcp_inner("127.0.0.1", addr2.port(), 2000, 400);
        assert_eq!(p2.kind, "held-open", "对端保持连接应判为 held-open");
        let _ = held.join();
    }

    #[test]
    fn tcp_对端先说话说明不是白帝隧道口() {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ln.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut c = ln.incoming().next().unwrap().unwrap();
            let _ = c.write_all(b"SSH-2.0-OpenSSH\r\n");
            std::thread::sleep(Duration::from_millis(300));
        });
        let p = probe_tcp_inner("127.0.0.1", addr.port(), 2000, 800);
        assert_eq!(p.kind, "server-spoke", "TLS/TLCP 服务端不会先说话，先说话的不是隧道口");
        assert_eq!(p.head, "53", "首字节应是 'S'(0x53)");
    }

    #[test]
    fn tcp_无人监听的端口拒绝或超时() {
        // 开一个监听立刻关掉，拿到一个必然没人听的端口
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ln.local_addr().unwrap().port();
        drop(ln);
        let p = probe_tcp_inner("127.0.0.1", port, 1000, 500);
        assert!(
            p.kind == "refused" || p.kind == "timeout",
            "无人监听应为拒绝或超时，实得 {}",
            p.kind
        );
        assert!(!p.err.is_empty(), "失败必须带中文原因");
    }

    #[test]
    fn tcp_域名解析失败有明确原因() {
        let p = probe_tcp_inner("this-host-does-not-exist.invalid", 443, 800, 400);
        assert_eq!(p.kind, "error");
        assert!(p.err.contains("解析"), "实得 {}", p.err);
    }

    #[test]
    fn dns_查询报文按_rfc1035_编码() {
        let q = build_query(0xBEEF, "oa.corp.example").unwrap();
        assert_eq!(&q[0..2], &[0xBE, 0xEF], "事务 id");
        assert_eq!(&q[2..4], &[0x01, 0x00], "标准查询 + RD");
        assert_eq!(&q[4..6], &[0x00, 0x01], "QDCOUNT=1");
        // QNAME：2oa4corp7example0
        assert_eq!(q[12], 2);
        assert_eq!(&q[13..15], b"oa");
        assert_eq!(q[15], 4);
        assert_eq!(&q[16..20], b"corp");
        assert_eq!(&q[q.len() - 5..], &[0x00, 0x00, 0x01, 0x00, 0x01], "根标签 + QTYPE=A + QCLASS=IN");
        // 尾点应被吃掉，编码与不带点一致
        assert_eq!(build_query(1, "a.b.").unwrap(), build_query(1, "a.b").unwrap());
        assert!(build_query(1, "a..b").is_err(), "空标签应被拒");
    }

    /// 造一个应答：头部 + question + 一条 A 记录（NAME 用压缩指针，真实解析器都这么发）。
    fn answer_with_a(id: u16, ip: [u8; 4]) -> Vec<u8> {
        let mut b = build_query(id, "oa.corp").unwrap();
        b[2] = 0x81; // QR=1 + RD
        b[3] = 0x80; // RA, RCODE=0
        b[6] = 0x00;
        b[7] = 0x01; // ANCOUNT=1
        b.extend_from_slice(&[0xC0, 0x0C]); // 指向 offset 12 的 NAME
        b.extend_from_slice(&1u16.to_be_bytes()); // TYPE=A
        b.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
        b.extend_from_slice(&60u32.to_be_bytes()); // TTL
        b.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        b.extend_from_slice(&ip);
        b
    }

    #[test]
    fn dns_应答解析认得_a_记录与三种_rcode() {
        let (kind, addr) = parse_answer(&answer_with_a(7, [10, 99, 0, 8]), 7).unwrap();
        assert_eq!((kind.as_str(), addr.as_str()), ("answered", "10.99.0.8"));

        // REFUSED：白帝隧道内解析器对未知域名的**正常**答复
        let mut r = build_query(9, "x.y").unwrap();
        r[2] = 0x81;
        r[3] = 0x85; // RCODE=5
        assert_eq!(parse_answer(&r, 9).unwrap().0, "refused");

        // NXDOMAIN：系统解析器的形态，与上面必须分得开
        let mut nx = build_query(9, "x.y").unwrap();
        nx[2] = 0x81;
        nx[3] = 0x83; // RCODE=3
        assert_eq!(parse_answer(&nx, 9).unwrap().0, "nxdomain");

        // NOERROR + 0 answer（白帝对 AAAA 命中就是这么答的）
        let mut e = build_query(9, "x.y").unwrap();
        e[2] = 0x81;
        e[3] = 0x80;
        assert_eq!(parse_answer(&e, 9).unwrap().0, "empty");
    }

    #[test]
    fn dns_畸形应答一律回错不panic() {
        assert!(parse_answer(&[], 1).is_err(), "空应答");
        assert!(parse_answer(&[0; 8], 1).is_err(), "头部不全");
        // id 不符（串包）
        assert!(parse_answer(&answer_with_a(1, [1, 2, 3, 4]), 2).is_err());
        // 声称有 1 条应答却在记录头处截断
        let mut trunc = answer_with_a(3, [1, 2, 3, 4]);
        trunc.truncate(trunc.len() - 8);
        assert!(parse_answer(&trunc, 3).is_err(), "截断的 rdata 必须报错而不是越界读");
        // rdlen 撒谎（声称很长）
        let mut lie = answer_with_a(4, [1, 2, 3, 4]);
        let n = lie.len();
        lie[n - 6] = 0xFF;
        lie[n - 5] = 0xFF;
        assert!(parse_answer(&lie, 4).is_err(), "rdlen 越界必须报错");
    }

    #[test]
    fn dns_真实回环解析器可被探到() {
        // 起一个只会回 REFUSED 的最小 UDP 解析器，验证端到端链路（含超时设置）
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = s.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((n, from)) = s.recv_from(&mut buf) {
                let mut r = buf[..n].to_vec();
                r[2] = 0x81;
                r[3] = 0x85; // REFUSED
                let _ = s.send_to(&r, from);
            }
        });
        let p = probe_dns_inner("127.0.0.1", addr.port(), "nope.invalid", 1500);
        assert_eq!(p.kind, "refused", "应认出 REFUSED（白帝解析器对未知域名的正常答复）");

        // 没人监听的 UDP 口：超时（UDP 无连接，通常不会立刻报错）
        let dead = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dport = dead.local_addr().unwrap().port();
        drop(dead);
        let p2 = probe_dns_inner("127.0.0.1", dport, "x.invalid", 300);
        assert!(p2.kind == "timeout" || p2.kind == "error", "实得 {}", p2.kind);
    }
}

#[cfg(test)]
mod realgw {
    /// 真机验证钩子：对着一个**真实的 baidi-gateway** 隧道口跑一次探测。
    ///
    /// 平时不跑（没设环境变量就直接返回）；要用时：
    ///   BAIDI_PROBE_REAL_GW=127.0.0.1:18943 BAIDI_PROBE_EXPECT=closed-immediately cargo test realgw
    ///
    /// ★这条钩子存在的意义：单测里的 TcpListener 只能模拟"立即断开/保持连接"两种**形态**，
    /// 证明不了真网关就是这么表现的。2026-08-15 用真 baidi-gateway 实测过两端：
    ///   - 未敲门          → closed-immediately（proxy.handle 的 al.Allowed 失败分支 c.Close()）
    ///   - SPA 敲门放行后  → held-open（连接被挂在 Handshake() 等 ClientHello，8s 后才超时）
    /// 整个「网关隧道口」检查项的判据就建立在这两端的差别上。
    #[test]
    fn 真网关探测符合预期() {
        let Ok(addr) = std::env::var("BAIDI_PROBE_REAL_GW") else { return };
        let want = std::env::var("BAIDI_PROBE_EXPECT").unwrap_or_else(|_| "closed-immediately".into());
        let (h, p) = addr.rsplit_once(':').expect("形如 host:port");
        let r = super::probe_tcp_inner(h, p.parse().expect("端口"), 3000, 1200);
        assert_eq!(r.kind, want, "真网关探测结果与期望不符：{r:?}");
    }
}
