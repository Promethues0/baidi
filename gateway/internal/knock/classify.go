package knock

import (
	"crypto/x509"
	"errors"
	"net"
	"syscall"
)

// ClassifyControlErr 把「连控制面失败」的底层错误翻成一句中文人话。**认不出的原样返回，绝不猜。**
//
// ★为什么现在需要它：这句话马上就要第一次上到用户界面上。此前它只活在健康行里给排障用，
// 2026-09-03 安卓真机（OPPO PKU110 / Android 16）实测拿到的原文是
// `取敲门令牌失败：Post "https://…": tls: failed to verify certificate: x509: certificate signed by
// unknown authority`——事实是准的，但它既没说"这台机器不信任控制面那张自签证书"，
// 也没说下一步该干什么，用户只会读成"网络有问题"然后去反复重连。
//
// ★分档一律用 errors.As / errors.Is，**不匹配字符串**：错误原文随 Go 版本和平台改写
// （crypto/tls 在 Go 1.20 起就把 x509 错误包进了 CertificateVerificationError），
// 按字符串匹配的归因会在某次升级后静默失效——而失效的表现是"又回到英文原文"，
// 没有任何测试会红，也没人会注意到。
//
// ★返回值保留原错误链（见 controlErr.Unwrap）：调用方仍能 errors.Is/As 判具体成因，
// Error() 只是换了一层给人看的说法。丢掉链的话，"给用户看得懂的话"就变成了
// "给程序看的信息也一起没了"，那是拿一个问题换另一个问题。
//
// ★这条消息会经 dataplane.sanitizeReason 进健康行（值域：单行 / 不含裸 `=` /
// < healthReasonMax 个字符），被改写就说明文案违约。有用例把这条钉住
// （internal/dataplane 侧真跑一遍 sanitizeReason 断言逐字不变）。
func ClassifyControlErr(err error) error {
	if err == nil {
		return nil
	}

	// ── 证书类：地址是对的、链路是通的，问题在信任材料上。三档的下一步动作完全不同。
	var unknownCA x509.UnknownAuthorityError
	if errors.As(err, &unknownCA) {
		return &controlErr{msg: msgUnknownCA, err: err}
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return &controlErr{msg: "控制中心的 HTTPS 证书里没有本机访问的这个主机名（" + hostErr.Host +
			"）。请按证书上的域名填写控制中心地址，或让管理员重新签发一张覆盖该地址的证书。", err: err}
	}
	var invalid x509.CertificateInvalidError
	// ★只认 Expired 这一档。CertificateInvalidError 还有 NotAuthorizedToSign / IncompatibleUsage
	// 等七八种 Reason，它们的成因与补救各不相同——一律套一句"证书过期了"就是在猜，
	// 而猜错的归因比英文原文更难纠正（人会照着错方向查下去）。其余 Reason 原样返回。
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return &controlErr{msg: "控制中心的 HTTPS 证书已过期或还没到生效时间。请先核对本机的系统时间，" +
			"时间没问题就是证书真的过期了，需要管理员换一张。", err: err}
	}

	// ── 解析类：连 TCP 都还没开始。排在超时之前，因为 DNS 查询失败本身也可能是超时，
	// 而"域名解析不了"比"连接超时"具体得多，先说具体的那句。
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return &controlErr{msg: "控制中心的主机名解析不了（DNS 查不到 " + dnsErr.Name +
			"）。请核对控制中心地址；若填的是内网域名，还要确认本机当前用的是内网 DNS。", err: err}
	}

	// ── 连接类。**被拒与超时必须分开说**：被拒是对端立刻回了 RST（说明包到得了那台机器、
	// 只是没有进程在听那个端口），超时是压根没有回应（不可达或被中间设备丢包）。
	// 两者的排查方向相反，混成一句「连不上」等于把这条最有用的线索抹掉。
	if errors.Is(err, syscall.ECONNREFUSED) {
		return &controlErr{msg: "连不上控制中心：对端拒绝了连接（包到得了那台机器，但没有进程在听这个端口）。" +
			"多半是端口写错了，或者控制面进程没起来。", err: err}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &controlErr{msg: "连不上控制中心：请求超时，对端一点回应都没有。" +
			"这通常是地址不可达或被防火墙静默丢包（真拒绝会立刻返回），请核对控制中心地址与网络。", err: err}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// 认得出是网络层的事，但认不出具体是哪一种（网络不可达 / 连接被重置 / …）。
		// **不硬编一句泛泛的"网络异常"**：那句话不比原文多说任何事，却把原文盖掉了。
		return err
	}
	return err
}

// msgUnknownCA 是本波真机上撞到的那一档，措辞与桌面端 diagnose.ts::explainControlFailure
// 的 HTTPS 分支同源：按 install-remote.sh 部署出来的控制面用的就是自签证书。
//
// ★结尾那句「不要绕过校验」是有意写给用户看的：这条提示最容易招来的"修法"就是
// 找一个跳过证书校验的开关，而本仓从不提供那种开关（提供了就等于把隧道的服务端认证
// 一起废掉）。把正确的两条路当面写出来，比事后解释便宜。
const msgUnknownCA = "本机不信任控制中心的 HTTPS 证书（按部署脚本装出来的控制面用的是自签证书）。" +
	"两条路：把该站点的根证书导入本机受信任的根证书颁发机构，或给控制中心换一张受信任的证书。不要绕过证书校验。"

// controlErr 是「人话说明 + 原始错误链」的载体。
type controlErr struct {
	msg string
	err error
}

func (e *controlErr) Error() string { return e.msg }

// Unwrap 保留原链：调用方（如 knockOne 判 ErrDenied）与将来的诊断代码仍能 errors.Is/As。
func (e *controlErr) Unwrap() error { return e.err }

// ClassifyControlStatus 把「连上了控制中心、但它回了个非 200」翻成人话。**认不出返回空串**，
// 调用方据此保留原来的 `control 返回 %d`——泛泛兜底一句"服务异常"会把状态码这条唯一线索也抹掉。
//
// ★为什么非 2xx 这一支也得翻：ClassifyControlErr 只接在传输层失败上，而从 wave10 起
// 这两条路的错误**都**会经健康行上到用户界面。两档最高频，且恰好是最容易被读反的：
//   · 502/503/504 —— 参考部署是 nginx 反代 baidi-control，控制面进程挂了/正在重启时
//     nginx 连不上 upstream 就回 502。客户端这一侧网络、地址、证书全都正常，
//     显示「control 返回 502」会让用户去查自己的网络，而该看的是服务端进程。
//   · 401 —— 会话令牌 8h 到期，而隧道还跑着（数据面每 15s 拿它去换敲门令牌）。
//     正确动作是重新登录，可界面上此前只说「control 返回 401」，且未就绪横幅还写着
//     「重开隧道无用」——两句合起来把人指向了一条走不通的路。
//
// 403 不在这里：它是控制面的**定性拒绝**（强制下线 / 账号禁用 / 终端不合规），
// 由 FetchToken 包成 ErrDenied 并带出服务端给的原因，那条路径有自己的语义（停止接入，不再重试）。
func ClassifyControlStatus(code int) string {
	switch code {
	case 401:
		return "登录状态已过期（控制中心不再认这张会话令牌）。请退出后重新登录；" +
			"重新接入时隧道会自动恢复，不必改任何配置。"
	case 502, 503, 504:
		return "控制中心的反向代理连不上后端进程（控制面可能没起来或正在重启）。" +
			"本机的网络与地址都是通的，请稍后重试，或联系管理员查看 baidi-control 的运行状态。"
	}
	return ""
}
