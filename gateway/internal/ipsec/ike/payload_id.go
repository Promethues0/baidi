package ike

import "fmt"

// ID 与 AUTH 的线格式一模一样（1 字节类型 + 3 字节保留 + 数据），
// 但 ID 多承担一件事：它的**载荷体原文**要进 AUTH 计算。
//
// ★RestOfIDPayload = `IDType(1) ‖ RESERVED(3) ‖ Data`，即去掉 4 字节通用头之后的
// **全部**内容。少算那 3 个保留字节（只拼 IDType‖Data）或多算 4 字节通用头，
// 都会让两端算出不同的 MACedID，而对端报回来的只有一句「认证失败」——
// 这是 PSK 路径上至少 6 个同症状根因里的一个，也是最容易写错的一个。
// 所以本文件直接把 appendBody 暴露成 RestOfIDPayload，让 auth.go 不必自己拼字节。

// ── IDi / IDr ──

// Type 实现 Payload 接口。
//
// T 由构造方设定（解析时由 newPayload 填，发送时由状态机填）。零值退化为 IDi
// 而不是原样返回 0：Type() 返回 NONE 会让 Encode 在 Next Payload 链上写出一个
// 提前终止符，对端解析时报文「合法地」少了后面所有载荷，且两端都不报错。
func (p *IDPayload) Type() PayloadType {
	if p.T == PayloadIDr {
		return PayloadIDr
	}
	return PayloadIDi
}

func (p *IDPayload) appendBody(dst []byte) []byte {
	dst = append(dst, byte(p.IDType), 0, 0, 0) // ID Type + RESERVED(3)
	return append(dst, p.Data...)
}

func (p *IDPayload) parseBody(b []byte) error {
	if len(b) < 4 {
		return payloadErr(p.Type(), fmt.Sprintf("体长 %d 不足 4 字节固定头（ID Type 1 + RESERVED 3）", len(b)))
	}
	if len(b) == 4 {
		// 空身份能让两个配置完全不同的站点算出同一个 MACedID，
		// 等于把「你是谁」这一问答短路掉。
		return payloadErr(p.Type(), "身份数据为空")
	}
	p.IDType = IDType(b[0])
	p.Data = append([]byte(nil), b[4:]...)
	// 类型与长度自洽：地址型 ID 的长度是规范写死的，不符即畸形。
	switch p.IDType {
	case IDIPv4Addr:
		if len(p.Data) != 4 {
			return payloadErr(p.Type(), fmt.Sprintf("ID_IPV4_ADDR 的数据应为 4 字节，实际 %d", len(p.Data)))
		}
	case IDIPv6Addr:
		if len(p.Data) != 16 {
			return payloadErr(p.Type(), fmt.Sprintf("ID_IPV6_ADDR 的数据应为 16 字节，实际 %d", len(p.Data)))
		}
	}
	return nil
}

// RestOfIDPayload 返回 AUTH 计算所需的 `IDType(1) ‖ RESERVED(3) ‖ Data`。
//
// ★这是 MACedIDForI / MACedIDForR 的**唯一**正确输入。auth.go 直接调它，
// 不要自己重新拼——手拼的版本一旦漏掉 3 个保留字节，症状是「认证失败」，
// 而两端日志都指不出问题在哪一段字节上。
func (p *IDPayload) RestOfIDPayload() []byte { return p.appendBody(nil) }

// String 供日志使用。FQDN/RFC822 直接打字符串，其余打十六进制。
// ★不要在这里打 PSK 或任何密钥材料；ID 本身是公开值，可以放心记录。
func (p *IDPayload) String() string {
	switch p.IDType {
	case IDFQDN:
		return fmt.Sprintf("FQDN:%s", p.Data)
	case IDRFC822:
		return fmt.Sprintf("EMAIL:%s", p.Data)
	case IDIPv4Addr, IDIPv6Addr:
		return fmt.Sprintf("IP:%x", p.Data)
	}
	return fmt.Sprintf("ID(%d):%x", uint8(p.IDType), p.Data)
}

// ── AUTH ──

// Type 实现 Payload 接口。
func (p *AuthPayload) Type() PayloadType { return PayloadAUTH }

func (p *AuthPayload) appendBody(dst []byte) []byte {
	dst = append(dst, byte(p.Method), 0, 0, 0) // Auth Method + RESERVED(3)
	return append(dst, p.Data...)
}

func (p *AuthPayload) parseBody(b []byte) error {
	if len(b) < 4 {
		return payloadErr(PayloadAUTH, fmt.Sprintf("体长 %d 不足 4 字节固定头（Auth Method 1 + RESERVED 3）", len(b)))
	}
	if len(b) == 4 {
		// 空 AUTH 必须在解析层就拒。放行的话，上层若不慎用「长度为 0 则跳过比较」
		// 的写法，空 AUTH 就成了万能钥匙。
		return payloadErr(PayloadAUTH, "认证数据为空")
	}
	p.Method = AuthMethod(b[0])
	p.Data = append([]byte(nil), b[4:]...)
	// ★不在这里校验 Method 是否受支持：收到 RSA/数字签名等方法时，正确回应是
	// N(AUTHENTICATION_FAILED)（此时已在加密的 IKE_AUTH 内，回错误是安全的），
	// 那是状态机的判断。解析层拒掉会退化成静默丢包，对端只能看到超时。
	return nil
}
