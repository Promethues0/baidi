package ike

import "fmt"

// Payload 一个 IKE 载荷。
//
// appendBody/parseBody 处理的都是**不含 4 字节通用头**的载荷体：
// 通用头（Next Payload / Critical / Length）由 wire.go 统一编解码，
// 各载荷只关心自己的字段。这样 Next Payload 链的回填逻辑只有一处，
// 不会散落到每个载荷里去（散落正是这类协议实现最容易出错的地方）。
type Payload interface {
	Type() PayloadType
	appendBody(dst []byte) []byte
	parseBody(b []byte) error
}

// RawPayload 承载「能识别边界但本轮不解释」的载荷（CERT/CERTREQ/V 等），
// 以及未知的非关键载荷。保留原始字节而不是丢弃，是为了
//
//	① 转发/日志时能原样呈现；
//	② 万一后续要支持，解析层不用改。
type RawPayload struct {
	T    PayloadType
	Body []byte
	// Critical 记录该载荷的 Critical 位。RFC 7296 §2.5：
	// 不认识且 Critical=1 → 必须回 UNSUPPORTED_CRITICAL_PAYLOAD；
	// Critical=0 → 必须**跳过**。把这一位丢掉就没法正确处置。
	Critical bool
}

func (p *RawPayload) Type() PayloadType            { return p.T }
func (p *RawPayload) appendBody(dst []byte) []byte { return append(dst, p.Body...) }
func (p *RawPayload) parseBody(b []byte) error     { p.Body = append([]byte(nil), b...); return nil }

// newPayload 按类型构造空载荷用于解析。
// 未登记的类型退化为 RawPayload——**不报错**：
// 未知载荷的处置权在调用方（依 Critical 位决定拒绝还是跳过），
// 解析层若直接报错，就会把「对端多发了一个我们不认识的可选载荷」
// 变成无法建连，那是互通杀手（strongSwan 默认就会多发好几个通知载荷）。
func newPayload(t PayloadType) Payload {
	switch t {
	case PayloadSA:
		return &SAPayload{}
	case PayloadKE:
		return &KEPayload{}
	case PayloadIDi, PayloadIDr:
		return &IDPayload{T: t}
	case PayloadAUTH:
		return &AuthPayload{}
	case PayloadNonce:
		return &NoncePayload{}
	case PayloadNotify:
		return &NotifyPayload{}
	case PayloadDelete:
		return &DeletePayload{}
	case PayloadTSi, PayloadTSr:
		return &TSPayload{T: t}
	case PayloadSK:
		return &SKPayload{}
	}
	return &RawPayload{T: t}
}

// payloadErr 统一载荷解析错误，带上类型便于定位。
func payloadErr(t PayloadType, msg string) error {
	return fmt.Errorf("ike: %s 载荷%s", t, msg)
}
