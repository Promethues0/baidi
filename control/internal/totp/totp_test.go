package totp

import (
	"strings"
	"testing"
	"time"
)

// rfc4226Secret RFC 4226 附录 D 与 RFC 6238 附录 B 共用的 ASCII 测试密钥。
const rfc4226ASCII = "12345678901234567890"

// TestHOTPRFC4226Vectors RFC 4226 附录 D 的 10 个官方向量（6 位）。
func TestHOTPRFC4226Vectors(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for c, w := range want {
		if got := hotpCode([]byte(rfc4226ASCII), uint64(c), 6); got != w {
			t.Errorf("counter=%d got %s want %s", c, got, w)
		}
	}
}

// TestTOTPRFC6238Vectors RFC 6238 附录 B 的 SHA1 官方向量（8 位）。
func TestTOTPRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		counter := counterAt(time.Unix(c.unix, 0))
		if got := hotpCode([]byte(rfc4226ASCII), counter, 8); got != c.want {
			t.Errorf("t=%d got %s want %s", c.unix, got, c.want)
		}
	}
}

func TestGenerateAndRoundTrip(t *testing.T) {
	sec, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sec, "=") {
		t.Fatalf("密钥不应含填充：%s", sec)
	}
	now := time.Unix(1_700_000_000, 0)
	code, err := Code(sec, now)
	if err != nil {
		t.Fatal(err)
	}
	ctr, ok := Verify(sec, code, now)
	if !ok {
		t.Fatal("当前步的码应通过")
	}
	if ctr != counterAt(now) {
		t.Fatalf("命中计数器 %d != %d", ctr, counterAt(now))
	}
}

// TestVerifySkewWindow 漂移窗：前后一步收、两步拒。
func TestVerifySkewWindow(t *testing.T) {
	sec, _ := GenerateSecret()
	now := time.Unix(1_700_000_000, 0)
	for _, d := range []int64{-1, 0, 1} {
		code, _ := Code(sec, now.Add(time.Duration(d*Period)*time.Second))
		if _, ok := Verify(sec, code, now); !ok {
			t.Errorf("漂移 %d 步的码应通过", d)
		}
	}
	for _, d := range []int64{-2, 2} {
		code, _ := Code(sec, now.Add(time.Duration(d*Period)*time.Second))
		if _, ok := Verify(sec, code, now); ok {
			t.Errorf("漂移 %d 步的码应被拒", d)
		}
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	sec, _ := GenerateSecret()
	now := time.Now()
	for _, code := range []string{"", "12345", "1234567", "abcdef", "000000\n"} {
		if _, ok := Verify(sec, code, now); ok {
			t.Errorf("%q 不应通过", code)
		}
	}
	if _, ok := Verify("!!!not-base32!!!", "123456", now); ok {
		t.Error("坏密钥不应通过任何码")
	}
}

// TestDecodeSecretLenient 手输形态（小写/空格/短横/填充）应宽容。
func TestDecodeSecretLenient(t *testing.T) {
	sec, _ := GenerateSecret()
	now := time.Unix(1_700_000_000, 0)
	code, _ := Code(sec, now)
	sloppy := strings.ToLower(sec[:4] + " " + sec[4:8] + "-" + sec[8:])
	if _, ok := Verify(sloppy, code, now); !ok {
		t.Fatal("手输形态的同一密钥应验出同一码")
	}
}

func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI("白帝", "zhang.wei", "ABCD2345")
	for _, want := range []string{"otpauth://totp/", "secret=ABCD2345", "digits=6", "period=30", "algorithm=SHA1", "zhang.wei"} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI 缺 %q：%s", want, uri)
		}
	}
	if strings.Contains(uri, "白帝:") {
		t.Error("label 中的非 ASCII 应被转义")
	}
}
