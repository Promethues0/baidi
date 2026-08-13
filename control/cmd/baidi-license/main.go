// baidi-license License 发行 CLI（**发行方离线工具**，不随控制面部署）。
//
//	baidi-license -genkey -out <目录>            生成发行密钥对（license-sign.key / .pub）
//	baidi-license -sign <manifest.json> -key <license-sign.key> [-out <license.json>]
//	baidi-license -verify <license.json> -pub <license-sign.pub>
//	baidi-license -example                       打印一份 manifest 样例
//
// 私钥留在发行方手里；控制面只配公钥（BAIDI_LICENSE_PUBKEY=<license-sign.pub 的内容>）。
// 这条分界是整套机制的全部：控制面上没有任何东西能签出新 license——
// 与「gateway/internal/auth 刻意没有 Sign」是同一条纪律，签发能力绝不下放到被约束方。
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"baidi.dev/control/internal/license"
)

func main() {
	genkey := flag.Bool("genkey", false, "生成发行密钥对")
	sign := flag.String("sign", "", "要签发的 manifest JSON 文件")
	verify := flag.String("verify", "", "要校验的 license 文件")
	key := flag.String("key", "", "发行私钥文件（-sign 用）")
	pub := flag.String("pub", "", "发行公钥文件（-verify 用）")
	out := flag.String("out", "", "输出目录（-genkey）/ 输出文件（-sign，缺省打印到 stdout）")
	example := flag.Bool("example", false, "打印 manifest 样例")
	flag.Parse()

	switch {
	case *example:
		b, _ := json.MarshalIndent(license.Manifest{
			Product: "baidi", Licensee: "某某科技有限公司",
			IssuedAt: "2026-08-13", ExpiresAt: "2027-08-13",
			MaxUsers: 200, MaxGateways: 4,
		}, "", "  ")
		fmt.Println(string(b))

	case *genkey:
		dir := *out
		if dir == "" {
			dir = "."
		}
		pubKey, privKey, err := ed25519.GenerateKey(nil)
		die(err)
		// 私钥 0600：它是发行权本身。
		die(os.WriteFile(filepath.Join(dir, "license-sign.key"),
			[]byte(base64.StdEncoding.EncodeToString(privKey)+"\n"), 0o600))
		die(os.WriteFile(filepath.Join(dir, "license-sign.pub"),
			[]byte(base64.StdEncoding.EncodeToString(pubKey)+"\n"), 0o644))
		fmt.Printf("✓ 发行密钥已生成：%s/license-sign.{key,pub}\n", dir)
		fmt.Println("  控制面配置：BAIDI_LICENSE_PUBKEY=<license-sign.pub 的内容>")
		fmt.Println("  ★私钥留在发行方，绝不要放到运行控制面的机器上。")

	case *sign != "":
		if *key == "" {
			fatal("缺 -key（发行私钥文件）")
		}
		manifestRaw, err := os.ReadFile(*sign)
		die(err)
		// 误传已签好的 license 文件是最容易犯的错——签出来会是"套了两层的合法文件"，
		// 导入时 product 校验才炸，浪费两边一个来回。按 File 结构探测当场拦下。
		var probe license.File
		if json.Unmarshal(manifestRaw, &probe) == nil && len(probe.Manifest) > 0 && probe.Signature != "" {
			fatal("-sign 的输入像是已签好的 license 文件；这里要的是 manifest 本体（-example 看样例）")
		}
		var m license.Manifest
		if err := json.Unmarshal(manifestRaw, &m); err != nil {
			fatal("manifest 不是合法 JSON：" + err.Error())
		}
		privRaw, err := os.ReadFile(*key)
		die(err)
		priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privRaw)))
		die(err)
		if len(priv) != ed25519.PrivateKeySize {
			fatal("私钥长度不对（应为 base64 的 Ed25519 私钥）")
		}
		f, err := license.Sign(manifestRaw, ed25519.PrivateKey(priv))
		die(err)
		// ★用 json.Marshal 而不是 MarshalIndent：Indent 会连内嵌的 manifest 一起
		// 重新缩进，落盘字节 ≠ 签名字节，签出来的文件自己都验不过（实测踩过）。
		// Sign 已把 manifest compact 成单行原子串，普通 Marshal 原样保留它。
		blob, _ := json.Marshal(f)
		// 签完立刻用 Parse 自检一遍结构（product/expiresAt/容量），
		// 发行侧就把格式错误拦死，别让它流到导入那一刻。
		if _, _, err := license.Parse(blob); err != nil {
			fatal("签出的 license 未通过结构自检（manifest 字段有误）：" + err.Error())
		}
		if *out == "" {
			fmt.Println(string(blob))
		} else {
			die(os.WriteFile(*out, append(blob, '\n'), 0o644))
			fmt.Printf("✓ 已写入 %s\n", *out)
		}

	case *verify != "":
		if *pub == "" {
			fatal("缺 -pub（发行公钥文件）")
		}
		blob, err := os.ReadFile(*verify)
		die(err)
		pubRaw, err := os.ReadFile(*pub)
		die(err)
		pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubRaw)))
		die(err)
		f, m, err := license.Parse(blob)
		if err != nil {
			fatal(err.Error())
		}
		if err := license.Verify(f, []ed25519.PublicKey{ed25519.PublicKey(pk)}); err != nil {
			fatal(err.Error())
		}
		fmt.Printf("✓ 验证通过：%s · 用户 ≤%s · 网关 ≤%s · 到期 %s\n",
			m.Licensee, unlimited(m.MaxUsers), unlimited(m.MaxGateways), m.ExpiresAt)

	default:
		flag.Usage()
		os.Exit(2)
	}
}

func unlimited(n int) string {
	if n <= 0 {
		return "不限"
	}
	return fmt.Sprintf("%d", n)
}

func die(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "✗ "+msg)
	os.Exit(1)
}
