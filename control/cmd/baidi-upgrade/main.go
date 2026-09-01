// baidi-upgrade 升级包签名 CLI（**发布方离线工具**，不随控制面部署）。
//
//	baidi-upgrade -genkey [-out <目录>]                     生成发布密钥对（upgrade-sign.key / .pub）
//	baidi-upgrade -manifest <包文件> -version v0.4.0 \
//	              -component control [-min-source v0.3.0] [-notes "…"]   由包体生成 manifest（自动算 SHA-256）
//	baidi-upgrade -sign <manifest.json> -key <upgrade-sign.key> [-out <manifest.sig>]
//	baidi-upgrade -verify <manifest.json> -sig <manifest.sig> -pub <upgrade-sign.pub>
//
// ★这个工具此前**不存在**，而验签是 fail-closed 的：
// `upgrade.VerifySignature` 在没配公钥时直接拒（那是对的——跳过验签等于任何人都能
// 推一个包上来），而全仓既没有签名工具、`BAIDI_UPGRADE_PUBKEY` 也没进任何部署模板。
// 结果是升级包校验在**任何真实部署上恒为「校验不通过」**：功能写完了、fail-closed
// 的方向也对，但链路缺了发布侧这一半，管理员永远走不通。
//
// 私钥留在发布方手里；控制面只配公钥（BAIDI_UPGRADE_PUBKEY=<upgrade-sign.pub 的内容>）。
// 与 baidi-license 同一条分界：控制面上没有任何东西能签出新包——
// 签发能力绝不下放到被约束方（同「gateway/internal/auth 刻意没有 Sign」）。
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"baidi.dev/control/internal/upgrade"
)

func main() {
	genkey := flag.Bool("genkey", false, "生成发布密钥对")
	manifest := flag.String("manifest", "", "由这个升级包文件生成 manifest（自动算 SHA-256）")
	sign := flag.String("sign", "", "要签名的 manifest JSON 文件")
	verify := flag.String("verify", "", "要校验的 manifest JSON 文件")
	sig := flag.String("sig", "", "签名文件（-verify 用；-sign 缺省写同名 .sig）")
	key := flag.String("key", "", "发布私钥文件（-sign 用）")
	pub := flag.String("pub", "", "发布公钥文件（-verify 用）")
	out := flag.String("out", "", "输出目录（-genkey）/ 输出文件（-manifest、-sign）")
	version := flag.String("version", "", "目标版本（-manifest 用，如 v0.4.0）")
	component := flag.String("component", "", "组件：control | gateway（-manifest 用）")
	minSource := flag.String("min-source", "", "允许的最低起跳版本（-manifest 用，可空）")
	notes := flag.String("notes", "", "版本说明（-manifest 用，可空）")
	flag.Parse()

	switch {
	case *genkey:
		dir := *out
		if dir == "" {
			dir = "."
		}
		pubKey, privKey, err := ed25519.GenerateKey(nil)
		die(err)
		// 私钥 0600：它就是发布权本身。
		die(os.WriteFile(filepath.Join(dir, "upgrade-sign.key"),
			[]byte(base64.StdEncoding.EncodeToString(privKey)+"\n"), 0o600))
		die(os.WriteFile(filepath.Join(dir, "upgrade-sign.pub"),
			[]byte(base64.StdEncoding.EncodeToString(pubKey)+"\n"), 0o644))
		fmt.Printf("✓ 发布密钥已生成：%s/upgrade-sign.{key,pub}\n", dir)
		fmt.Println("  控制面配置：BAIDI_UPGRADE_PUBKEY=<upgrade-sign.pub 的内容>")
		fmt.Println("  ★私钥留在发布方，绝不要放到运行控制面的机器上。")
		fmt.Println("  ★轮换期可配多把（逗号分隔），新旧并存直到旧包全部下线。")

	case *manifest != "":
		if *version == "" || *component == "" {
			fatal("缺 -version 或 -component（control | gateway）")
		}
		sum, size, err := sha256File(*manifest)
		die(err)
		m := upgrade.Manifest{
			Product: "baidi", Component: strings.ToLower(*component), Version: *version,
			MinSource: *minSource, SHA256: sum, Notes: *notes,
			BuiltAt: time.Now().Format("2006-01-02 15:04:05"),
		}
		// ★发布侧就把结构错误拦死（product/component/版本序/哈希格式），
		//   别让它流到管理员上传那一刻——那时的报错离原因已经很远了。
		if _, err := upgrade.ParseManifest(mustJSON(m)); err != nil {
			fatal("生成的 manifest 未通过结构自检：" + err.Error())
		}
		blob := mustJSONIndent(m)
		if *out == "" {
			fmt.Println(string(blob))
		} else {
			die(os.WriteFile(*out, append(blob, '\n'), 0o644))
			fmt.Printf("✓ 已写入 %s（包体 %s，%d 字节）\n", *out, sum[:16]+"…", size)
		}

	case *sign != "":
		if *key == "" {
			fatal("缺 -key（发布私钥文件）")
		}
		raw, err := os.ReadFile(*sign)
		die(err)
		// ★签的是**文件原文字节**，不是重新序列化的结果：控制面验签时读的也是
		//   上传上来的那份原文。任何一侧动一下缩进，签名就对不上——
		//   而症状是「签得好好的包，导入时说签名无效」。
		if _, err := upgrade.ParseManifest(raw); err != nil {
			fatal("manifest 不合法：" + err.Error())
		}
		privRaw, err := os.ReadFile(*key)
		die(err)
		priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privRaw)))
		die(err)
		if len(priv) != ed25519.PrivateKeySize {
			fatal("私钥长度不对（应为 base64 的 Ed25519 私钥）")
		}
		s := base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(priv), raw))
		// 签完立刻自验一遍：发布侧就确认这对密钥、这份原文能过——
		// 别把「签出来但验不过」留到管理员上传那一刻。
		if err := upgrade.VerifySignature(raw, mustB64(s),
			[]ed25519.PublicKey{ed25519.PublicKey(ed25519.PrivateKey(priv).Public().(ed25519.PublicKey))}); err != nil {
			fatal("签出的签名未通过自检：" + err.Error())
		}
		target := *out
		if target == "" {
			target = strings.TrimSuffix(*sign, filepath.Ext(*sign)) + ".sig"
		}
		die(os.WriteFile(target, []byte(s+"\n"), 0o644))
		fmt.Printf("✓ 已写入签名 %s\n", target)
		fmt.Println("  上传升级包时把 manifest 原文与这份签名一并提交；控制面用 BAIDI_UPGRADE_PUBKEY 验。")

	case *verify != "":
		if *pub == "" || *sig == "" {
			fatal("缺 -pub 或 -sig")
		}
		raw, err := os.ReadFile(*verify)
		die(err)
		sigRaw, err := os.ReadFile(*sig)
		die(err)
		pubRaw, err := os.ReadFile(*pub)
		die(err)
		pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubRaw)))
		die(err)
		m, err := upgrade.ParseManifest(raw)
		if err != nil {
			fatal(err.Error())
		}
		if err := upgrade.VerifySignature(raw, mustB64(strings.TrimSpace(string(sigRaw))),
			[]ed25519.PublicKey{ed25519.PublicKey(pk)}); err != nil {
			fatal(err.Error())
		}
		fmt.Printf("✓ 验证通过：%s %s（包体 sha256 %s…）\n", m.Component, m.Version, m.SHA256[:16])

	default:
		flag.Usage()
		os.Exit(2)
	}
}

// sha256File 算包体校验和（流式，不整包进内存——升级包动辄几十 MB）。
func sha256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func mustJSON(v any) []byte       { b, _ := json.Marshal(v); return b }
func mustJSONIndent(v any) []byte { b, _ := json.MarshalIndent(v, "", "  "); return b }
func mustB64(s string) []byte     { b, _ := base64.StdEncoding.DecodeString(s); return b }
func die(err error) {
	if err != nil {
		fatal(err.Error())
	}
}
func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "✗ "+msg)
	os.Exit(1)
}
