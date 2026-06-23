// Command baidi-gmca 一次性初始化网关国密证书材料（持久化 SM2 根 CA + 网关双证书）。
// 幂等：已存在即复用并打印信息。部署期跑一次，把 certs/ 交给网关与客户端共用。
package main

import (
	"flag"
	"fmt"
	"log"

	"baidi.dev/gateway/internal/gmcert"
)

func main() {
	dir := flag.String("dir", "certs", "证书材料目录（生成/复用 ca.pem + sign/enc 双证书）")
	flag.Parse()

	if _, err := gmcert.EnsureGateway(*dir); err != nil {
		log.Fatalf("生成/加载国密证书失败: %v", err)
	}
	subject, notAfter, err := gmcert.CAInfo(*dir)
	if err != nil {
		log.Fatalf("读取 CA 信息失败: %v", err)
	}
	fmt.Printf("✓ 国密证书就绪：%s\n", *dir)
	fmt.Printf("  CA 主体：%s\n", subject)
	fmt.Printf("  CA 有效期至：%s\n", notAfter.Format("2006-01-02"))
	fmt.Printf("  网关双证书：sign.pem(签名) + enc.pem(加密)，SAN=baidi-gateway/localhost/127.0.0.1\n")
	fmt.Printf("  客户端用 -ca %s 校验（探针/数据面去掉 InsecureSkipVerify）\n", *dir)
}
