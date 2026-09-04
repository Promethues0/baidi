import java.security.MessageDigest

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.baidi.mobile"
    compileSdk = 34 // 本机 platforms/ 已装 android-34；AGP 8.5.2 支持上限即 34

    defaultConfig {
        applicationId = "dev.baidi.mobile"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
        // 控制中心地址：./gradlew -PbaidiApiBase=https://x.x.x.x 覆盖
        val apiBase = (project.findProperty("baidiApiBase") as String?) ?: "https://101.43.125.131"
        buildConfigField("String", "BAIDI_API_BASE", "\"$apiBase\"")

        // ── 控制中心 HTTPS 信任锚（-PbaidiControlCa=/path/to/ca.pem，可不传）──
        //
        // ★为什么要在构建期注入：参考部署（deploy/install-remote.sh）给控制面签的是自签证书，
        //   系统信任库当然不认它。两条链路**都**会被它挡住，而且两处失败长得完全不一样：
        //     · WebView（登录、拉剖面、api.ts 的每一次 fetch）→ ERR_CERT_AUTHORITY_INVALID
        //     · Go 数据面（取敲门令牌）→ x509: certificate signed by unknown authority
        //   2026-09-03 真机上先后撞到这两处，看起来像两个不相干的 bug。
        //
        // ★**两半必须吃同一份字节**：材料只存在 res/raw/baidi_control_ca.pem 一处，
        //   NSC（管 WebView）与 Go 的 ControlCaPEM（管数据面）都从它来。只解决一半的话，
        //   会造出「网页登录得进去而隧道连不上」（或反过来）——两边都不报错的静默失效。
        //
        // ★BuildConfig 里**只放 SHA-256，不放 PEM 正文**：运行期各自读 res/raw 再比对，
        //   于是"NSC 用的那份"与"Go 用的那份"是否同源变成一件**可执行**的事，而不是靠约定。
        //
        // ★NSC 的 <domain> 从 apiBase 的 host 推，**不另开一个入参**：两个入参就是两个真相来源，
        //   而它们不一致时的现场是「证书装了却不生效」——最难查的那一类。
        //   裸 IP 也认（2026-09-03 OPPO PKU110 实测，带反例对照：把 domain 改成另一个 IP 后
        //   同一次 fetch 必然失败，说明起作用的确实是这条 domain 匹配）。
        val caPath = project.findProperty("baidiControlCa") as String?
        val caFile = caPath?.let { file(it) }
        val genRes = layout.buildDirectory.dir("generated/baidiTrust/res").get().asFile
        val rawDir = File(genRes, "raw"); val xmlDir = File(genRes, "xml")
        rawDir.mkdirs(); xmlDir.mkdirs()
        val rawPem = File(rawDir, "baidi_control_ca.pem")

        var caSha = ""
        if (caFile != null) {
            if (!caFile.isFile) throw GradleException("-PbaidiControlCa 指向的文件不存在：${caFile.absolutePath}")
            val pem = caFile.readText()
            // 构建期就把"解析不出证书"挡掉：漏到运行期的话，现场是数据面报一句锚无效，
            // 而 WebView 那半边（NSC）会被 aapt 直接拒绝——同一个错分成两种完全不同的现象。
            val n = Regex("-----BEGIN CERTIFICATE-----").findAll(pem).count()
            if (n < 1) throw GradleException(
                "-PbaidiControlCa 里一张证书都没有（要 -----BEGIN CERTIFICATE----- 开头的**公证书**，" +
                "不是私钥、不是 DER 二进制）：${caFile.absolutePath}")
            rawPem.writeText(pem)
            caSha = MessageDigest.getInstance("SHA-256")
                .digest(pem.toByteArray()).joinToString("") { "%02x".format(it) }
            logger.lifecycle("→ 控制中心信任锚：${caFile.absolutePath}（$n 张，sha256=${caSha.take(16)}…）")
        } else {
            rawPem.writeText("")   // 恒存在：否则 R.raw.baidi_control_ca 在未配置时编不过
            logger.lifecycle("→ 未配置控制中心信任锚（-PbaidiControlCa）：只信系统信任库。" +
                "自签部署下 WebView 登录与数据面取令牌都会失败——这是**如实的**姿态，不是 bug")
        }
        buildConfigField("String", "BAIDI_CONTROL_CA_SHA256", "\"$caSha\"")

        val host = Regex("^[a-zA-Z]+://([^/:]+)").find(apiBase)?.groupValues?.get(1) ?: ""
        // ★锚给了却解不出 host = **锚在包里、WebView 那半边静默不匹配任何域**：
        //   res/raw 有证书、BuildConfig 有摘要、数据面那一半照常工作，而登录仍旧
        //   ERR_CERT_AUTHORITY_INVALID——"配置齐全、零报错、就是不生效"，本仓最忌讳的形态。
        //   CI 的 -PbaidiApiBase 来自 workflow_dispatch 的自由输入，漏写 scheme 就会命中这里。
        if (caSha.isNotEmpty() && host.isEmpty()) throw GradleException(
            "-PbaidiControlCa 给了信任锚，但从 -PbaidiApiBase 解不出主机名：\"$apiBase\"。" +
            "NSC 的 <domain> 会是空的 → 锚对 WebView 完全不生效，而数据面那一半照常工作，" +
            "现场表现是「证书装了却只有隧道通、登录不通」。请写成 https://<主机名或IP> 的形式。")
        val anchors = if (caSha.isEmpty()) "" else
            """\n            <certificates src="@raw/baidi_control_ca" />"""
        // host 为空时**整段 domain-config 都不发**：空 <domain> 匹配不到任何东西，
        // 留着只会让人以为有一条按域的规则在生效。
        val domainBlock = if (host.isEmpty()) "" else """
    <domain-config>
        <domain includeSubdomains="false">$host</domain>
        <trust-anchors>
            <certificates src="system" />$anchors
        </trust-anchors>
    </domain-config>"""
        File(xmlDir, "network_security_config.xml").writeText(
            """<?xml version="1.0" encoding="utf-8"?>
<!-- 由 build.gradle.kts 从 -PbaidiControlCa 与 -PbaidiApiBase 生成，**不要手改**。 -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors><certificates src="system" /></trust-anchors>
    </base-config>$domainBlock
</network-security-config>
""")
    }
    sourceSets["main"].res.srcDir(layout.buildDirectory.dir("generated/baidiTrust/res"))
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(files("libs/baidimobile.aar"))
    implementation("androidx.webkit:webkit:1.11.0")
    // JVM 单测（src/test）：网段解析与运行态两处纯 Kotlin 逻辑，CI 用 testDebugUnitTest 跑
    testImplementation("junit:junit:4.13.2")
}
