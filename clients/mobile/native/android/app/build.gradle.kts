plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.baidi.mobile"
    compileSdk = 34 // 本机 platforms/ 已装 android-34；AGP 8.5.2 支持上限即 34

    defaultConfig {
        applicationId = "dev.baidi.mobile"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
        // 控制中心地址：./gradlew -PbaidiApiBase=https://x.x.x.x 覆盖
        val apiBase = (project.findProperty("baidiApiBase") as String?) ?: "https://101.43.125.131"
        buildConfigField("String", "BAIDI_API_BASE", "\"$apiBase\"")
    }
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
}
