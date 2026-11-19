// Acceptance-only independent UID client. Never included in the Prism APK.
plugins { id("com.android.application") }
android {
    namespace = "dev.prism.routeprobe"
    compileSdk { version = release(37) { minorApiLevel = 0 } }
    buildToolsVersion = "37.0.0"
    defaultConfig { applicationId = "dev.prism.routeprobe"; minSdk = 26; targetSdk = 37; versionCode = 1; versionName = "acceptance-only" }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
androidComponents { beforeVariants(selector().withBuildType("release")) { it.enable=false } }
