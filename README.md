# Prism Phone

Prism 手机端独立仓库。当前交付 Android Beta，原生 Kotlin 界面、Android VpnService 和 Rust 内核。桌面端在 [yuuolo/prism](https://github.com/yuuolo/prism)。iOS/iPadOS 与 HarmonyOS NEXT 暂停开发。

当前版本：[Android 0.2.0-beta.2](https://github.com/yuuolo/prism-phone/releases/tag/android-v0.2.0-beta.2)，新增真实内核仪表盘；[发布说明](docs/releases/android-0.2.0-beta.2.md)。沿用原签名，兼容 Beta.1 覆盖升级，尚非完整版或稳定版。

- [Android 功能、构建和验证](android/README.md)
- [完整版功能范围与验收标准](docs/android-full.md)：列明当前缺口，不代表功能已交付。
- [移动端平台边界](docs/mobile.md)
- [迁移来源与升级兼容](docs/repository-migration.md)

## 构建

需要 JDK 17、Android SDK 37.0 / Build Tools 37.0.0、NDK 28.2.13676358、Rust Android targets 和 cargo-ndk 4.0.0。完整构建及模拟器验证见 [Android CI](.github/workflows/android.yml)。

```sh
cargo test -p prism-android --lib --locked
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358"
bash scripts/android/build-native.sh
bash android/gradlew -p android assembleDebug
```

仓库包含固定来源的 `prism-core` 源码快照，可独立构建，无需相邻的桌面仓库。版本与桌面端独立发布。应用包名和发布证书保持一致，以支持覆盖升级；签名密钥不进入仓库或 CI。
