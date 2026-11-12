# Prism Android

独立原生 Kotlin 界面与 Android VpnService，内嵌 Rust prism-core。当前发布版本 [0.2.0-beta.2](https://github.com/yuuolo/prism-phone/releases/tag/android-v0.2.0-beta.2)，与桌面版本、设置、签名及更新渠道分开。当前为 Beta 验证阶段。

## 范围

以下列表描述已发布 Beta 的范围。未发布开发已接入真实连接/路由详情、日/月历史统计、DNS/TCP 检测、本机 HTTP/SOCKS5 服务、有序规则组、自动优选、订阅合并池、GeoIP/GeoSite 地区规则及广告域名拦截，逐项验证记录见[完整版进度](../docs/android-full.md)；尚不代表完整版已发布。

- 连接/断开、系统 VPN 授权、前台连接通知。
- 连接页显示真实内核运行时间、实时速率、活跃连接数、当前规则策略和默认节点；仅前台采样，流量统计口径及验证状态见[完整版进度](../docs/android-full.md)。
- 多个 HTTPS 订阅独立导入/更新和删除，粘贴配置与单节点添加；更新一个订阅不覆盖其他来源。
- 节点搜索、协议筛选、名称/协议/收藏排序、收藏、选择和删除；按需测试当前节点。
- 基础域名后缀/IPv4 CIDR 直连规则，受限的本地运行记录及复制。
- 独立安卓升级通道，启动检查、系统每日后台检查、升级通知、手动下载和系统确认安装。
- 紫色连接卡片、底部导航、分组列表、订阅卡片与独立更新页；适应系统边距和软键盘。
- IPv4/IPv6 均路由进入 VPN；首版仅开放 IPv4 目标，IPv6 目标在内核拒绝，避免移除 IPv6 路由造成旁路。
- DNS TCP/UDP 53 由内核处理，使用经所选节点的 DoH；代理服务器域名使用独立 IP 地址 DoH 引导，普通查询不回退系统 DNS。
- 用户配置和订阅凭据使用 Android Keystore AES-GCM 加密，不参加系统备份；诊断事件有容量上限，不记录节点密钥和订阅 URL。

首版允许基础 TCP/TLS AnyTLS、Shadowsocks、Trojan、VLESS、SOCKS5、HTTP 节点；禁用跳过证书校验、链式代理、指纹/Reality/Vision 和高级传输。不支持的节点会跳过并显示数量，不能用时明确报错。订阅只导入节点，不执行桌面规则、providers、覆写或脚本；手机规则由用户独立设置。

不包含 Tailscale、多内核下载、桌面服务、地图、应用流量统计、云同步和桌面看门狗。首版不启用系统常开 VPN，也不承诺进程被系统终止后的断网保护。

## 生命周期

所有 Rust TCP/UDP 出站 socket 在连接前调用 VpnService.protect，防止回环。Java 的普通应用请求仍进入 VPN；不全局排除自身 UID。手机系统管理底层网络，底层网络变化时有间隔限制地重建连接池/DNS，保留 VPN 描述符；不以流量空闲反复重启。

用户断开和撤销 VPN 授权使旧连接请求失效；关闭 native runtime 后再释放 Java 的 TUN 描述符。后台不持续测速、不轮询连接列表、不持有无限保活任务。

## 版本更新

新构建的更新元数据固定为 `https://github.com/yuuolo/prism-phone/releases/download/android-updates/android-update.json`；已安装 Beta.1 的旧仓库入口保留，通过同签名 APK 镜像提供兼容升级，见 [迁移说明](../docs/repository-migration.md)。不读取 GitHub 默认 latest 或桌面 `latest.json`。后台任务由 Android JobScheduler 安排，系统省电、强行停止、网络限制或通知权限会影响提醒时机；应用打开时还会按间隔检查。只检查和提醒，不自动下载安装。

安装包需通过大小、SHA-256、包名、递增 versionCode 和当前安装签名校验，拒绝其他签名和损坏包。只允许官方仓库的安卓 APK 地址及 GitHub 官方下载重定向。安装必须由用户授权此来源并在系统安装器确认，不进行静默安装。

`0.1.0-alpha.1` 未含更新器，需要手动覆盖安装 Beta 一次，此后可收到升级提醒。保留同一安卓签名和 Keystore 数据，旧节点配置自动迁移为独立订阅/节点来源。

## 构建

最低计划 Android 8.0/API 26，64 位（arm64-v8a；x86_64 用于模拟器）。主要适配和测试目标为 Android 17/API 37。尚需分别验证旧系统和具体厂商设备。

依赖：JDK 17、Android SDK 平台 `37.0`、build-tools `37.0.0`、NDK 28.2.13676358、Rust stable，以及 arm64/x86_64 Android targets。Gradle Wrapper 和分发包摘要已固定；AGP 9.1.1 使用内置 Kotlin。

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk --version 4.0.0 --locked
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358"
bash scripts/android/build-native.sh
bash android/gradlew -p android assembleDebug
```

调试产物：`android/app/build/outputs/apk/debug/app-debug.apk`。CI 另行构建 Release 未签名 APK，正式对外的 Alpha 安装包在本机使用固定的 Android 私钥签名，再运行 `apksigner verify` 后发布；不上传签名私钥和密码，不复用桌面更新密钥。调试签名与发布签名不同，不能互相覆盖安装。

本机签名材料位于被 Git 忽略的 `android/.signing/`，应保留离线备份，后续版本沿用同一个签名。CI 的未签名 APK 不能直接安装。

CI：`.github/workflows/android.yml` 构建 ARM64 与 x86_64 JNI 库、APK、Lint，并在 Android 17 模拟器进行真实 VPN/DNS/TCP/UDP、IPv6 阻断、会话重建和断开测试。测试使用本地 SOCKS 服务，不使用真实订阅或远程账号。模拟器授权只作用于隔离 CI 设备，普通手机仍需要用户确认系统 VPN 对话框。

在真机完成订阅节点、Wi-Fi/蜂窝切换、锁屏、后台、省电、撤权、内存和耗电验证前，不宣称已达到稳定发布标准。
