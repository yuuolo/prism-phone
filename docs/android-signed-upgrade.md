# 原签名覆盖验收

此流程只用于明确归属于本任务的可清空模拟器，不能对用户手机卸载应用或清除数据。普通 CI 继续使用调试签名，不需要正式私钥；`SignedUpgradeInstrumentation` 只在显式选择时运行，不属于默认 JUnit 用例。

## 两阶段流程

1. 从本仓库已成功完成双系统 CI 的 `prism-android-unsigned-release` 取候选。先验证已发布 Beta.2 APK 的 SHA-256：`6b27d0821a50d92b078b8bda258028b452d4c377f94f8f08a7877b3a2d77466f`。
2. 构建专用验收 APK：`android/gradlew -p android assembleDebugAndroidTest -PprismAcceptanceRunner=dev.prism.android.SignedUpgradeInstrumentation`。PowerShell 中须将整个 `-P…` 参数加引号。此参数只选择测试 runner，不改变主 APK。
3. 沿用现有本机签名步骤签署候选和验收 APK，核对两者公开证书 SHA-256 均为 `618f92202c7e120f365eebc928044ec68422bd12a26ba7337e43075336f6f1c0`。不读取/输出密码内容，不上传验收 APK、私钥或密码。
4. 在空白隔离模拟器安装已发布 Beta.2 和原证书验收 APK，执行下方 prepare。它要求旧版空配置，创建两个订阅来源和一个本地节点，写入测试凭据、收藏、选择和两条旧直连规则，保存内容摘要及 UID，不输出凭据。
5. 仅用 `adb install -r` 覆盖安装候选；两阶段之间不能卸载、清除数据或更换设备。执行 verify，验证 UID、原 Keystore 解密、节点/凭据/来源/ID/收藏/选择/规则内容不变，旧规则有序迁移、新优选和链路不被自动启用，并通过新内核配置校验。

对已确认的模拟器序列号分别执行：

```sh
adb -s emulator-5560 shell am instrument -w -e phase prepare dev.prism.android.test/dev.prism.android.SignedUpgradeInstrumentation
# 此处 adb install -r 覆盖候选，不能卸载应用
adb -s emulator-5560 shell am instrument -w -e phase verify dev.prism.android.test/dev.prism.android.SignedUpgradeInstrumentation
```

必须分别出现 `upgradeAcceptance=passed-prepare` 和 `upgradeAcceptance=passed-verify`；不能仅依赖 adb 的退出码。结束后重新构建不带 `prismAcceptanceRunner` 的普通测试包，恢复隔离模拟器调试安装并运行默认回归。

## 2026-11-17 记录

- 候选取自 `2d91092` 的 [完整 CI 44082743745](https://github.com/yuuolo/prism-phone/actions/runs/44082743745)，仅在本机沿用原证书签署，文件置于忽略目录 `artifacts/signed-upgrade-acceptance/`，未发布。
- Android 8.0/API 26 和 Android 17/16 KiB 均完成真实 Beta.2 安装、prepare、覆盖安装和 verify；检查了升级后的连接页及保留的选择。
- 本轮候选仍为 versionCode 3，所以这是 Android 包管理器允许的同版本覆盖验收，不是内置更新器的新版本发布。正式发布必须递增版本，原有同签名高版本与错误签名更新包校验继续由默认回归检查。
- 本记录不替代真机覆盖、厂商系统、长时后台、耗电及蜂窝网络切换验收。

辅助程序的默认 runner 编译和回归由 `f5040f9` 的[完整 CI 44086595517](https://github.com/yuuolo/prism-phone/actions/runs/44086595517)通过，双系统各 17 项；CI 没有读取正式签名材料。

## 2026-11-18 高版本系统安装器验收

API 26 已验证真实已发布 Beta.2（code 3）经应用的“安装已下载的更新”、系统来源授权与系统安装确认，升级到本地 `0.2.0-acceptance.4`（code 4）。高版本候选没有通过 adb 安装；安装后 `passed-verify` 检查 UID、原 Keystore、节点/凭据/来源/ID/收藏/选择和旧规则迁移全部通过，内核配置校验通过，已安装版本不再由更新页提示为可更新。

候选仅在忽略目录 `artifacts/signed-upgrade-high-version/` 构建、签署和使用，未发布。构建使用独立归档的 Android 源码，仅修改归档中的 versionCode/versionName；主仓库仍为 code 3 / Beta.2。双架构 JNI 原字节取自已通过[完整 CI 44147218755](https://github.com/yuuolo/prism-phone/actions/runs/44147218755)的 Release APK，来源摘要保存在该本地目录。候选和辅助 APK 沿用上文原证书，签名材料不上传。

此项只覆盖**已校验缓存到系统安装器及数据保留**。缓存由显式辅助阶段准备并调用实际已安装 Beta.2 的 `Updates.verifyDownloaded`；没有访问虚构的新版本 URL，也没有模拟成一次真实线上检查/下载，不能据此关闭线上高版本检查和下载验收。

复现时，先在独立归档中生成真实高版本的 BuildConfig 和 APK、沿用原证书签署，再把签署后的候选复制为该归档的 `app/src/androidTest/assets/installer-candidate.apk`，以高版本 BuildConfig 编译专用 `SignedUpgradeInstrumentation` APK并签署。只在明确归属本任务的空白模拟器执行：

1. 安装真实 Beta.2 和专用辅助 APK，执行 `phase=prepare`，要求 `passed-prepare`。
2. 执行 `phase=stage-install`，要求 `passed-stage-install`。该阶段要求候选高于已安装版本，生产校验器验证摘要、大小、包名、版本与原签名后才保存本地缓存元数据，关闭测试应用的自动更新检查。
3. 辅助程序退出后从正常更新页点击安装，通过实际系统来源授权及安装确认。两个阶段之间不卸载、不清数据，不使用 adb 安装高版本候选。
4. 包管理器报告高版本已安装后执行 `phase=verify`，要求 `passed-verify`；候选 BuildConfig、已安装版本与缓存版本必须一致，升级后不得继续提示安装相同版本。

Android 17 的真实 Beta.2 已通过 prepare、stage-install 和生产缓存校验，但其来源设置默认是 “Ask every time”。旧 Beta.2 的前置 `canRequestPackageInstalls` 检查会把该状态引导回设置页；本轮保留按次授权，尚未完成该系统的高版本按钮安装路径，不将 API 26 的成功外推到 Android 17。原有双系统同版本覆盖记录仍然有效；ARM64 真机及完整线上高版本更新仍未验证。

## 已下载缓存失效恢复

安装前的生产校验现在通过 `Updates.prepareInstall` 串行执行。先确认缓存仍属于本次更新，再验证大小、摘要、包名、版本和签名；校验失败时只清理应用自己的更新 APK 与“已下载”标记，使下一次显式操作重新下载，不反复提示安装同一坏包。过期页面发出的旧版本安装校验请求不会删除较新版本的缓存，正常有效缓存继续保留。该处理不自动重试下载、不改变来源授权或系统安装确认，也不接触配置与 Keystore。

API 26 的更新完整性用例已验证：损坏包经原始校验仍保留下载提示的缺陷前提、新安装准备拒绝并清理坏缓存、有效缓存通过，以及旧版本校验请求失败后较新缓存仍可通过完整校验。原有错误签名、大小/摘要/版本和受限 Provider 检查仍执行；默认用例数量不变。
