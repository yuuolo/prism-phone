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
