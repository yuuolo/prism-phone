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

此限制指已发布旧 Beta.2 自身的按钮流程；下节另记录系统文件管理器回退及新客户端按次授权的实际原签名验证，不将二者冒充为旧按钮已通过。

## 已下载缓存失效恢复

安装前的生产校验现在通过 `Updates.prepareInstall` 串行执行。先确认缓存仍属于本次更新，再验证大小、摘要、包名、版本和签名；校验失败时只清理应用自己的更新 APK 与“已下载”标记，使下一次显式操作重新下载，不反复提示安装同一坏包。过期页面发出的旧版本安装校验请求不会删除较新版本的缓存，正常有效缓存继续保留。该处理不自动重试下载、不改变来源授权或系统安装确认，也不接触配置与 Keystore。

API 26 的更新完整性用例已验证：损坏包经原始校验仍保留下载提示的缺陷前提、新安装准备拒绝并清理坏缓存、有效缓存通过，以及旧版本校验请求失败后较新缓存仍可通过完整校验。原有错误签名、大小/摘要/版本和受限 Provider 检查仍执行；默认用例数量不变。

## Android 17 按次授权与连续原签名更新

新客户端在 API 37 起先完成已下载包的生产校验，再交给系统安装器处理来源授权。它不再以 `canRequestPackageInstalls()==false` 将 “Ask every time” 反复引导回设置页；应用不授予权限，系统仍负责来源同意、拒绝和最终安装确认。较旧平台的原有前置提示保留。本次验证使用独立的 `PrismInstallerCI` / Android 17（API 37.2、16 KiB、Google APIs）模拟器；不外推所有厂商系统都提供相同选项。

先使用普通调试签名夹具完成三项真实 UI 验证：

| 场景 | 观察结果 |
| --- | --- |
| 破坏已校验缓存后点击安装 | 在系统安装器之前拒绝坏包，页面恢复“下载并安装更新”，未请求来源授权 |
| 有效缓存，系统选择 Only this time，再确认 Update | code 3→4、UID 保留；安装后来源仍为 Ask every time，未选 Always allow |
| 有效缓存，系统选择 Don't allow | code 3 未改变，缓存保留，可再次由用户显式尝试 |

调试更新夹具保留 `REQUEST_INSTALL_PACKAGES` 声明，避免将权限声明被移除误认为按次授权未持久化；它没有业务代码，因此上述调试夹具本身不证明实际升级后的配置/Keystore 保留。`InstallerStageInstrumentation` 只在显式选择、模拟器及 debuggable 目标上准备本地测试缓存，退出后由正常应用和系统 UI 处理安装；不授予来源权限，不自动确认安装，不属于默认 JUnit 用例。

随后在同一独立模拟器的新隔离安装中完成真实原证书连续更新：

1. 安装真实已发布 Beta.2（code 3），prepare 保存旧配置与 UID 摘要。生产校验器验证本地 code 4 原签名候选；仅将已核对 SHA-256 的公开 APK 文件复制到测试 Downloads，通过实际系统文件管理器和系统本次安装确认完成 3→4。没有使用旧 Beta.2 的受限安装按钮，也没有对 Prism 授予长期来源权限。
2. 当前 code 4 客户端准备更高的 code 5 原签名缓存，经自身“安装已下载的更新”按钮进入系统 Only this time，再确认 Update，完成 4→5。两个高版本候选均没有通过 adb 安装。
3. 两次 `passed-verify` 均通过：原证书、从真实 Beta.2 延续的 UID、Keystore、节点/凭据/来源/ID/收藏/选择和旧规则迁移一致，新内核配置校验通过，相同版本不再被提示为可更新。来源设置重新打开并确认显示实际 code 5 版本后，Ask every time 仍选中、Always allow 未选中，AppOps 未留下长期允许。

code 4/5 与对应辅助 APK、源文件/Gradle/APK 摘要分别保存在忽略目录的 `per-install-v4/`、`per-install-v5/`，不覆盖 API 26 早期验收文件或已发布资产；仓库仍为 code 3。辅助 stage-install 要求连续验证的 UID 和配置摘要一致，候选 BuildConfig 高于当前安装版本，才允许准备下一份本地已校验缓存。签名材料不上传。

这些是**本地缓存到正常安装器及连续数据保留**的证据，不是线上新版本检查/下载验收；真实 ARM64 设备仍未覆盖。旧 Beta.2 自身在 Ask every time 状态下的按钮限制保留，已验证可用系统文件管理器回退，新客户端自身的按次授权路径已通过。另保留了一次带安装夹具元数据直接运行默认功能组时的节点搜索可见性断言失败；清理该专用测试数据后，相同代码的默认 5 项全部通过，未放宽搜索断言。

## 已发布旧客户端的真实线上检查与下载

在专用 `PrismInstallerCI` 模拟器保存上述证据后，清理该隔离安装并安装真实已发布 Beta.1（code 2），APK SHA-256 为 `160c36e94947a1224f0206b1dcd1937f36c1c194e41fe4dff354ce30fe698120`，证书与上文原证书一致。正常应用启动后从旧仓库兼容通道发现 Beta.2，更新页显示真实发布说明；滚动后点击“下载并安装更新”，实际 HTTPS 下载和生产校验完成后进入旧客户端的来源授权提示。未预置更新元数据或 APK 缓存，也未授权长期来源权限。

随后才安装原证书辅助 APK，显式执行 `phase=verify-online` 并得到 `upgradeAcceptance=passed-verify-online`。该阶段只读取缓存，要求真实 Beta.1、原证书、模拟器、Beta.2 的旧仓库 URL、已发布摘要 `6b27d0821a50d92b078b8bda258028b452d4c377f94f8f08a7877b3a2d77466f` 和大小 22,992,525 字节完全一致，再调用实际已安装旧客户端的 `Updates.verifyDownloaded` 复核包名、版本和签名；不写入元数据、不创建下载缓存、不执行安装。

本地证据保存在忽略目录 `artifacts/online-upgrade-acceptance/`，包括初始安装版本、正常更新页/下载中/来源提示 XML、只读校验日志及结果。本次补齐的是**已发布 Beta.1→Beta.2 的真实线上检查与下载、旧地址兼容**；安装步骤由前文独立记录，不拼接成一次连续端到端安装。未发布完整版的未来更新清单与新高版本下载，以及 ARM64 真机仍待验收；没有新发布或修改线上资产。
