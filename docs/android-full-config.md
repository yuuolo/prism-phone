# Android 完整配置工作进度

2026-11-26 按用户要求暂停新增高级协议接入，先处理完整配置与 JavaScript 覆写、高级分流、运行中修改、代理组扩展、DNS。iOS 和 HarmonyOS NEXT 继续暂停。

当前工作分支 `codex/android-full-config` 从已验收的 gRPC code 14 源码 `d5388b3` 建立。Reality/Vision 的未验收代码独立保留在 `codex/android-vmess-candidate` 的 `5884d56`，不随此分支开放。当前私有开发版本使用 versionCode 16；包名、原签名密钥、加密配置及原更新通道保留，未发布新版本。

已实现第一阶段基础：

- 独立、版本化的 Clash 文档，保留源配置和脚本；脚本修改副本，输出保留未知扩展字段。
- QuickJS 执行 `function main(config, profileName) { return config; }`，通过参数传递配置与名称。每次创建独立运行环境，无文件、网络、模块加载或 Android 桥接能力。
- 输入/输出 4 MiB、脚本 128 KiB、引擎堆 64 MiB、栈 256 KiB、500 ms 中断预算；拒绝异步返回、数组、空值与不可序列化结果。错误不回显脚本异常或凭据。中断是引擎执行预算，不是操作系统进程隔离。
- 不调用会静默修正配置的 `sanitize`；拒绝解析警告、重复/保留名称、空组、缺失成员/provider/规则集引用与组循环。组图校验使用迭代算法。
- YAML 在进入脚本前按展开后的字符串字节数、131072 个节点和 64 层深度限制解析，保留普通别名引用，拒绝重复键、多文档和非有限数值；源文件字节限制不能代替展开后的限制。
- Android JNI 提供预览和统计，始终返回 `activated: false`，不会修改偏好设置或当前 VPN。

本地主机 `config_script` 6 项、`config_document` 4 项通过，见 `artifacts/full-config-document-tests.log`。Android 8 专用调试实例通过 4 项 JNI/存储用例（1.149 秒）及后补的页面操作用例（21.403 秒）；Android 17 / 实际 16 KiB 实例最终完整 5 项通过（19.057 秒），分别见 `artifacts/full-config-instrumentation-api26.log`、`artifacts/full-config-ui-api26.log`、`artifacts/full-config-instrumentation-api37-final.log`。加密保存用例验证原节点/设置保留、冲突及脚本失败不落盘，并在 finally 恢复原配置密文。双架构 JNI、Debug/Release APK、8 项 JVM 与双 Lint 通过，Release APK 的 16 KiB zipalign 检查通过。

Android 17 首轮 5 项中页面标题断言失败，其余 4 项通过；完整原始失败为 `artifacts/full-config-instrumentation-api37.log`，logcat 为 `artifacts/full-config-api37-first-logcat.txt`。当时系统记录页面首次显示耗时 13.478 秒；随后同一生产代码的页面复验通过（30.747 秒），再由最终完整 5 项通过。仅增加测试失败取证，未放宽断言或增加生产超时；首轮失败不算通过，也不宣称冷启动延迟根因已解决。

已补充手机草稿编辑入口和现有加密存储，保存前重新校验并检查草稿是否已被其它操作修改，不改变正在使用的会话。尚未完成：sing-box 完整导入、providers 有界获取/缓存/快照、完整规则语义校验与 Android UID 路由、多代理组实际流量、原子热重载及切网后保留新配置、DNS 策略与 IPv6 双栈验收。预览通过不代表可直接启动或已完成全部兼容。

Android 依赖启用 QuickJS `bindgen`，因为上游没有预生成 Android 绑定。Linux CI 安装 `libclang-dev`。仓库构建脚本已自动处理 Windows LLVM 标准头目录和 NDK sysroot，默认 LLVM 安装目录可由 `LIBCLANG_PATH` 覆盖；`cargo-ndk` 会覆盖下划线形式的 bindgen 参数，使用连字符 target 形式传入。不能直接使用旧分支遗留的 JNI 文件打包。
