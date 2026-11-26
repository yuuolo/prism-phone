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


## 首批最终软件验收回执（未发布）

最终代码为 `89863174fc736e7c8ade565f2045203c5e496d3d`，包含 `d8dc54a` 的草稿与脚本基础，以及后续 YAML 展开限制。[CI 45771936781](https://github.com/yuuolo/prism-phone/actions/runs/45771936781) 的构建和两套 Android 任务全部成功。

- 42 项手机 Rust 单元测试（含 YAML 资源限制）、4 项文档和 6 项脚本专项，以及 4 项配置防降级回归通过；现有 Linux 内核、独立服务端互通、JVM、双架构 JNI、Debug/Release 和双 Lint 回归通过。
- Android 8 与 Android 17 各通过 32 项主回归和两项既有传输专项，共 68 项，包含实际 JNI 脚本、资源拒绝后恢复、加密草稿保存/冲突、页面预览及过量 YAML 展开拒绝。现有协议仅回归，不开放新的协议。
- 已下载并校验两份设备归档的官方 SHA-256，逐项核对共 8 份独立 180 秒后台报告：强制 IDLE、原 PID/VPN、三个阶段的冷 fake-IP DNS、严格 TLS/HTTP 200，以及断开保持停止/负对照拒绝均通过。Android 17 实测页大小 16384。
- 未签名 Release APK 为 26,797,340 字节，SHA-256 `7870ae04a2ea4528d8487e9663cc805540d8e657aa73055323a9fb303c1c2fe4`；归档官方 SHA-256 `cae67a9f6368eddd4d402b3cdf5b6334a8939a51a9de44d68169ebd0dc32af80` 已回读匹配，16 KiB zipalign 检查通过。
- 原始报告与汇总保留在本地 `artifacts/full-config-ci-45771936781/`。当前工作区忽略的双架构 JNI 已从该已校验 APK 回填，避免后续误打包旧分支原生库；后续修改 Rust 后仍须重新构建。

较早的 CI 45769632276 对应 `d8dc54a`，构建成功，设备任务在 YAML 补强后被主动取消，不能算作整轮通过。其 Android 17 已完成的 31 项前台测试仅为旧提交的部分证据，不替代最终 CI。先前本地 Android 17 页面首次显示慢导致的失败仍按上文保留，不宣称其根因已解决。

本轮没有创建 Release、更新清单或修改公开通道，仍公开 Beta.9。code 16 尚未进行原签名包的真实覆盖升级，本轮不沿用 code 14 的升级结果；发布前须重新验收。无真机长时、厂商切网或耗电新证据。当前仍是完整配置第一阶段，providers 获取与缓存、sing-box、真正运行应用/热重载及其余高级目标继续开发。
