# Prism Android 0.2.0-beta.7

包含 Beta.6 的按应用 VPN 包含/排除与节点质量曲线，并修正主页范围提示：显示当前应用接管策略，DNS 保护说明明确仅作用于进入 VPN 的应用。避免选择部分应用后仍显示旧版“全设备接管”。路由与探测实现未变。

按应用分流是在系统 VPN 层选择经过或绕过，不是每个应用指定不同节点。进入 VPN 的应用继续遵循规则/全局/直连；绕过应用的 DNS、流量和广告请求不进入 Prism。最多选择 256 个包名，无需所有应用列表权限，修改需断开。节点质量读取当前候选已有的最近 10 个真实探测，不额外测速；失败单独标记，重建或断开清空。

高级协议、完整 Clash/sing-box 配置与 providers、JavaScript 配置覆写、自定义多组/规则集/按应用指定代理、热重载、完整 DNS/IPv6、应用流量和地图仍在开发。完整范围见 `docs/android-advanced.md`；本次不是七项高级目标全部完成。

保留原签名、包名、加密配置和 Beta.2 以来的升级兼容。主仓库 prism-phone 发布，旧仓库继续同包镜像和兼容更新清单，不修改桌面 latest。真机长时后台、耗电、切网、共享和实际账号仍待验收，继续保持 Beta；iOS 与 HarmonyOS NEXT 暂停。

实际原签名 APK 从已发布 Beta.6 经应用按钮及系统 Only this time/Update 覆盖，延续原 Beta.2 的 UID、Keystore、节点/凭据/来源/收藏/选择与规则校验通过。升级前通过 Beta.6 界面保存的应用包含名单也保留，Beta.7 主页已核对正确显示“仅所选 1 个应用及 Prism 经过 VPN”和限定范围的 DNS 说明；来源保持 Ask every time。本次安装从已校验缓存开始，不算作本次线上检查/下载验收。

APK：24,241,771 字节，SHA-256：`e38c8502b1d32a8e2edc15d0f0c14798c318f8d0b2d94bcc2fd55b8e836e53eb`。

[发布 CI 44451687529](https://github.com/yuuolo/prism-phone/actions/runs/44451687529)（源码 `410f29a`）全部通过：双架构 Debug/Release、双 Lint、34 项手机 Rust、101 项 Linux 共享内核回归、7 项 Android 单元测试、Release 权限检查，以及 Android 8 与 Android 17/16 KiB 各 23 项完整回归和各自独立 180 秒 Doze。两份后台报告已核对强制 IDLE、原进程与 VPN 不变、冷 DNS、严格 TLS/HTTP 200、断开不复活及断开对照拒绝。
