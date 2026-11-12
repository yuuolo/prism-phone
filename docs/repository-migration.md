# 仓库拆分与更新兼容

2026-11-12 从 `yuuolo/prism` 的合并提交 `1351bf5d142499522a89ca9384ee323d03447fe8` 导出已跟踪的 Android、JNI、构建脚本及移动文档。原有开发历史保留在桌面仓库的 `prism-codex` 分支及 `master` 合并历史中；本仓库从该源码快照开始独立记录历史，保留 MIT 许可证。

`crates/prism-core` 同步自上述提交，是手机端独立构建使用的源码快照。后续同步桌面修复时，需在提交说明记录来源提交并通过手机策略、VPN 和 DNS 测试；手机改动不自动同步到桌面。

手机端后续局部扩展：`crates/prism-core/src/tunnel.rs` 增加按实际出口与规则类别的累计载荷计数，供跨会话历史统计使用，累计量跨连接结束和 Hub 重载保留。该扩展仅存在于手机仓库，未同步修改桌面仓库；`mobile_traffic` 真实 TCP/UDP 与手机 VPN/DNS 验收用于检查兼容性。

## 更新入口

本机代理服务增加 `inbound.rs` 的受控监听入口、关联式 SOCKS UDP 与取消清理，`tunnel.rs` 增加任务中止时连接表清理和受限 UDP 会话，`net.rs` 增加 Android VPN 保护的监听 socket。原有桌面监听入口保持原行为；手机服务独立管理生命周期，断开 VPN 时回收。同步上游时需保留并重跑本机代理、流量、DNS 和网络恢复验收。

- 新构建检查 `https://github.com/yuuolo/prism-phone/releases/download/android-updates/android-update.json`。
- 已安装的 Android 0.2.0-beta.1 只接受 `yuuolo/prism` 的 APK 下载路径。因此旧仓库的 `android-updates/android-update.json` 必须继续维护，不能直接改成指向新仓库的 APK。
- `scripts/android/publish.ps1` 从本仓库通过构建及模拟器验证的 CI 下载 APK，本机签名，在本仓库发布，同时向旧仓库镜像同一个签名 APK，并生成使用旧下载路径的兼容清单。两边 SHA-256、版本、包名及证书相同。脚本拒绝回退版本或替换同版本 APK。
- 迁移时新通道先指向原有 Beta.1 的旧仓库 APK；没有把未经验证的新源码冒充为已发布二进制。下一次正式发布必须增加 `versionCode` 和版本名。
- 2026-11-12 已发布 `0.2.0-beta.2`（versionCode 3），由手机仓库提交 `180b7dc` 的完整 CI 产出并本机原证书签名。新旧通道均指向各自仓库的同一签名 APK，大小及 SHA-256 一致；后续发布继续递增版本。
- Alpha.1 没有内置升级检查，需要手动安装一次 Beta。

## 本机签名与桌面隔离

自动优选扩展了手机快照的规则组初次健康检查延迟配置及 UrlTest 重建后选择保留。一般配置仍默认 1 秒开始；手机网络重建 payload 将初次检查延后 300 秒，以约束网络抖动时的探测。该修改未同步桌面仓库，需在后续同步上游时保留手机恢复与优选测试。

发布仍使用原有 `dev.prism.android` 包名和原始签名证书。私钥及密码保存在被 Git 忽略的 `android/.signing/`，不提交、不上传 GitHub Secrets。发布只上传公开 APK、校验和及更新清单。

旧仓库仅保留移动端入口说明与兼容发布资产；桌面应用继续使用原有 `latest.json`。安卓发布始终 `--prerelease --latest=false`，不得覆盖桌面稳定版更新通道。
