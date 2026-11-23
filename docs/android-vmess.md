# Android VMess 本地候选验收（未发布）

本地开发候选已开放 TCP/TLS VMess AEAD 导入；已公开的 Beta.9 网络恢复修复包不包含此功能。只有独立服务端互通与 Android TUN 验收同时通过才计入候选证据，不能把共享内核实现当作已发布。包名、签名及更新通道未更改；iOS 与 HarmonyOS NEXT 暂停。

## Android 专项实测

本地候选 40 项手机 Rust、7 项 JVM、双架构 JNI、Debug/Release 与双 Lint 通过。Android 8 / API 26 对接 Xray 26.11.9，Android 17 / API 37 / 16 KiB 对接 V2Fly 5.53.0，分别通过 `VmessTest.independentVmessTunDnsGroupsChainAndRecovery`（31.086 秒、42.125 秒）。API 26 测试 auto、aes-128-gcm、chacha20-poly1305，API 37 另测 none、zero；每轮断开后修改两处节点 cipher，并断言修改数量。

各 cipher 通过普通应用 socket 经 TUN 的严格证书 TLS/HTTP、fake-IP 域名恢复后的 1200 字节 UDP 原样回显、代理 DNS 与节点流量计数；随后验证 SOCKS→VMess 双跳 TCP/UDP/DNS、网络重建后同会话与本地混合代理、真实 url-test 候选选择、错误 UUID 拒绝而不回落直连。结果保存于 `artifacts/vmess-candidate-api26-evidence.json` 与 `artifacts/vmess-candidate-api37-evidence.json`，均为 `complete:true`。外层 VMess TLS 的有效服务器正向互通尚未覆盖；内部 HTTPS 不能替代这项证据。

另通过 Android 17 独立 180 秒强制 IDLE：前置 instrumentation 退出后正常 UI 启动，使用 SOCKS→V2Fly VMess 链，无后台保活流量；休眠前、中、恢复后均为冷 DNS/fake-IP、严格 TLS、HTTP 200，PID 12700 和 VPN 111/tun0 保持不变，用户断开不复活，断开对照拒绝。`artifacts/vmess-background-api37.json` 的 `mode:vmess-chain`、`ok:true` 标识其与旧 SOCKS 后台测试的区别。API 26 的专项后台也已补齐，见下述记录；新远端 CI 尚待完整结束。

后续配置回归复现 Clash/sing-box 无效端口被 `as u16` 截断的问题，VMess 现明确拒绝零、负值、溢出、浮点及非数值端口，URI 同样拒绝零；其它协议解析路径未改。`artifacts/vmess-port-before.log` 保留失败，`artifacts/vmess-port-after.log` 三项跨格式回归、`vmess-port-core-regression.log` 90 项内核与 `vmess-port-mobile-regression.log` 40 项手机策略通过。上述 Android 流量实测发生在此参数修正之前，不能冒称已重新运行全部专项。

## 已修改与验证

共享快照的 VMess 只实现 AEAD，却曾忽略非零 `alterId`。新增回归先复现旧行为，再改为明确拒绝非零值。依据 [V2Fly AEAD 配置说明](https://www.v2fly.org/v5/config/proxy/vmess.html) 与[协议格式](https://www.v2fly.org/en_US/developer/protocols/vmess.html)，不静默将旧式认证配置改成另一种认证。该改动仅在手机仓库，未同步桌面。

Windows 本地最新共享内核 90 项单元、2 项跨格式参数与手机策略 39 项回归通过，记录为 `artifacts/vmess-parameters-core-regression.log`、`artifacts/vmess-parameters-mobile-regression.log`。独立互通入口为 `crates/prism-core/tests/vmess_interop.rs`，默认 ignored，必须显式指定经校验的服务端运行；忽略状态不计为互通通过。服务端、目标 TCP/UDP 回显均仅监听回环地址，路由只允许两个实际回显端口，其余目标拒绝。测试结束或 panic 时终止并回收子进程；不在 APK 中打包外部服务端。

| 独立服务端 | 已通过的本地实际范围 |
| --- | --- |
| [Xray 26.11.9](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9) | auto、aes-128-gcm、chacha20-poly1305；各 70,000 字节 TCP；1/1200/8000 字节 UDP；错误 UUID 在 5 秒观察内未将数据送达 TCP 回显目标 |
| [V2Fly 5.53.0](https://github.com/v2fly/v2ray-core/releases/tag/v5.53.0) | 上述三项及 none、zero 配置；各 70,000 字节 TCP；1/1200/1900 字节 UDP；同样的错误 UUID 目标计数检查 |

记录分别为 `artifacts/vmess-interop-xray-final.log`、`artifacts/vmess-interop-v2fly-final.log`。本轮为 TCP 传输，不含外层 TLS、WS、gRPC、Reality 或 Vision。

## 尚未通过与证据边界

2026-11-22 最新参数修正后的 API 26 专项首次运行失败：auto 已完成，下一阶段的公共 TLS 上游关闭连接（`vmess-port-api26.log`、`vmess-port-api26-failed-evidence.json`）；相同 APK 单次复测通过，31.167 秒（`vmess-port-api26-recheck.log`、对应 evidence）。没有修改 TLS 断言，也不把复测通过当作首次失败已修复；根因仍需定位。分支 CI 45034871491 的手机 40 项、Linux 内核 86 项通过，但旧 `anytls_wire::records_follow_the_padding_scheme` 在首包明文长度 96 的范围断言失败，后续互通和模拟器步骤未执行；保留 `artifacts/vmess-ci-45034871491-failed.log`，不能声称 VMess 远端 CI 已通过。

后续数据完整性修正：VMess UDP 原先会对超长报文取前缀发送，现按实际标准帧长度校验；计入认证标签与填充后超过 2^14 的报文明确关闭该 UDP 会话，不截断或拆成多个报文。无法区别于流结束的空报文也明确拒绝。检查使用实际编码长度，明文模式的合法 16384 字节 payload 不被统一降低上限。本地 TCP 字节捕获回归验证非法输入只留下请求头、无 payload 帧，另验证各 body cipher 合法边界完整还原。记录为 `artifacts/vmess-udp-boundary-before-exact.log`（旧行为失败）及 `artifacts/vmess-udp-boundary-after.log`（修复后通过）。修复后两类独立服务端的既定范围重新通过，记录为 `artifacts/vmess-udp-v2fly-common.log`、`artifacts/vmess-udp-xray-large.log`；没有将 V2Fly 的 8 KiB 失败算作解决。

参数保真修正：Clash `alterId`、sing-box `alter_id` 及分享链接 `aid` 不再把负值、浮点、溢出或无效类型回落/截断为 0。合法 u32 数值保留供构造器判断，仅 AEAD 0 可被构造；缺省值仍为 0。跨格式两个回归见 `vmess_parameters.rs`，先复现负值变 0，再通过格式/边界检查（`artifacts/vmess-parameters-before.log`、`artifacts/vmess-parameters-after.log`）。手机候选导入时也调用构造器校验 UUID/cipher/alterId；WS/gRPC、跳过证书验证及其它未支持字段继续拒绝。

- V2Fly 的 8000 字节 UDP 未通过，原始记录 `artifacts/vmess-interop-v2fly.log` 保留。其 [packet writer](https://github.com/v2fly/v2ray-core/blob/v5.53.0/common/crypto/auth.go) 的封包大小受 [2048 字节缓冲](https://github.com/v2fly/v2ray-core/blob/v5.53.0/common/buf/buffer.go)限制；不能据此宣称所有服务端支持大报文，也不把 UDP 拆成多个数据报来假装保留原报文。`PRISM_VMESS_LARGE_UDP=1` 保留显式大报文探测入口。
- Xray 本轮版本不接受 none/zero，见其[安全类型定义](https://github.com/XTLS/Xray-core/blob/v26.11.9/common/protocol/headers.proto)，没有把拒绝当作 Prism 互通通过。
- 首次 Xray TCP 超时来自其默认 final rule 阻止回环目标；诊断日志证明 VMess 请求已经被认证接收。夹具只对两个回显端口精确放行，未改认证/加密断言。原始失败见 `artifacts/vmess-interop-first-failure.log`、`artifacts/vmess-interop-diagnostic.log`；none/zero 拒绝见 `artifacts/vmess-interop-finalrules.log`。
- 本轮包含上述修复的 ARM64/x86_64 JNI、Debug/Release APK 已构建通过，Release ZIP 16 KiB 对齐检查通过（`artifacts/vmess-parameters-native.log`、`artifacts/vmess-parameters-android-build.log`）。Android 17 / 16 KiB 的既有 SOCKS VPN 真实流量及加密配置回归通过（`artifacts/vmess-parameters-existing-vpn-api37.log`，18.609 秒），APK 内 x86_64 JNI 已核对与本轮 strip 后构建一致。此结果只证明既有路径未回归，不是 VMess TUN 验收。该记录属于早期兼容性检查；后续 VMess TUN 专项结果见本文前述实测，两端专项后台均已通过；新远端 CI 尚待完整结束。汇总与源码/产物摘要见本地 `artifacts/vmess-integrity-parameters-proof.json`。

## 可复现命令

Linux x86_64 CI 已配置 `bash scripts/android/test-vmess-interop.sh`：固定官方版本与 SHA-256，校验后执行 Xray 大报文模式、V2Fly 常规报文模式；已通过 shell 语法检查，尚未执行远端 Linux 作业。Windows 本地官方 ZIP 摘要为：

- Xray：`1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d`
- V2Fly：`46ee170d031ea3be79cc583e61e6335a612e4c87925deed2a7179b0a5fb79f60`

PowerShell 示例如下，服务端路径须指向已核对官方摘要的独立二进制：

```powershell
$env:PRISM_VMESS_SERVER_BIN='D:\claude\prism-phone\artifacts\v2fly-v5.53.0\v2ray.exe'
$env:PRISM_VMESS_SERVER_KIND='v2fly'
$env:PRISM_VMESS_LARGE_UDP='0'
cargo test -p prism-core --test vmess_interop --locked -- --ignored --nocapture
```

Xray 切换 `SERVER_KIND=xray` 并使用其二进制；大报文探测设置 `PRISM_VMESS_LARGE_UDP=1`。普通命令未执行该模式时，不算作大报文验收。

2026-11-23 补齐 API 26 / Xray 的独立 180 秒 Doze：artifacts/vmess-background-api26.json 为 mode=vmess-chain、ok=true，PID 3978 与 VPN 102/tun0 不变，三个阶段均通过冷 DNS/fake-IP、严格 TLS 和 HTTP 200，用户断开不复活、断开对照拒绝。测试后正常关闭一次性 AVD 并清理核实过的夹具，未操作原签名升级样本。

AnyTLS CI 失败已定位为测试对填充边界的错误假设：96 字节首包若随机目标为 100–103，放不下七字节头及正长度填充，应原样发送。断言现只在实测首包载荷长度一致且处于该边界时接受；没有修改协议运行行为。另补确定性 96–104 边界回归，本地 6 项 AnyTLS 线协议与该单元通过。新 CI 45115934125 的策略与独立 Xray/V2Fly 互通步骤已通过，其余构建/模拟器仍在执行；不把阶段通过当作完整 CI 通过。
