# VMess WebSocket 开发候选（未发布）

首次完整 CI 固定为提交 8e6b957，运行 45614298228 已失败，不得用于签名升级或发布。下一项 [gRPC 独立互通准备](android-vmess-grpc.md) 仍仅为核心互通测试，手机 gRPC 尚未开放。

接续基础 VMess AEAD TCP 候选。本轮在 Android 导入策略中增加 VMess 的 WebSocket，保留 UUID/cipher/alterId 构造校验及严格证书要求；其它协议的 WS、gRPC、Reality/Vision 等仍须分别接入。没有改变公开 Beta.9 或升级通道。

后续候选递增为 code 13 / 0.2.0-beta.10，避免与已用于原签名验收的内部 code 12 混淆。code 13 的 8 项 JVM、Debug/Release、双 Lint 与 16 KiB 对齐通过（`artifacts/vmess-ws-code13-build.log`）。code 12 的较早回执不覆盖本轮候选。

配置使用 [V2Fly WebSocket 配置](https://www.v2fly.org/config/transport/websocket.html) 的 path、Host 语义。Clash `ws-opts`、sing-box `transport` 的移动导入→会话生成及 VMess 分享链接参数保留检查通过。手机候选拒绝路径/Host 中的控制字符与空白，并约束长度。其它自定义 HTTP 头、前置数据和完整配置兼容仍未完成，不能将基础 path/Host 支持当作全量 WS 配置支持。TLS 外层有效服务端正向证据仍需补齐，未放宽 skip-cert-verify。

## 已取得的本地证据

- 官方版本及摘要校验后的 Xray 26.11.9：WS 三种 AEAD 配置，70,000 字节 TCP、1/1200/8000 字节 UDP、错误 UUID 与错误路径拒绝；`artifacts/vmess-ws-xray-path-interop.log`。
- V2Fly 5.53.0：WS 五种配置（另含 none/zero），相同 TCP 与 1/1200/1900 字节 UDP，以及两种拒绝；`artifacts/vmess-ws-v2fly-interop.log`。没有宣称 V2Fly 的 8 KiB UDP 已解决。
- 原 TCP 对两种服务端重新通过；`vmess-ws-existing-tcp-xray.log`、`vmess-ws-existing-tcp-v2fly.log`。CI 独立互通脚本现分别执行 TCP/WS，两种服务端都在循环内。
- 40 项手机 Rust、移动会话参数 1 项、核心跨格式参数 4 项、8 项 JVM、双架构 JNI、Debug/Release 与双 Lint 通过。APK 内 x86_64 JNI 与本轮 strip 后产物摘要一致：`838712bc2d312d03a3add50390ca4909f6fe8a1c86bf44f47b2557b1befce708`。
- Android 8 / API 26 对接 Xray WS，实际 TUN 严格 TLS、1200 字节 UDP、代理 DNS、双跳 TCP/UDP、重建与本地代理、url-test 自动优选、错误凭据拒绝通过：`vmess-ws-api26.log`，14.469 秒；`vmess-ws-api26-evidence.json` 为 complete=true、transport=ws，包含三个 cipher 及各场景结果。

- API 26 的 WS 双跳独立 180 秒 Doze 通过：`vmess-ws-background-api26.json` 为 mode=vmess-ws-chain、ok=true；PID 4806 和 VPN 108/tun0 不变，三个阶段冷 DNS/fake-IP、严格 TLS/HTTP 200，断开不复活与断开对照均核对通过。没有测试中的保活流量，也不是耗电或真机证明。
- Android 17 / API 37、实测页大小 16384，对接 V2Fly WS 五种配置全部通过：`vmess-ws-api37.log`，72.321 秒；`vmess-ws-api37-evidence.json` 为 complete=true、transport=ws，逐项确认 auto/AES-GCM/ChaCha/none/zero 的 TUN 收发计数及链式、重建、本地代理、优选与错误凭据拒绝。

API 37 首次后台验收在 ui-connect 阶段找不到按钮，未进入 IDLE（`vmess-ws-background-api37-initial-ui-failure.json`）。后台工具由固定 1 秒启动等待改用已有 15 秒 UI 就绪判定，并补充失败时 XML 捕获；没有增加实际 VPN 连接重试或放宽流量判定。第二次仍未进入休眠，保存的 `vmess-ws-background-api37-final-failure-ui.xml` 明确显示 System UI isn't responding 弹窗覆盖应用。活动日志虽有首次绘制偏晚，仅归因于冷启动等待不充分。

在一次性模拟器关闭无响应的系统界面后，System UI PID 从 1146 变为 10596，实际应用连接按钮恢复可见（`vmess-ws-api37-systemui-recovered.xml`）；随后才执行新的完整后台观察。系统 lastanr 查询未提供 ANR 原因，不能把模拟器图形警告当作已确认的根因。两次失败均保留，不计为后台通过。

恢复后完整 WS 后台验收通过（`vmess-ws-background-api37-recovered.json`，mode=vmess-ws-chain、ok=true）：强制 IDLE 180 秒，PID 11409 与 VPN 110/tun0 保持不变，三阶段均通过冷 DNS/fake-IP、严格 TLS/HTTP 200，用户断开不复活及断开对照拒绝。结束时 System UI 仍为 PID 10596。观察期间未再次干预系统界面；这不是无干预首次冷启动成功的证据。验收后关闭一次性模拟器及核实过的夹具，原签名样本未改动。

## 尚待完成

2026-11-26 核对上述 CI：两端均完成 26 项应用测试，随后在 TCP→WS 夹具切换阶段退出；API 26 保存的 WS 夹具日志明确为前置 SOCKS 端口 19097 的 `EADDRINUSE`，WS 专项未运行。修正仅对非 Windows 的回环 TCP 监听启用 `SO_REUSEADDR`，允许旧连接关闭后立即顺序重绑；不启用 `SO_REUSEPORT`，也不允许替换仍活动的监听。新增活动监听不可替换与真实连接主动关闭后立即重绑两项回归，后者须在 Linux CI 执行；Windows 本地跳过该项。较早下载的 code 13 APK 因 CI 失败保持 unsigned、不可升级，须使用修正后完整 CI 的新产物重新验收。

code 13 的新完整远端 CI 与最终候选原签名升级均已通过，仍未发布。后台工具使用独立 WS 种子标记与 mode，CI 先完成 TCP，再切换独立 WS 服务端，重新安装标准 runner 后执行 WS 前台与后台测试。不能用较早 TCP 的 CI、原签名升级或后台报告代替 WS 结果。

修正后的 [CI 45675078331](https://github.com/yuuolo/prism-phone/actions/runs/45675078331) 固定为 5af7d34，构建及两个模拟器作业均成功。其中 8 项 Python 测试全部执行通过，包含 Linux 主动关闭连接后的立即重绑；两端各 26 项完整回归及 1 项 WS 专项，共 54 项。两份官方摘要核验后的模拟器归档内，六份独立后台报告均检查了 180 秒强制 IDLE、同一进程/VPN、三阶段冷 fake-IP DNS、严格 TLS/HTTP 200、用户断开不复活及断开对照拒绝；WS 前台分别覆盖三种与五种 cipher。回执为 `artifacts/android-candidate-45675078331/ci-proof.json`。

新未签名归档 SHA-256 为 `4f6fc88e68ebf0dd438a15cb7f24c469b839b00133c74016ef4055fc996b5f2a`，官方摘要一致，code 13 / 最低 API 26 / 16 KiB 对齐核对通过。随后才使用原证书本机签名私有验收包，大小 24,352,363 字节，APK SHA-256 为 `81c6b3da86de207143e9fea65739fa9ff934be827ea585af5ac8fee8338cc7ce`。后续 gRPC 修正与专项工具提交不属于该固定源码的候选。

原签名 PrismInstallerCI 样本从 code 12 经正常应用缓存安装按钮、系统 Only this time 和 Update 覆盖至 13；先验证旧样本，再安装隔离源码构建的助手，未清除或卸载主应用。升级后 helper 为 passed-verify，原 Beta.2 延续的节点、凭据、来源、收藏、选择与规则保持，UID 仍为 10230，Keystore 可正常解密；`prism-mobile` 全部一项加密偏好条目的 OuterXml 完全一致。拉取系统实际安装 APK 的摘要与上述候选一致，来源设置选中的仍为 Ask every time，安装来源 app-op 为 deny。回执 `artifacts/android-candidate-45675078331/upgrade-proof.json`，验收后关闭模拟器并保留数据。缓存安装不算本次线上下载证据，未修改公开版本、Release、tag 或更新通道。

真实设备、实际节点账号与物理无线/长时耗电条件仍缺失。全部外部服务端仅用于回环夹具，不随 APK 分发。此候选尚未发布，完整版目标继续保持未完成。
