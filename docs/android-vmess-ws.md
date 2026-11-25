# VMess WebSocket 开发候选（未发布）

接续基础 VMess AEAD TCP 候选。本轮在 Android 导入策略中增加 VMess 的 WebSocket，保留 UUID/cipher/alterId 构造校验及严格证书要求；其它协议的 WS、gRPC、Reality/Vision 等仍须分别接入。没有改变公开 Beta.9 或升级通道。

配置使用 [V2Fly WebSocket 配置](https://www.v2fly.org/config/transport/websocket.html) 的 path、Host 语义。Clash `ws-opts`、sing-box `transport` 的移动导入→会话生成及 VMess 分享链接参数保留检查通过。手机候选拒绝路径/Host 中的控制字符与空白，并约束长度。其它自定义 HTTP 头、前置数据和完整配置兼容仍未完成，不能将基础 path/Host 支持当作全量 WS 配置支持。TLS 外层有效服务端正向证据仍需补齐，未放宽 skip-cert-verify。

## 已取得的本地证据

- 官方版本及摘要校验后的 Xray 26.11.9：WS 三种 AEAD 配置，70,000 字节 TCP、1/1200/8000 字节 UDP、错误 UUID 与错误路径拒绝；`artifacts/vmess-ws-xray-path-interop.log`。
- V2Fly 5.53.0：WS 五种配置（另含 none/zero），相同 TCP 与 1/1200/1900 字节 UDP，以及两种拒绝；`artifacts/vmess-ws-v2fly-interop.log`。没有宣称 V2Fly 的 8 KiB UDP 已解决。
- 原 TCP 对两种服务端重新通过；`vmess-ws-existing-tcp-xray.log`、`vmess-ws-existing-tcp-v2fly.log`。CI 独立互通脚本现分别执行 TCP/WS，两种服务端都在循环内。
- 40 项手机 Rust、移动会话参数 1 项、核心跨格式参数 4 项、8 项 JVM、双架构 JNI、Debug/Release 与双 Lint 通过。APK 内 x86_64 JNI 与本轮 strip 后产物摘要一致：`838712bc2d312d03a3add50390ca4909f6fe8a1c86bf44f47b2557b1befce708`。
- Android 8 / API 26 对接 Xray WS，实际 TUN 严格 TLS、1200 字节 UDP、代理 DNS、双跳 TCP/UDP、重建与本地代理、url-test 自动优选、错误凭据拒绝通过：`vmess-ws-api26.log`，14.469 秒；`vmess-ws-api26-evidence.json` 为 complete=true、transport=ws，包含三个 cipher 及各场景结果。

- API 26 的 WS 双跳独立 180 秒 Doze 通过：`vmess-ws-background-api26.json` 为 mode=vmess-ws-chain、ok=true；PID 4806 和 VPN 108/tun0 不变，三个阶段冷 DNS/fake-IP、严格 TLS/HTTP 200，断开不复活与断开对照均核对通过。没有测试中的保活流量，也不是耗电或真机证明。

## 尚待完成

API 37/16 KiB 对接 V2Fly 的五种配置与 WS 后台、新完整远端 CI、最终候选原签名升级仍须验收。后台工具已增加独立 WS 种子标记与 mode，CI 会先完成 TCP，再切换独立 WS 服务端，重新安装标准 runner 后执行 WS 前台与后台测试。不能用较早 TCP 的 CI、原签名升级或后台报告代替 WS 结果。

真实设备、实际节点账号与物理无线/长时耗电条件仍缺失。全部外部服务端仅用于回环夹具，不随 APK 分发。此候选尚未发布，完整版目标继续保持未完成。
