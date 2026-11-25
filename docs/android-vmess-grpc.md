# VMess gRPC 手机开发候选（未发布）

WS code 13 的完整 CI 运行期间，继续接入下一项 gRPC。当前工作区 code 14 / 0.2.0-beta.10 开发候选仅允许 VMess AEAD 的基础 gRPC；服务名接受缺省/空值或最多 255 字节的 ASCII 字母、数字、下划线、点，拒绝路径覆盖、空白和控制字符。其它协议 gRPC、Reality/Vision、证书跳过等限制不变。本文件不是 Android 功能已交付或已发布的声明。旧 WS CI 因夹具端口重绑失败，修正后的 CI 45675078331 固定使用提交 5af7d34，不包含后续接收边界修正和手机 gRPC。

code 14 的手机 Rust 40 项、gRPC 导入/会话生成 2 项、WS 回归 1 项本地通过（`artifacts/vmess-grpc-mobile-policy.log`），覆盖 Clash/sing-box 的自定义和缺省服务名、长度边界、非法名称及其他协议拒绝。双架构 JNI 正在构建；手机 TUN、链式、DNS、优选、重建、后台及完整 CI 尚未取得本轮证据，不能用下面的核心互通代替。

按 [V2Fly gRPC 配置](https://www.v2fly.org/config/transport/grpc.html) 核对 serviceName 和 Tun 路由。独立测试同时覆盖显式服务名 PrismVmessInterop，以及双方均不设置服务名的缺省配置；使用实际 Go 服务端结果，没有更改运行中的协议实现来满足测试。

| 独立服务端 | 本地已验证范围 |
| --- | --- |
| 官方摘要校验的 Xray 26.11.9 | auto/AES-GCM/ChaCha；每项 TCP 70,000 字节，UDP 1/1200/8000 字节；自定义和缺省服务名；错误 UUID 无目标载荷、错误服务名及时拒绝且无目标载荷 |
| 官方摘要校验的 V2Fly 5.53.0 | 上述三项及 none/zero 配置；相同 TCP，UDP 1/1200/1900 字节；两种服务名及相同拒绝断言 |

日志为 `artifacts/vmess-grpc-xray-interop.log`、`vmess-grpc-v2fly-interop.log`、`vmess-grpc-xray-default.log`、`vmess-grpc-default-before.log`。后一个文件名表示首次缺省行为探测，实际结果为通过，不能将名称中的 before 当作失败。Clash、sing-box 与分享链接的 serviceName 保留回归通过，见 `artifacts/vmess-grpc-parameters.log`（共五项参数测试）。

服务端与目标均仅绑定回环地址，路由精确允许本次 TCP/UDP 回显端口，其他目标拒绝；结束时回收独立服务端。未启用外层 TLS，不是严格 TLS 正向证明；没有改变 V2Fly 大 UDP 的既有未通过边界。

复现：在原独立互通入口设置 PRISM_VMESS_TRANSPORT=grpc，自定义服务名模式设置 PRISM_VMESS_GRPC_DEFAULT=0，缺省模式设为 1。修正夹具后的 CI 45675078331（5af7d34）构建作业 139420335478 已通过，包括 Linux 下两种服务端、自定义与缺省 gRPC 服务名的四轮互通，以及 TCP/WS 既有互通。此时两个 Android 模拟器作业仍在运行；它们仅验收 TCP/WS，不包含 Android gRPC，也不包含后续接收边界修正。

受保护 socket、TUN、链式 TCP/UDP、代理 DNS、候选组、重建与后台仍待专门接入验证。gRPC 其它配置及外层 TLS、实际账号与真机条件继续保留缺口。iOS 与 HarmonyOS NEXT 暂停，没有发布。

## 接收边界修正（不属于 WS 固定候选）

2026-11-26 核对 [gRPC HTTP/2 协议](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md) 后，接收端明确拒绝未协商的压缩标记；声明消息长度超过本实现的 4 MiB 上限时，在等待正文之前拒绝。4 MiB 是本实现的资源策略，不是协议长度字段的最大值。Hunk 长度的未终止、溢出和短正文不再被当作空载荷；流结束仍有半帧时记录截断错误。沿用现有桥接流的关闭行为，不增加直连回退。

新增 `grpc_frames` 三项回归覆盖上述畸形输入、上限声明，以及分片/合并传输的 70,000 字节和空载荷。本地通过，90 项内核单元和 5 项参数回归通过；修正后 Xray/V2Fly 的自定义、缺省服务名共四轮独立互通重新通过，日志为 `artifacts/vmess-grpc-bounded-*.log`。该变化尚需后续 Linux CI；正在运行的 45675078331 不包含它，不以此改动替换该运行的源码归属。此修正完成时手机 gRPC 尚未接入。

手机专项工具已增加可选 `grpc` 传输，使用服务名 `PrismVmessMobile`，前台参数、后台种子及 `vmess-grpc-chain` / `seeded-vmess-grpc-cold-dns-v1` 标记相互对应。两种 Go 服务端的专用回环夹具均启动成功（`artifacts/vmess-grpc-mobile-host-*/fixture.log`），随后回收父/子进程；仪器测试编译通过（`artifacts/vmess-grpc-harness-compile.log`）。这仅是工具准备，不是 Android gRPC 流量验收，默认仍运行原 TCP，尚未加入手机 CI 执行阶段。

后续补充 HTTP/2 实际收发边界回归：内存双工连接上的独立 h2 服务端发送非法压缩标记或超大声明后保持响应体开放，客户端必须在 2 秒界限内关闭，不等待正文或对端 EOF。同步信号确认服务端已校验路由并发送，避免将服务端提前失败误算为通过。`grpc_frames` 现共 4 项通过（`artifacts/vmess-grpc-wire-bounds.log`）；此项不验证公网、TLS 或 Android。
