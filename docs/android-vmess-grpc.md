# VMess gRPC 接入准备（手机尚未开放）

WS code 13 的完整 CI 运行期间，继续验证下一项 gRPC 的共享内核互通。手机白名单仍拒绝 gRPC；本文件不是 Android 功能已交付或已发布的声明，WS 升级验收继续固定使用提交 8e6b957。

按 [V2Fly gRPC 配置](https://www.v2fly.org/config/transport/grpc.html) 核对 serviceName 和 Tun 路由。独立测试同时覆盖显式服务名 PrismVmessInterop，以及双方均不设置服务名的缺省配置；使用实际 Go 服务端结果，没有更改运行中的协议实现来满足测试。

| 独立服务端 | 本地已验证范围 |
| --- | --- |
| 官方摘要校验的 Xray 26.11.9 | auto/AES-GCM/ChaCha；每项 TCP 70,000 字节，UDP 1/1200/8000 字节；自定义和缺省服务名；错误 UUID 无目标载荷、错误服务名及时拒绝且无目标载荷 |
| 官方摘要校验的 V2Fly 5.53.0 | 上述三项及 none/zero 配置；相同 TCP，UDP 1/1200/1900 字节；两种服务名及相同拒绝断言 |

日志为 `artifacts/vmess-grpc-xray-interop.log`、`vmess-grpc-v2fly-interop.log`、`vmess-grpc-xray-default.log`、`vmess-grpc-default-before.log`。后一个文件名表示首次缺省行为探测，实际结果为通过，不能将名称中的 before 当作失败。Clash、sing-box 与分享链接的 serviceName 保留回归通过，见 `artifacts/vmess-grpc-parameters.log`（共五项参数测试）。

服务端与目标均仅绑定回环地址，路由精确允许本次 TCP/UDP 回显端口，其他目标拒绝；结束时回收独立服务端。未启用外层 TLS，不是严格 TLS 正向证明；没有改变 V2Fly 大 UDP 的既有未通过边界。

复现：在原独立互通入口设置 PRISM_VMESS_TRANSPORT=grpc，自定义服务名模式设置 PRISM_VMESS_GRPC_DEFAULT=0，缺省模式设为 1。CI 互通脚本已安排两种模式，尚未运行这些新增 Linux 作业；运行中的 WS CI 不包含本批测试变化。

手机导入、受保护 socket、TUN、链式 TCP/UDP、代理 DNS、候选组、重建与后台仍待专门接入验证。gRPC 其它配置及外层 TLS、实际账号与真机条件继续保留缺口。iOS 与 HarmonyOS NEXT 暂停，没有发布。
