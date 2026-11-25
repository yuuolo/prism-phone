# Reality/Vision 独立接入准备（手机未开放）

公开版本仍为 Beta.9，手机白名单仍拒绝 Reality、Vision 和指纹配置。本轮仅增加共享内核对独立 Xray 的互通测试，不将内核已有代码或本地测试当作 Android 已交付。gRPC code14 的修正 CI 45683589159 固定为 d5388b3，不包含本批 Reality 测试。

按照 [REALITY 官方示例](https://github.com/XTLS/REALITY/blob/main/README.en.md) 配置公钥/短 ID、服务名和可选 `xtls-rprx-vision`，使用已有官方摘要校验的 Xray 26.11.9。服务端、TLS 1.3 伪装目标、TCP/UDP 回显均绑定 127.0.0.1；代理路由只允许本次回显端口，其余拒绝，无公网伪装目标或任意转发。

`crates/prism-core/tests/reality_interop.rs` 的首次本地独立测试通过（`artifacts/reality-initial-interop.log`）：

- 分别使用不带 Vision 和带 Vision 的 VLESS Reality 服务端，逐字节核对 70,000 字节 TCP 及 1/1200/8000 字节 UDP。
- 每种模式分别验证错误公钥、错误短 ID、错误 UUID，要求 5 秒内错误或 EOF，目标累计载荷不增加；不把等待超时当作认证拒绝成功。
- 每轮产生临时 X25519 密钥。客户端 `skip_cert_verify` 未开启，必须通过 REALITY 的临时证书认证；伪装 TLS 服务使用本地证书，不将它注入客户端信任或充当 REALITY 认证替代品。测试结束回收独立进程，不将服务端或密钥打包进应用。

复现需显式设置 `PRISM_REALITY_SERVER_BIN` 指向已独立核验的 Xray 绝对路径，再运行 `cargo test -p prism-core --test reality_interop --locked -- --ignored --nocapture`。普通测试不自动执行或下载服务端。

## 内层 TLS 与直接拷贝回归

增加独立的内层 TLS 1.3 服务和测试客户端，客户端仅信任该内层服务的临时测试根并校验名称，不改变 Reality 出站的认证。Reality 两种模式均通过 TLS 1.3 握手及双向各 512,000 字节完整校验（`artifacts/reality-inner-tls-interop.log`）。初版夹具遗漏 TLS flush 而超时，失败保留为 `reality-inner-tls-initial-timeout.log`；补齐客户端与服务端 flush 后通过，未改生产协议代码。

进一步加入只捕获 Vision 状态事件的日志和切换后的追加载荷，要求双向实际切到直接拷贝。该增强测试目前**失败**：下行切换可见，上行事件缺失（`artifacts/reality-direct-copy-before.log`）。因此不能把内层 TLS 数据通过当作双向优化已完成。[Xray 实现](https://github.com/XTLS/Xray-core/blob/main/proxy/proxy.go) 在重塑缓冲前判断完整记录，再在末块发送切换指令；本内核按每个 8 KiB 填充块检查完整性，较大或跨 write 的记录会漏掉上行切换。

仅将检查移到切块前的尝试仍失败（`reality-direct-copy-after.log`），该尝试未保留在生产实现。后续须按实际已消费字节跟踪跨 write 的记录边界，限制状态/内存，不能假定调用者在一次部分写入成功后一定继续提供同一未消费缓冲。增强断言保留为显式 opt-in 的未通过回归，不放宽为只验证数据或单向事件；当前普通 CI 不执行该忽略测试。

生产协议代码保持原状。仍需解决上述缺口、更多参数与错误 SNI、Linux 独立互通、手机导入/会话参数、受保护 socket、实际 TUN/DNS/链式/优选/恢复、双系统后台、原签名升级与真实设备。手机入口继续保持关闭。iOS 与 HarmonyOS NEXT 暂停；没有发布新版本。
