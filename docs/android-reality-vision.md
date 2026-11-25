# Reality/Vision 手机开发候选（未发布）

公开版本仍为 Beta.9，不包含 Reality/Vision。当前开发候选为 code15 / 0.2.0-beta.10，开始受限手机接入，尚未取得本轮 Android 流量验收。开发分支增加独立互通、Vision 修正与导入边界校验，不将内核已有代码或本地测试当作 Android 已交付。gRPC code14 的修正 CI 45683589159 固定为 d5388b3，不包含本批 Reality 测试。

按照 [REALITY 官方示例](https://github.com/XTLS/REALITY/blob/main/README.en.md) 配置公钥/短 ID、服务名和可选 `xtls-rprx-vision`，使用已有官方摘要校验的 Xray 26.11.9。服务端、TLS 1.3 伪装目标、TCP/UDP 回显均绑定 127.0.0.1；代理路由只允许本次回显端口，其余拒绝，无公网伪装目标或任意转发。

`crates/prism-core/tests/reality_interop.rs` 的首次本地独立测试通过（`artifacts/reality-initial-interop.log`）：

- 分别使用不带 Vision 和带 Vision 的 VLESS Reality 服务端，逐字节核对 70,000 字节 TCP 及 1/1200/8000 字节 UDP。
- 每种模式分别验证错误公钥、错误短 ID、错误 UUID，要求 5 秒内错误或 EOF，目标累计载荷不增加；不把等待超时当作认证拒绝成功。
- 每轮产生临时 X25519 密钥。客户端 `skip_cert_verify` 未开启，必须通过 REALITY 的临时证书认证；伪装 TLS 服务使用本地证书，不将它注入客户端信任或充当 REALITY 认证替代品。测试结束回收独立进程，不将服务端或密钥打包进应用。

复现需显式设置 `PRISM_REALITY_SERVER_BIN` 指向已独立核验的 Xray 绝对路径，再运行 `cargo test -p prism-core --test reality_interop --locked -- --ignored --nocapture`。普通测试不自动执行或下载服务端。

## 内层 TLS 与直接拷贝回归

增加独立的内层 TLS 1.3 服务和测试客户端，客户端仅信任该内层服务的临时测试根并校验名称，不改变 Reality 出站的认证。Reality 两种模式均通过 TLS 1.3 握手及双向各 512,000 字节完整校验（`artifacts/reality-inner-tls-interop.log`）。初版夹具遗漏 TLS flush 而超时，失败保留为 `reality-inner-tls-initial-timeout.log`；补齐客户端与服务端 flush 后通过，未改生产协议代码。

进一步加入只捕获 Vision 状态事件的日志和切换后的追加载荷，要求双向实际切到直接拷贝。增强测试最初失败：下行切换可见，上行事件缺失（`artifacts/reality-direct-copy-before.log`）。因此不能把内层 TLS 数据通过当作双向优化已完成。[Xray 实现](https://github.com/XTLS/Xray-core/blob/main/proxy/proxy.go) 在重塑缓冲前判断完整记录，再在末块发送切换指令；本内核按每个 8 KiB 填充块检查完整性，较大或跨 write 的记录会漏掉上行切换。

仅将检查移到切块前的尝试仍失败（`reality-direct-copy-after.log`），该尝试未保留。后续临时诊断确认 TLS 1.3/允许的套件已经识别，但实际写入为 8155、37 等片段（`reality-direct-copy-diagnostic.log`）；诊断输出未留在生产代码。

修正使用固定 5 字节头与剩余长度计数跟踪实际入队的 TLS 字节，不缓存记录正文，不依赖调用者保留未消费后缀；仅在已消费片段恰好结束应用记录时发出 END/DIRECT，继续沿用 TLS 版本/套件判断及写出后再切换。畸形头禁用该优化，转发仍保留外层 TLS。

同一增强测试现已通过，两个方向均观测到直接拷贝，切换后的追加 TLS 载荷也逐字节通过；512,000 字节、原 TCP/UDP 及错误公钥/短 ID/UUID 保留，并新增错误 SNI 的及时拒绝（`artifacts/reality-record-boundary-final.log`）。93 项 Windows 内核单元、4 项 gRPC 帧及 5 项 VMess 参数回归通过；新增三项覆盖 1/37/8155/8192 分片、跨 write 头、正文伪头及畸形输入（`vision-record-boundary-core.log`）。没有放宽双向事件、认证或后续数据断言。

CI 独立互通脚本已增加使用固定 Xray 的 Reality/Vision 测试，尚待 Linux 执行；已完成的 gRPC CI d5388b3 不包含本次修正。更多参数、手机导入/会话、受保护 socket、实际 TUN/DNS/链式/优选/恢复、双系统后台、原签名升级与真实设备仍缺证据，公开包继续不支持该功能。iOS 与 HarmonyOS NEXT 暂停；没有发布新版本。


## 导入参数与拒绝降级

新增三格式 Reality/可选 Vision 参数回归，Clash、sing-box、分享链接均保留公钥、短 ID、SNI、指纹、flow，并能构造真实出站。按 [sing-box Reality 字段](https://sing-box.sagernet.org/configuration/shared/tls/#reality) 和 [Mihomo TLS 配置](https://wiki.metacubex.one/en/config/proxies/tls/) 校对必需公钥语义。

新测试先复现两种静默降级：显式 Reality 缺少公钥仍导入普通 TLS，未知 VLESS URI security 被当成 none（`artifacts/reality-parameters-before.log`）。现修正三条导入路径，缺失、null、空白或非字符串公钥拒绝导入，不猜测普通 TLS；VLESS URI 仅接受 none/tls/reality，未知值拒绝而非转明文。sing-box 显式 enabled=false 则不启用 Reality，清除公钥/短 ID；Clash 的 null 可选块仍按未配置处理，普通 TLS 保持。

四项参数回归、93 项内核单元、4 项 gRPC 帧及 5 项 VMess 参数通过（`artifacts/reality-parameter-regression.log`）。合法公钥的密码学格式仍由出站构造器验证。本次为新导入路径修正，不冒称能从缺少原始安全意图的旧节点反推并修复旧缓存。尚未开放手机 Reality/Vision，固定 gRPC CI d5388b3 不包含本批解析修正。


## 认证派生前的低阶点拒绝

进一步检查发现 Reality 静态公钥 ECDH 缺少普通 TLS 分支已有的 non-contributory 检查。新增零点和低阶点 1 的测试先失败（`artifacts/reality-low-order-before.log`），说明旧路径仍会尝试派生认证密钥；这不是已有用户遭受攻击的证据。

现于 HKDF/会话认证封装前调用已锁定 x25519-dalek 2.0.1 的 [was_contributory](https://docs.rs/x25519-dalek/2.0.1/x25519_dalek/struct.SharedSecret.html#method.was_contributory) 常量时间检查，无效点立即返回固定错误。正常临时密钥的正向保留，另用真实异步内存连接确认错误点产生 EOF、收到精确错误且未发出 ClientHello（`artifacts/reality-low-order-after.log`）。公钥编码/长度仍由出站构造器校验，点贡献检查在真实握手派生前完成，未把格式可解析冒称为连接可用。

修正后独立 Xray 的 Reality/可选 Vision、双向直接拷贝、切换后追加 TLS 数据、512,000 字节载荷及错误认证重新通过（`artifacts/reality-low-order-interop.log`）；95 项内核单元、4 项 Reality 参数、4 项 gRPC 帧和 5 项 VMess 参数通过（`reality-low-order-core.log`）。该阶段手机尚未接入，Linux/Android 尚待，不属于固定 d5388b3 的 gRPC 候选。


## code15 手机策略与夹具准备

仅允许 VLESS + Reality 的 TCP，可选 xtls-rprx-vision；指纹仅缺省或 chrome，要求显式 TLS、可用公钥、合法短 ID/UUID、ASCII DNS 形式 SNI，拒绝 IP、控制字符、空标签/过长标签。其它协议的 Reality、WS/gRPC Reality、其它 flow/指纹、Vision 普通 TLS 仍未开放；证书跳过与依赖节点仍拒绝。出站构造必须通过，不接受孤立短 ID；Reality::parse 另以固定公开校验标量提前拒绝低阶点，实际握手仍保留独立检查，不将校验标量用作认证密钥。

40 项手机策略、Reality 三格式导入→会话生成 2 项、原 gRPC 2 项及 WS 1 项通过（`artifacts/reality-mobile-policy.log`）。覆盖公钥/短 ID/SNI/指纹/flow 保留和非法组合拒绝；95 项内核单元、4 项 Reality 参数、4 项 gRPC 帧、5 项 VMess 参数与独立 Xray 强验收重新通过（`reality-candidate15-core.log`、`reality-candidate15-interop.log`）。双架构 JNI 已启动构建，尚未打包或取得 Android TUN/后台/原签名验收，不能把上述策略测试当成功能交付。

宿主示例 `reality_fixture_cert` 只为新目录生成伪装 TLS 服务端的临时证书/密钥，拒绝覆盖文件，不进入 JNI/APK、不修改客户端信任；PEM 已由 Python TLS1.3 上下文成功加载（`artifacts/reality-camouflage-cert-build.log`）。它只准备伪装服务端，尚需独立 Xray 手机夹具和实际流量验证。gRPC code14 原签名样本仍保留 code14 与原 UID/配置，未安装 code15；旧原签名样本不变。
