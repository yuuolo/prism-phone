# 仓库拆分与更新兼容

Reality 后续另在静态公钥 ECDH 的 HKDF/认证封装前拒绝 non-contributory 共享值，使用现有 x25519-dalek 的常量时间检查。低阶点先红后绿、连接未发出 ClientHello 的回归及独立 Xray 正向均通过，未同步桌面；同步须保留派生前拒绝及无线上认证字节的断言。

手机快照后续修正 Vision 上行直接拷贝的完整记录识别：固定大小状态按实际入队字节跟踪跨写入/填充块的 TLS 记录边界，不缓存正文，仅在完整应用记录末尾发送切换指令，畸形头保留外层 TLS。独立 Xray 的真实内层 TLS 1.3/双向载荷/切换事件及三项边界单元通过，Linux 和 Android 尚待；见 [Reality/Vision 准备](android-reality-vision.md)。未同步桌面仓库，同步时必须保留这些回归，不能因内层载荷能通过就省略双向直接拷贝断言。

Beta.4 后手机候选组扩展 fallback/按目标负载均衡与自定义 HTTPS 检测地址。共享快照的 DelayStore/Hub 在延后重测、组探测策略相同且节点配置完全一致时保留已知可用性，不复制延迟历史，避免重建后复用已失败成员；节点配置改变不继承。该改动仅在手机仓库，同步桌面时需保留连续重建和配置变化回归。其余高级能力以 `android-advanced.md` 的逐项验收为准，不一次性解除协议白名单。

手机快照的 DNS 流式连接池修正失效连接恢复：首次复用失败后第二次尝试强制新建，避免池中多个旧连接同时失效时连续取旧连接而未真正恢复。保持原有最多两次尝试、总查询时限和代理 DNS 路径，不增加后台探测。同步上游时保留多失效连接及真实新建 TCP 回归；该修改尚未同步桌面仓库。

链式代理扩展固定 Relay 的逐跳连接元数据、组级 UDP 拒绝及仅固定协议节点的 proxy-only DNS 路径；动态组、内置 DIRECT 和嵌套组仍不允许成为该 DNS relay。RegistryCell 改用 Weak 引用，修复网络重建/停止后旧 Registry 无法释放的引用环；同步上游时必须保留生命周期、真实链路、DNS 隐私和网络恢复回归。以上仅修改手机快照，未同步桌面仓库。

2026-11-12 从 `yuuolo/prism` 的合并提交 `1351bf5d142499522a89ca9384ee323d03447fe8` 导出已跟踪的 Android、JNI、构建脚本及移动文档。原有开发历史保留在桌面仓库的 `prism-codex` 分支及 `master` 合并历史中；本仓库从该源码快照开始独立记录历史，保留 MIT 许可证。

`crates/prism-core` 同步自上述提交，是手机端独立构建使用的源码快照。后续同步桌面修复时，需在提交说明记录来源提交并通过手机策略、VPN 和 DNS 测试；手机改动不自动同步到桌面。

2026-11-22 VMess 接入准备修正手机快照的 `outbound/vmess.rs`：仅实现 AEAD 时明确拒绝非零 `alterId`，避免静默忽略旧式认证参数。新增独立 Xray/V2Fly 服务端 TCP/UDP 互通测试；实际范围和仍未通过的 V2Fly 大 UDP 报文见 [VMess 接入验收](android-vmess.md)。此修正未同步桌面仓库。后续本地手机候选开放 AEAD TCP/TLS，并通过 API 26/37 的独立服务端 TUN 专项，仍未发布；Beta.9 恢复修复候选不包含 VMess。

随后修正 VMess UDP 超长报文被取前缀发送的问题，按实际帧长度拒绝无法完整表示的报文；Clash、sing-box、分享链接三条 VMess `alterId` 解析路径不再将畸形或溢出值转为 0。合法值保留供 AEAD 构造器判断；其它协议的字段路径保持原逻辑。同步上游时保留真实字节捕获、合法边界、三格式参数与独立服务端回归。

手机端后续局部扩展：`crates/prism-core/src/tunnel.rs` 增加按实际出口与规则类别的累计载荷计数，供跨会话历史统计使用，累计量跨连接结束和 Hub 重载保留。该扩展仅存在于手机仓库，未同步修改桌面仓库；`mobile_traffic` 真实 TCP/UDP 与手机 VPN/DNS 验收用于检查兼容性。

## 更新入口

新客户端“打开安卓发布页”指向独立的 `yuuolo/prism-phone` 安卓发布列表；旧客户端通道及旧仓库镜像继续兼容，不移除旧下载地址。

本机代理服务增加 `inbound.rs` 的受控监听入口、关联式 SOCKS UDP 与取消清理，`tunnel.rs` 增加任务中止时连接表清理和受限 UDP 会话，`net.rs` 增加 Android VPN 保护的监听 socket。原有桌面监听入口保持原行为；手机服务独立管理生命周期，断开 VPN 时回收。同步上游时需保留并重跑本机代理、流量、DNS 和网络恢复验收。

- 新构建检查 `https://github.com/yuuolo/prism-phone/releases/download/android-updates/android-update.json`。
- 已安装的 Android 0.2.0-beta.1 只接受 `yuuolo/prism` 的 APK 下载路径。因此旧仓库的 `android-updates/android-update.json` 必须继续维护，不能直接改成指向新仓库的 APK。
- `scripts/android/publish.ps1` 从本仓库通过构建及模拟器验证的 CI 下载 APK，本机签名，在本仓库发布，同时向旧仓库镜像同一个签名 APK，并生成使用旧下载路径的兼容清单。两边 SHA-256、版本、包名及证书相同。脚本拒绝回退版本或替换同版本 APK。
- 迁移时新通道先指向原有 Beta.1 的旧仓库 APK；没有把未经验证的新源码冒充为已发布二进制。下一次正式发布必须增加 `versionCode` 和版本名。
- 2026-11-12 已发布 `0.2.0-beta.2`（versionCode 3），由手机仓库提交 `180b7dc` 的完整 CI 产出并本机原证书签名。新旧通道均指向各自仓库的同一签名 APK，大小及 SHA-256 一致；后续发布继续递增版本。
- 2026-11-18 发布 `0.2.0-beta.3`（versionCode 4），来源为提交 `ad32a6f` 的完整 CI `44204505812`，沿用原证书；新旧仓库镜像同一 APK，分别维护各自下载 URL。实际发布包的 Beta.2 覆盖与加密配置保留验收通过，剩余真机条件见完整版验收文档。
- 2026-11-18 发布 `0.2.0-beta.4`（versionCode 5），来源为提交 `d28c3a4` 的完整 CI `44317571741`。实际发布包通过 Beta.3 应用按钮及系统按次授权安装，延续原 Beta.2 的 UID/Keystore/加密配置；原开关与规则保留。新旧仓库 APK、校验和及两个兼容更新清单均下载回读核对，SHA-256 为 `71d1ef4867fadee2de7c8fd7c9293697aada5bb16af05729e72b8167e3a6948f`，不修改桌面 latest。
- Alpha.1 没有内置升级检查，需要手动安装一次 Beta。

## 本机签名与桌面隔离

广告拦截增加手机内部 `PRISM-ADS` 标记规则，复用逻辑规则与 GeoSite 条件以支持例外后继续普通路由；`tunnel.rs` 只累计该规则实际拒绝的尝试次数，使用共享 Stats 跨 Hub 重建保留，不保存目的地。该标记不接受手机规则导入，未改动桌面仓库。

自动优选扩展了手机快照的规则组初次健康检查延迟配置及 UrlTest 重建后选择保留。一般配置仍默认 1 秒开始；手机网络重建 payload 将初次检查延后 300 秒，以约束网络抖动时的探测。该修改未同步桌面仓库，需在后续同步上游时保留手机恢复与优选测试。

发布仍使用原有 `dev.prism.android` 包名和原始签名证书。私钥及密码保存在被 Git 忽略的 `android/.signing/`，不提交、不上传 GitHub Secrets。发布只上传公开 APK、校验和及更新清单。

旧仓库仅保留移动端入口说明与兼容发布资产；桌面应用继续使用原有 `latest.json`。安卓发布始终 `--prerelease --latest=false`，不得覆盖桌面稳定版更新通道。

## Beta.5 发布与验收回执

2026-11-19 发布 `0.2.0-beta.5`（versionCode 6），源码 `68de83a` 的[发布 CI 44346214298](https://github.com/yuuolo/prism-phone/actions/runs/44346214298)全部通过：双架构 Debug/Release、双 Lint、34 项手机 Rust、101 项 Linux 共享内核回归、7 项 Android 单元测试、双系统各 21 项完整回归及各自独立 180 秒 Doze。

实际原签名 APK 从 Beta.4 经应用按钮及系统 Only this time/Update 覆盖，延续原 Beta.2 的 UID、Keystore、节点/凭据/来源/收藏/选择与规则，来源仍为 Ask every time。安装从已校验缓存开始，未算作本次线上检查/下载验收。两个仓库公开 APK、校验和与各自更新清单已下载回读一致；桌面 latest 仍为 v0.2.13。

APK 大小 24,245,867 字节，SHA-256：`e6ce1e64443932880c8df9caf97f4a35247473151b62a2f2287ee1897f8d08da`。本次只交付高级目标的候选组第一批，其余目标继续开发；真机条件仍未完成。
## Beta.6 / Beta.7 发布回执

Beta.6（code 7）源码 `b6d5b48`、CI `44449467389`；24,241,771 字节，SHA-256 `58f64f0e2cebf0fef50441a376d61d5545a587b12a29c38883cab11ef9e7de9a`。Beta.5 正常应用/系统覆盖通过，旧数据保留。

2026-11-19 发布 `0.2.0-beta.7`（code 8），源码 `410f29a` 的[发布 CI 44451687529](https://github.com/yuuolo/prism-phone/actions/runs/44451687529)全部通过：双架构 Debug/Release、双 Lint、34 项手机 Rust、101 项 Linux 共享内核回归、7 项 Android 单元测试、双系统各 23 项完整回归及各自独立 180 秒 Doze。两份后台报告已核对强制 IDLE、原进程与 VPN 不变、冷 DNS、严格 TLS/HTTP 200 和断开对照。原签名发布包从 Beta.6 经应用按钮及系统 Only this time/Update 覆盖，延续原 Beta.2 的 UID、Keystore、节点/凭据/来源/收藏/选择与规则；实际界面保存的应用包含名单也保留，主页范围提示核对通过。来源仍为 Ask every time，安装从已校验缓存开始，不算作本次线上检查/下载验收。新旧仓库公开 APK、校验和及各自下载地址的更新清单均已回读一致，桌面 latest 仍为 v0.2.13。[发布说明](releases/android-0.2.0-beta.7.md)。

Beta.7 APK 24,241,771 字节，SHA-256 `e38c8502b1d32a8e2edc15d0f0c14798c318f8d0b2d94bcc2fd55b8e836e53eb`。两个版本原签名和包名不变；旧仓库继续自己的 APK 下载地址。应用名单使用 Android VPN Builder，不改动 PC 进程路由；质量历史只增加手机候选状态输出，不修改桌面仓库。

## Beta.8 发布回执

2026-11-19 发布 `0.2.0-beta.8`（code 10，9 仅本地候选未发布），源码 `17ac37a` 的[发布 CI 44461176843](https://github.com/yuuolo/prism-phone/actions/runs/44461176843)全部通过：双架构 Debug/Release、双 Lint、37 项手机 Rust、102 项 Linux 共享内核回归、7 项 Android 单元测试、双系统各 25 项及各自独立 180 秒 Doze。后台原始报告已核对强制 IDLE、进程/VPN 不变、冷 DNS、严格 TLS/HTTP 200、断开不复活及断开对照拒绝。原签名包从 Beta.7 code 8 经未发布候选 9、最终 10 连续通过应用按钮及系统 Only this time/Update 覆盖，保留原 Beta.2 的 UID、Keystore、节点/凭据/来源/收藏/选择与规则；应用包含名单及旧默认 DNS 保留，安装来源仍为 Ask every time。安装从已校验缓存开始，不算作本次线上检查/下载验收。最终 CI ZIP 官方摘要核对通过；两个仓库公开 APK、校验和及各自更新地址已回读一致，桌面 latest 仍为 v0.2.13。[发布说明](releases/android-0.2.0-beta.8.md)。

APK 24,323,691 字节，SHA-256 `74c647770dc1060c876d9c178804aebb1b5b857b0a366f6d996f37ade2ce0882`。新增 DNS 模型为可选 version 1，旧配置保持默认；手机共享快照的 opt-in fake-IP hosts 与拨号覆盖详见 `android-dns.md`，默认不改变未启用该开关的旧行为，不同步修改桌面。
