# Android 高级能力扩展（前三批已发布，当前 Beta.9）

2026-11-26 用户调整优先级：高级协议接入暂停，先完成完整配置与 JavaScript 脚本、高级分流、运行中修改、多代理组和 DNS。当前进度见 [完整配置工作记录](android-full-config.md)。

用户现已将下列能力纳入 Android 开发目标，取代旧移动方案中相应的“不纳入”边界。当前公开安装包为 Beta.9，已交付候选组策略、应用 VPN 包含/排除、真实质量历史和高级 DNS；其余目标未全部完成；不能把内核已有代码、路线或导入成功当成手机已交付能力。已有签名、包名、更新地址、加密配置及节点标识继续兼容，iOS 与 HarmonyOS NEXT 暂停。

| 用户目标 | 接入与验收安排 | 当前状态 |
| --- | --- | --- |
| Reality/Vision、VMess、Hysteria2、TUIC、WireGuard、WS/gRPC | 快照已有协议代码，逐项核对参数保真、TCP/UDP socket 保护、严格认证、真实握手/载荷及网络恢复；通过后逐项开放导入 | 新增协议接入已暂停。VMess TCP/WS code 13 与 gRPC code 14 私有候选通过完整 CI 和原签名升级；code 14 CI 45683589159 双系统共 56 项、8 份独立后台报告通过，均未发布。Reality/Vision 工作独立保留且未完成 Android 验收 |
| 完整 Clash/sing-box、providers、覆写、脚本 | 增加独立的完整配置模型与预览/校验；provider 缓存与下载有界；JavaScript 使用 Clash 配置覆写语义，修改生成的配置，资源/执行有上限，脚本失败保留旧配置 | 开发中：独立 Clash 文档、真实 JavaScript、严格引用校验、JNI 预览及加密草稿编辑已接入；主机 10 项、双系统各 5 项专项通过，首次 Android 17 页面失败单独保留；sing-box/providers/运行应用未完成 |
| 更多规则、自定义代理组、规则集、按应用分流 | 自定义组图校验、规则集来源/大小校验；Android 按包/UID 适配，不把 PC 进程路径假装成 Android 程序标识；区分应用绕过 VPN 与 VPN 内按应用路由 | Beta.6/7 已发布应用包含/排除，完整 CI 通过；多组/规则集/应用指定代理仍待实现 |
| 运行中切换与热重载 | 校验完成后原子切换，保留监听/TUN、选择与统计；失败不替换运行配置，回归旧会话及新连接 | 待实现；当前界面仍要求断开修改 |
| 更多代理组、检测地址、fallback、负载均衡 | 第一批扩展已有候选组；后续完整配置模型承载多个自定义组 | 候选组首批已随 Beta.5 发布，Android 与完整 CI 已通过；尚非多个自定义组 |
| DNS 上游/策略/fallback/hosts/IPv6 | 增加明确的 DNS 配置模型及防泄漏校验，验证 bootstrap、代理 DNS、双栈路由与网络恢复；不能仅移除 IPv6 拒绝规则 | Beta.8 已发布加密上游、分域策略、fallback 与 hosts，完整 CI 通过；IPv6 仍待完整双栈验收 |
| 应用流量、连接地图、节点质量曲线 | 按 Android 可用 API 获取归属；未知归属明确显示，限制采样和保留量，数据与连接生命周期一致 | Beta.6/7 已发布真实候选组质量历史，完整 CI 通过；应用流量和地图仍待实现 |

第 8 项尚未提供内容，等待补充，不自行添加需求。

2026-11-22 开始下一批 VMess 接入准备：修复 AEAD 构造器静默忽略非零 alterId，建立独立 Xray/V2Fly 的真实 TCP/UDP 与错误凭据目标计数回归。88 项共享内核、39 项手机策略通过；实际互通范围及仍未通过的 V2Fly 大 UDP 报文见 [VMess 接入验收](android-vmess.md)。公开版本未交付 VMess；本地候选已开放 AEAD TCP/TLS 并通过 API 26/37 专项 TUN 与两端独立 180 秒 Doze，后续 code 12 完整 CI 与原签名升级均通过；握手期间意外重建与前台服务竞态的定位、修复及仍缺失的外层 TLS 证据见上述专门记录。

后续同批修正 UDP 超长报文取前缀发送、三种配置格式畸形 alterId 变 0 的问题：最新 90 项内核单元、2 项跨格式参数、39 项手机策略通过，双架构 JNI、Debug/Release APK、16 KiB 对齐和 Android 17 既有 VPN 1 项回归通过。后续本地候选手机策略增至 40 项，API 26/37 独立服务端 TUN 专项均通过；这不是公开交付。具体边界与未通过项保留在上述专门记录中。

## 第一批：候选组策略

已有候选组增加 `url-test`、`fallback`、`load-balance` 与可编辑的 HTTPS 检测地址。fallback 依候选顺序选择首个可用节点；负载均衡按目标主机保持粘性，使用已知可用候选，不冒称每次请求轮询或带宽加速。负载均衡没有唯一出口，界面显示“按目标负载均衡”，连接和流量仍归属实际出口。

沿用 2–16 个候选、300–3600 秒间隔、0–2000 毫秒容差、5 秒单次探测上限与停止清理；容差只影响 url-test。旧配置缺少新字段时仍使用 url-test 和 `https://1.1.1.1/`，不重写原候选/开关。初期检测地址要求 HTTPS，不接收账号、查询参数、片段、零端口或 IPv6 目标；IPv6 留待完整双栈验收开放。

Beta.8 及以前网络重建延后 300 秒重测。当前工作区修复（尚未发布）改为重建后等待 2 秒即发起健康检查，避免旧节点在新网络不可用时长时间不切换；这不是保证 2 秒恢复，探测仍有单次 5 秒上限，重建仍受 3 秒事件节流。常规探测间隔及用户设置保持不变。对策略、URL、成员顺序相同的组，仅复制配置完全一致的协议节点的已知可用性；不复制或伪造延迟历史。地址、凭据等变化的节点不继承旧状态。实际新探测替换继承状态。该修改仅在手机快照，未同步桌面仓库。

2026-11-22 切网反馈回归：本地真实代理夹具在重建前选中 A、重建时令 A 失效，禁止手动触发健康检查，要求重建后的后台探测在 4 秒窗口内自动切到 B。旧 300 秒实现触发超时，修复后结果记录于本地 `artifacts/recovery-after.log`。此项验证恢复调度，不代替真机 Wi-Fi／蜂窝切换；300 秒等待在 Beta.3 已存在，不能据此认定为 Beta.8 独有回归。

本地验收（未发布）：38 项手机 Rust、6 项共享内核 DNS/hosts/网络恢复集成测试、7 项 Android JVM 测试通过；ARM64 与 x86_64 JNI 构建通过，Debug/APK/仪器包与 Debug Lint 通过。新增 fallback/均衡回归反转两个候选的可达性，验证继承状态被后台实际探测替换、失败节点排除及真实 HTTP 转发。API 26 候选策略测试 1 项、自动优选及 OS Wi-Fi/蜂窝往返链式代理测试 2 项通过，覆盖 TLS、代理 DNS、会话与统计保留。记录见本地 `artifacts/recovery-api26-candidates.log`、`artifacts/recovery-api26-network.log`。API 26 旧调试签名覆盖被拒后的旧包误启动测试已停止，结果未计入；核对专用 AVD 与 DEBUGGABLE 后重装本地包，APK 内 strip 后 x86_64 JNI 摘要与当前构建一致。原签名升级样本未改动，真机验收仍缺失。

Android 17 / API 37 / 16 KiB 的上述 3 项仪器测试也通过（`artifacts/recovery-api37-network.log`，93.662 秒）；Release 构建、Release Lint 与双架构 APK 的 16 KiB zipalign 检查通过。汇总与本地产物摘要保存在 `artifacts/recovery-proof.json`。本轮为针对切网恢复的验收，未重跑整套 25 项仪器测试或 180 秒 Doze，也未重新验收原签名覆盖升级，不把本地未发布包当成新版本。

后续补充完全断网场景：`NetworkRecoveryTest` 在 Wi-Fi 关闭时再关闭移动数据，等待两种非 VPN 物理网络均消失并观察 OS 回调重建；保持原会话及累计流量，再恢复移动数据，验证新的链式 TLS 与代理 DNS，最后返回 Wi-Fi。全程不为实际切换调用 JNI 通知或手动重连 VPN；finally 恢复原移动数据/Wi-Fi 设置。仪器包重新编译通过，API 26 此扩展用例通过（`artifacts/recovery-offline-api26.log`，38.468 秒）。这不验证飞行模式、真实基带/厂商省电或断网期间的流量泄漏。

Android 17 完全断网用例首次运行在 VPN 启动前的蜂窝前置条件超时（`artifacts/recovery-offline-api37-setup-failure.log`）。观察到 `mobile_data=1`、SIM LOADED、飞行模式关闭，清理阶段 `svc data enable` 后才出现 LTE 网络；尚不能据此确定模拟器初始化根因。测试准备现显式执行 `svc data enable`，不再只依赖持久化开关；未增加生产连接重试、放宽 TLS/DNS 校验或扩大原等待窗口。finally 仍恢复测试前开关。

最终测试包在 Android 17 / 16 KiB 完全断网恢复通过（`artifacts/recovery-offline-api37-final.log`，45.328 秒）。本次 Android 17 成功运行使用已启动的原实例，不能将其当作重新冷启动后蜂窝准备问题已被彻底解决的证据。

同一最终仪器包在 API 26 也通过（`artifacts/recovery-offline-api26-final.log`，44.277 秒）；最终测试包、应用包和源文件摘要见本地 `artifacts/recovery-offline-proof.json`。两端结束后恢复网络开关并关闭专用模拟器及夹具。无真机、飞行模式或长时 Doze 新证据，无新增发布。

后续仪表盘恢复状态（工作区未发布）：内核开始处理重建事件时进入 rebuilding；地区数据校验阻止、8 秒重建超时或 Hub 重建错误分别记录固定原因码；成功进入 ready，保留本会话失败累计。状态不存盘、不包含底层错误或目的地址，也不代表互联网连通。39 项手机 Rust（含失败后再次恢复及新会话重置报告）、7 项 JVM、双架构 JNI、Debug/Release APK、双 Lint 与 Release 16 KiB zipalign 通过。API 26 真实数据损坏失败与 OS 网络恢复两项通过（`artifacts/recovery-status-api26-scroll.log`，49.996 秒），同时验证仪表盘失败/完成提示、原规则保留、链式 TLS/DNS 与统计。

UI 回归曾两次未找到完成文字（`artifacts/recovery-status-api26-ui-failure.log`、`artifacts/recovery-status-api26-offscreen-failure.log`）。第二次保留的测试内界面层级 `artifacts/recovery-dashboard-failure.xml` 显示小屏链式说明占据前部空间，实时概况在滚动区域下方。测试现明确进入仪表盘并滚动到目标文字后断言；未修改生产超时或去掉状态/流量断言。不能将这些失败记录算作通过。

Android 17 最终状态/仪表盘两项通过（`artifacts/recovery-status-api37-final.log`，65.588 秒）；该系统第一次运行的内核失败原因码已通过，但未滚动时未找到失败提示，整轮判失败，记录为 `artifacts/recovery-status-api37-offscreen-failure.log`。失败提示用例现也明确滚动后断言，两个提示都保留失败界面取证。仅验证这两项相关用例，未重跑全套 25 项或新一轮 180 秒 Doze，未重新验收原签名升级；这些不能作为稳定版完成证据。

相同最终测试包在 API 26 两项也通过（`artifacts/recovery-status-api26-last.log`，49.609 秒）。汇总、源码及 APK/JNI 摘要见本地 `artifacts/recovery-status-proof.json`。专用模拟器和回环夹具已关闭，原签名升级样本及公开版本未更改。真机与完整高级能力仍待继续验收和开发。

恢复闭环扩展（仍未发布）：`GeoDataTest` 增加同一会话从数据校验失败到恢复原文件、成功重建及 UI 错误清除的检查；失败累计保留、原因清除、尝试增加，原拒绝规则继续生效。随后验证数据损坏时重新启动失败、恢复文件后新会话失败计数清零，最后断开再发送网络变化并等待节流窗口，确认内核不复活且不再返回恢复状态。仪器包编译通过，API 26 用例通过（`artifacts/recovery-cycle-api26.log`，16.763 秒）；尚不能据此替代真实厂商切网或基带验证。

Android 17 闭环最终通过（`artifacts/recovery-cycle-api37-final.log`，28.132 秒）。首次以“恢复前后失败次数相等”断言失败，记录为 `artifacts/recovery-cycle-api37-counter-failure.log`：读到的累计从 1 增至 2。真实系统在损坏文件保留期间仍可能送入额外网络事件，因此改为恢复前重新采样，并验证累计不减少；确定性 Rust 报告测试仍保留精确计数。未放宽会话保持、重建成功、规则命中、UI 错误清除或断开不复活断言。

API 26 另通过本轮独立 180 秒 Doze（`artifacts/recovery-cycle-background-api26.json`）：强制 IDLE 保持，进程/VPN 身份不变，前/空闲/恢复三阶段均通过真实 VPN fake-IP DNS、严格 TLS 与 HTTP 200；用户断开保持停止，断开对照被拒。使用当前源码重建的独立客户端及本地调试签名 seed，仪器进程退出后才从普通 UI 启动 VPN；空闲期仅主机心跳，没有应用保活。这是链式模式的短时后台验证，不验证自动优选后台耗电或真机长时省电。

后台工具新增本地 `PrismAdvancedCI` 入口，并在任何安装或配置重置前检查包的 DEBUGGABLE 标记，保留精确 AVD 身份检查。6 项 Python 前置校验测试通过，覆盖 release 包、缺失包、相似/无关标记、错误 AVD 的提前拒绝，以及有效调试包进入只读电源检查；已加入 CI 工作流，但本轮尚未提交或运行新的远端 CI。测试不会调用真实 adb 或修改设备。标准 AndroidJUnitRunner 已从 seed 构建恢复。

Android 17 / 16 KiB 独立 180 秒 Doze 同样通过（`artifacts/recovery-cycle-background-api37.json`），包括强制 IDLE、进程/VPN 身份、冷 DNS/严格 TLS/HTTP 200、断开不复活与断开对照。该次实际运行经过新增调试包前置检查；API 26 的本轮后台运行早于此工具检查改动。汇总和本地产物摘要见 `artifacts/recovery-cycle-proof.json`；标准测试包恢复，专用实例及夹具关闭。仍无真机长时、耗电或自动优选后台频率新证据，尚未重新运行完整远端 CI，也未发布。

34 项手机 Rust 回归通过，包含旧配置默认、自定义地址拒绝边界、真实 fallback 转发、均衡按目标粘性/分配、失败成员排除、连续重建保留可用性与节点变化失效。Android 新增实际 TLS、载荷归属及重建后代理 DNS 回归；完整构建、双系统各 21 项及独立 180 秒 Doze 已通过，已发布 Beta.5。

Beta.5 已发布高级扩展第一批：候选组 url-test、fallback、按目标粘性负载均衡及自定义 HTTPS 检测地址。新增七项高级目标尚未全部完成，见[高级能力路线](android-advanced.md)。原签名和旧版升级通道继续兼容。

## Beta.5 发布与验收回执

2026-11-19 发布 `0.2.0-beta.5`（versionCode 6），源码 `68de83a` 的[发布 CI 44346214298](https://github.com/yuuolo/prism-phone/actions/runs/44346214298)全部通过：双架构 Debug/Release、双 Lint、34 项手机 Rust、101 项 Linux 共享内核回归、7 项 Android 单元测试、双系统各 21 项完整回归及各自独立 180 秒 Doze。

实际原签名 APK 从 Beta.4 经应用按钮及系统 Only this time/Update 覆盖，延续原 Beta.2 的 UID、Keystore、节点/凭据/来源/收藏/选择与规则，来源仍为 Ask every time。安装从已校验缓存开始，未算作本次线上检查/下载验收。两个仓库公开 APK、校验和与各自更新清单已下载回读一致；桌面 latest 仍为 v0.2.13。

APK 大小 24,245,867 字节，SHA-256：`e6ce1e64443932880c8df9caf97f4a35247473151b62a2f2287ee1897f8d08da`。本次只交付高级目标的候选组第一批，其余目标继续开发；真机条件仍未完成。

## 第二批交付

应用名单与质量历史的具体范围、系统 UID 语义和验收方法见[实现说明](android-app-routing.md)。此处应用名单是系统 VPN 包含/排除，不是 VPN 内应用指定代理；历史最多 10 点，不增加探测。

2026-11-19 发布 `0.2.0-beta.7`（code 8），源码 `410f29a` 的[发布 CI 44451687529](https://github.com/yuuolo/prism-phone/actions/runs/44451687529)全部通过：双架构 Debug/Release、双 Lint、34 项手机 Rust、101 项 Linux 共享内核回归、7 项 Android 单元测试、双系统各 23 项完整回归及各自独立 180 秒 Doze。两份后台报告已核对强制 IDLE、原进程与 VPN 不变、冷 DNS、严格 TLS/HTTP 200 和断开对照。原签名发布包从 Beta.6 经应用按钮及系统 Only this time/Update 覆盖，延续原 Beta.2 的 UID、Keystore、节点/凭据/来源/收藏/选择与规则；实际界面保存的应用包含名单也保留，主页范围提示核对通过。来源仍为 Ask every time，安装从已校验缓存开始，不算作本次线上检查/下载验收。新旧仓库公开 APK、校验和及各自下载地址的更新清单均已回读一致，桌面 latest 仍为 v0.2.13。[发布说明](releases/android-0.2.0-beta.7.md)。

## 第三批交付

高级 DNS 的协议、隐私边界、hosts 域名保留、端口防回环、IPv6 限制和诊断证据见[高级 DNS](android-dns.md)。

2026-11-19 发布 `0.2.0-beta.8`（code 10，9 仅本地候选未发布），源码 `17ac37a` 的[发布 CI 44461176843](https://github.com/yuuolo/prism-phone/actions/runs/44461176843)全部通过：双架构 Debug/Release、双 Lint、37 项手机 Rust、102 项 Linux 共享内核回归、7 项 Android 单元测试、双系统各 25 项及各自独立 180 秒 Doze。后台原始报告已核对强制 IDLE、进程/VPN 不变、冷 DNS、严格 TLS/HTTP 200、断开不复活及断开对照拒绝。原签名包从 Beta.7 code 8 经未发布候选 9、最终 10 连续通过应用按钮及系统 Only this time/Update 覆盖，保留原 Beta.2 的 UID、Keystore、节点/凭据/来源/收藏/选择与规则；应用包含名单及旧默认 DNS 保留，安装来源仍为 Ask every time。安装从已校验缓存开始，不算作本次线上检查/下载验收。最终 CI ZIP 官方摘要核对通过；两个仓库公开 APK、校验和及各自更新地址已回读一致，桌面 latest 仍为 v0.2.13。[发布说明](releases/android-0.2.0-beta.8.md)。
