# Android 独立后台软件验收

此验收仅操作 `PrismPhoneCI` 和 `PrismPhoneApi26` 两个可丢弃模拟器，会覆盖其中的测试配置。API 26 与 Android 17 / 16 KiB 均已在本机通过 180 秒强制深度 Doze 验收；默认 CI 随后执行相同脚本，结果保存为 `emulator-results/background.json`。

## 验证方法

1. 专用 `BackgroundSeedInstrumentation` 只导入两跳 SOCKS 测试节点与路由，然后退出。脚本强制停止应用，确认进程消失，再从正常界面点击连接；待机阶段没有 instrumentation 持续附着。
2. 独立的 Android ELF 客户端使用普通系统 DNS 和 TCP，不调用内核的 socket protect。既要求系统解析返回 fake-IP，也要求 TCP 本地源地址为 VPN 的 `172.19.0.1`，然后执行正常证书及主机名校验的公网 TLS 请求，要求 HTTP 200。断开后的客户端必须失败，避免把宿主或系统 DNS 行为误认作 VPN 成功。
3. 测试规则默认 REJECT。第一条 `198.18.0.0/15 → REJECT` 允许真实解析，第二条 `0.0.0.0/0 → SELECTED` 禁止自行解析。fake-IP 还原域名后，必须先经原生代理 DoH 获得真实地址，后条规则才会放行；无答案或 fake-IP 答案不能通过。静置前访问 `one.one.one.one`，静置后首次访问 `cloudflare-dns.com`，覆盖待机中的冷解析。
4. 退回桌面、熄屏、模拟拔电并强制进入 Doze；180 秒内只输出宿主计时，不向应用发送保活或周期探测。随后仍在 IDLE 状态下执行独立客户端，检查前台服务、进程及 VPN network ID 不变，唤醒后再验证一次。
5. 从正常界面断开，确认 VPN 和前台服务释放且不自行复活；执行断开对照，最后恢复电源覆盖状态并停止测试应用。

首跳通过模拟器物理路由访问宿主回环端口 19092，只转到第二跳 19090；第二跳只允许固定公网 `1.1.1.1:443`，可选接受上述两个固定 TLS 域名并转往同一服务，不允许任意目标。无 adb reverse 数据路径、TLS 解密、测试 CA、伪造 DNS 答案、root 或电池白名单。HTTP 请求使用 Cloudflare 的[官方 DoH JSON 接口](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)。

## 构建与结果边界

`prism-acceptance-client` 仅由 Cargo 的 `acceptance-tools` feature 显式构建，作为独立测试制品，不进入 APK。专用 seed APK 与默认 JUnit APK 分开保存，默认回归仍执行原有 18 项。CI 在两套系统的完整回归后分别执行本项验收。

这证明模拟器 Doze 策略下的短时后台存活、冷 DNS、TUN/TLS、恢复及手动断开行为。PSS 仅记录静置前后的样本，不能据此宣称无泄漏、低耗电或长时稳定。模拟器强制 Doze 不等于真机 CPU 深睡，也不替代 ARM64 真机长时锁屏、厂商省电、无线切换、真实节点账号或多设备局域网验收。正式包版本、签名、升级通道与平台暂停范围均不改变。
