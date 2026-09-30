# ECHWorkers

基于 **Cloudflare Workers + ECH（Encrypted Client Hello）** 的透明代理桌面工具。

客户端在本机创建 TUN 虚拟网卡接管全局流量，TLS 握手中的 SNI 被 ECH 加密后，流量经 WebSocket 多路复用隧道转发到部署在 Cloudflare Workers 上的服务端，再由 Worker 连接真实目标。整条链路上，中间设备既看不到真实 SNI，也只能看到你在访问 Cloudflare。

## 特性

- **ECH 隐匿 SNI**：通过 DoH 查询 HTTPS(type=65) 记录获取 ECH 配置，反射注入 Go `tls.Config`（Go 1.23+ 实验字段），握手失败自动刷新重试
- **WebSocket 多路复用**：一条 WS 长连接承载多个 TCP 流（自定义帧协议），连接建立零握手开销；会话池按需扩容、空闲保温、失效自动重连
- **gVisor 用户态协议栈**：`wireguard/tun` + gVisor netstack 拦截 TCP，无需系统代理/SOCKS
- **DNS 劫持 + 缓存**：UDP:53 被 gVisor 截获后转发为 ECH DoH，带 TTL 缓存与负缓存
- **TLS 会话恢复**：共享 `ClientSessionCache`，新会话握手省去证书链解析开销
- **分流**：全局 / 跳过中国大陆（内嵌 CN IP v4/v6 列表，二分查找）/ 直连
- **优雅退出**：context 取消式生命周期，退出时恢复路由与网关

## 平台支持

| 平台          | 状态      | 权限      | 说明                                            |
|---------------|-----------|-----------|-------------------------------------------------|
| Windows       | ✅ 完整   | 管理员    | wintun.dll 已内嵌，自动提取                     |
| macOS         | ⚠️ 实验性 | root/sudo | utun，接口随退出自动销毁                        |
| Linux         | ⚠️ 实验性 | root/sudo | `/dev/net/tun`，`ip` 命令配置                   |
| iOS / Android | ❌        | —         | 透明代理需走系统 VPN Provider，架构不同，不支持 |

macOS/Linux 注意事项：

- 需要 `sudo` 运行（创建 TUN 和改路由都需要 root）；
- 系统性 DNS **不会被修改**：发往局域网路由器的 DNS 查询走直连路由绕过 TUN（明文），进 TUN 的 DNS 照旧被劫持为 DoH；
- macOS/Linux 版尚未经过广泛真机验证，遇到问题欢迎反馈。

## 服务端部署

1. 将 `_worker.js` 部署到 Cloudflare Workers（Dashboard 粘贴或 `wrangler deploy`）；
2. 修改文件开头的 `const token = '你的密码'`，**务必设置非空密码**，否则任何人都能白嫖你的 Worker；
3. 浏览器访问 Worker 域名，应显示 `WebSocket Mux Proxy Server`。

## 客户端使用

1. 启动程序，填入：
   - **服务器**：Worker 域名或 `IP:443`（`域名:端口[/路径]` 格式）
   - **密码**：与服务端 `token` 一致
   - **分流模式**：全局 / 跳过中国大陆 / 直连
2. 点击启动，首次启动会查询 ECH 配置（约 1~2 秒），之后秒连；
3. 停止代理会自动恢复路由。若程序崩溃导致断网，重启一次程序或手动删除 `/1` 拆分路由即可。

## 从源码构建

依赖：Go 1.27+（需支持 ECH）、Node.js、pnpm、[Task](https://taskfile.dev)、wails3 CLI。

```bash
# Windows / macOS / Linux 桌面版
task build              # 构建当前平台
task build GOOS=linux   # 交叉编译（产物在 bin/）
task package            # 打包发行版

# 开发模式（前端热重载）
task dev

# 无 GUI 服务端模式（HTTP 管理 + 无头代理）
task build:server
```

GUI 依赖 Wails v3（beta），前端为 SolidJS + UnoCSS（`frontend/`）。

## 协议简述

一条 WS 二进制消息 = 一帧：

```
+--------+------------+--------+------------------+
| type 1B| streamID 4B| len 2B | payload (≤32KB)  |
+--------+------------+--------+------------------+
```

| 帧类型        | 方向 | 含义                                             |
|---------------|------|--------------------------------------------------|
| `SYN 0x01`    | C→W  | 开流，payload = `host:port`                      |
| `OPENED 0x02` | W→C  | 流已建立；payload 带 `ERR:` 前缀表示目标连接失败 |
| `DATA 0x03`   | 双向 | 流数据                                           |
| `FIN 0x04`    | 双向 | 本端写完（半关闭）                               |
| `RST 0x05`    | 双向 | 异常中止流                                       |

保活使用 WS 协议层 ping/pong。streamID 由客户端单调分配，Worker 永不主动开流。每条 WS 会话最多约 5 条并发流（受 Cloudflare 每调用 6 个出站 socket 限制），客户端会话池最多 16 会话。

## 许可

见 [LICENSE](LICENSE)。

## 免责声明

本项目仅供学习研究网络协议技术，请遵守当地法律法规，勿用于非法用途。
