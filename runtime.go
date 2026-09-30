package main

// runtime.go —— 代理运行时状态收敛。
// 此前这些状态散落为 10 个包级可变全局变量（serverAddr/serverIP/token/dnsServer/
// echDomain/routingMode/echList/globalDoHClient/localPhysicalIP/muxPool），
// 生命周期是否残留全靠人脑记忆。现统一收敛到 proxyRuntime：
// StartProxy 创建唯一的 app 实例，ctx 取消时 stop() 释放全部资源并置空 app。

import (
	"net"
	"net/http"
	"sync"
)

// ProxyConfig 一次代理会话的完整配置（启动后只读）。
type ProxyConfig struct {
	ServerAddr  string // Worker 地址 host:port[/path]
	ServerIP    string // 解析后的真实 IP（防止 route add 域名失败）
	Token       string // WebSocket 鉴权 token（可空）
	DNSServer   string // 用于查询 ECH 的 DoH 服务器
	ECHDomain   string // 查询 ECH 配置的域名
	RoutingMode string // 分流模式: "global", "bypass_cn", "none"
}

type proxyRuntime struct {
	cfg     ProxyConfig
	logChan chan string

	echMu   sync.RWMutex
	echList []byte // 当前 ECH 配置（queryHTTPSRecord 获取）

	dohMu     sync.Mutex
	dohClient *http.Client // 复用 HTTP/2 连接的 DoH 客户端（ECH 配置变化时需失效）

	muxPool *muxSessionPool

	localIP net.IP // 本机物理网卡 IP，出站绑定用（防路由死循环）

	chinaMu  sync.RWMutex
	chinaIP4 []ipRange
	chinaIP6 []ipRangeV6
}

// app 当前代理运行时；未启动时为 nil。
var app *proxyRuntime

// stop 释放运行时全部资源（幂等）。ctx 取消时由 StartProxy 的 goroutine 调用。
func (r *proxyRuntime) stop() {
	r.stopMuxPool()
	r.invalidateDoHClient()
	if app == r {
		app = nil
	}
}

// invalidateDoHClient 关闭复用的 DoH 客户端。必须在两种时机调用：
// 1. 停止代理（旧的 serverIP 绑定与 ECH 配置不再可信）；
// 2. ECH 配置刷新后（客户端 TLS 配置里仍是旧 ECH 配置）。
// 此前只在请求失败时才重建，是配置变更后 DNS 行为不变的隐患来源。
func (r *proxyRuntime) invalidateDoHClient() {
	r.dohMu.Lock()
	r.dohClient = nil
	r.dohMu.Unlock()
}
