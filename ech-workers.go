package main

// ech-workers.go —— 代理生命周期入口与分流逻辑。
// 运行时状态收敛见 runtime.go，ECH 配置管理见 ech.go，拨号见 dial.go，
// DoH 客户端见 doh.go，多路复用见 mux.go，TUN 接管见 tun.go。

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
)

// ipRange 表示一个IPv4 IP范围
type ipRange struct {
	start uint32
	end   uint32
}

// ipRangeV6 表示一个IPv6 IP范围
type ipRangeV6 struct {
	start [16]byte
	end   [16]byte
}

// ======================== 日志重定向 ========================

// chanWriter 拦截标准日志输出并将其发送到 Wails 管道中
type chanWriter struct {
	ch chan string
}

func (cw *chanWriter) Write(p []byte) (n int, err error) {
	// 使用 defer recover 机制捕获向已关闭 channel 发送数据引发的 panic
	defer func() {
		if r := recover(); r != nil {
			// 捕获到了向关闭通道发送的 panic，静默丢弃该日志，防止程序崩溃
		}
	}()

	msg := string(p)
	if cw.ch != nil {
		// 使用非阻塞发送，防止日志通道满时阻塞核心网络逻辑
		select {
		case cw.ch <- msg:
		default:
		}
	}
	return len(p), nil
}

// ======================== 核心入口 ========================

// StartProxy 创建运行时并启动代理。ctx 取消时所有资源由 app.stop() 统一释放。
func StartProxy(ctx context.Context, server, tunName, tokenStr, ip, dns, ech, routing string, logChan chan string) error {
	// 1. 设置日志重定向
	log.SetOutput(&chanWriter{ch: logChan})
	log.SetFlags(log.Ltime)

	// --- 强制将 serverIP 解析为真实 IP，防止 route add 失败 ---
	if ip == "" || net.ParseIP(ip) == nil {
		// 如果传入的 serverIP 是域名（如 saas.sin.fan）
		host := ip
		if host == "" {
			host, _, _, _ = parseServerAddr(server) // 从 server 取 host
		}

		ips, err := net.LookupIP(host)
		if err == nil && len(ips) > 0 {
			for _, resolveIP := range ips {
				if resolveIP.To4() != nil {
					ip = resolveIP.String()
					log.Printf("[系统] 服务器域名解析为真实 IPv4: %s", ip)
					break
				}
			}
		} else {
			log.Printf("[警告] 无法解析服务器域名: %s", host)
		}
	}
	// -------------------------------------------------------------

	cfg := ProxyConfig{
		ServerAddr:  server,
		ServerIP:    ip, // 现在这里一定是一个真实的 IP 地址
		Token:       tokenStr,
		DNSServer:   dns,
		ECHDomain:   ech,
		RoutingMode: routing,
	}

	if cfg.ServerAddr == "" {
		return errors.New("必须指定服务端地址 server")
	}

	r := &proxyRuntime{cfg: cfg, logChan: logChan}
	log.Printf("[启动] 正在获取 ECH 配置...")
	if err := r.prepareECH(); err != nil {
		return fmt.Errorf("获取 ECH 配置失败: %w", err)
	}
	app = r

	// 加载中国IP列表（如果需要）
	switch r.cfg.RoutingMode {
	case "bypass_cn":
		log.Printf("[启动] 分流模式: 跳过中国大陆，正在加载中国IP列表...")
		ipv4Count, ipv6Count := r.loadChinaIPList(), r.loadChinaIPV6List()

		if ipv4Count > 0 || ipv6Count > 0 {
			log.Printf("[启动] 已加载 %d 个中国IPv4段, %d 个中国IPv6段", ipv4Count, ipv6Count)
		} else {
			log.Printf("[警告] 未加载到任何中国IP列表，将使用默认规则")
		}
	case "global":
		log.Printf("[启动] 分流模式: 全局代理")
	case "none":
		log.Printf("[启动] 分流模式: 不改变代理（直连模式）")
	default:
		log.Printf("[警告] 未知的分流模式: %s，使用默认模式 global", r.cfg.RoutingMode)
		r.cfg.RoutingMode = "global"
	}

	// 2. 启动 mux 会话池（复用长连接，消除每条 TCP 连接的握手延迟）
	r.startMuxPool()
	go func() {
		<-ctx.Done()
		r.stop()
	}()

	// 3. 启动 TUN 代理 (传递 Context 用于优雅退出)
	go func() {
		if err := runTUNProxy(ctx, r, tunName); err != nil {
			log.Printf("[TUN] 启动失败: %v", err)
		}
	}()

	return nil
}

// ======================== 分流：中国 IP 列表 ========================

// ipToUint32 将IP地址转换为uint32
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// compareIPv6 比较两个IPv6地址，返回 -1, 0, 或 1
func compareIPv6(a, b [16]byte) int {
	for i := range 16 {
		if a[i] < b[i] {
			return -1
		} else if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// isChinaIP 检查IP是否在中国IP列表中（支持IPv4和IPv6）
func (r *proxyRuntime) isChinaIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// 检查IPv4
	if ip.To4() != nil {
		ipUint32 := ipToUint32(ip)
		if ipUint32 == 0 {
			return false
		}

		r.chinaMu.RLock()
		defer r.chinaMu.RUnlock()

		// 二分查找
		left, right := 0, len(r.chinaIP4)
		for left < right {
			mid := (left + right) / 2
			v := r.chinaIP4[mid]
			if ipUint32 < v.start {
				right = mid
			} else if ipUint32 > v.end {
				left = mid + 1
			} else {
				return true
			}
		}
		return false
	}

	// 检查IPv6
	ipBytes := ip.To16()
	if ipBytes == nil {
		return false
	}

	var ipArray [16]byte
	copy(ipArray[:], ipBytes)

	r.chinaMu.RLock()
	defer r.chinaMu.RUnlock()

	// 二分查找IPv6
	left, right := 0, len(r.chinaIP6)
	for left < right {
		mid := (left + right) / 2
		v := r.chinaIP6[mid]

		// 比较起始IP
		cmpStart := compareIPv6(ipArray, v.start)
		if cmpStart < 0 {
			right = mid
			continue
		}

		// 比较结束IP
		cmpEnd := compareIPv6(ipArray, v.end)
		if cmpEnd > 0 {
			left = mid + 1
			continue
		}

		// 在范围内
		return true
	}
	return false
}

// loadChinaIPList 从嵌入资源中加载中国 IPv4 地址段，返回加载的段数。
func (r *proxyRuntime) loadChinaIPList() int {
	// 直接从 main.go 定义的 ipData 读取
	data, err := ipData.ReadFile("chn_ip.txt")
	if err != nil {
		log.Printf("[警告] 未能在嵌入资源中找到 chn_ip.txt: %v", err)
		return 0
	}

	var ranges []ipRange
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		startIP := net.ParseIP(parts[0])
		endIP := net.ParseIP(parts[1])
		if startIP == nil || endIP == nil {
			continue
		}

		start := ipToUint32(startIP)
		end := ipToUint32(endIP)
		if start > 0 && end > 0 && start <= end {
			ranges = append(ranges, ipRange{start: start, end: end})
		}
	}

	if len(ranges) == 0 {
		log.Printf("[警告] 嵌入的 IPv4 列表为空")
		return 0
	}

	// 排序（二分查找的前提）
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})

	r.chinaMu.Lock()
	r.chinaIP4 = ranges
	r.chinaMu.Unlock()

	log.Printf("[加载] 已从嵌入资源加载 %d 条 IPv4 范围", len(ranges))
	return len(ranges)
}

// loadChinaIPV6List 从嵌入资源加载 IPv6 列表，返回加载的段数。
func (r *proxyRuntime) loadChinaIPV6List() int {
	data, err := ipData.ReadFile("chn_ip_v6.txt")
	if err != nil {
		log.Printf("[警告] 未能在嵌入资源中找到 chn_ip_v6.txt，跳过 IPv6 分流")
		return 0
	}

	var ranges []ipRangeV6
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		startIP := net.ParseIP(parts[0])
		endIP := net.ParseIP(parts[1])
		if startIP == nil || endIP == nil {
			continue
		}

		startBytes := startIP.To16()
		endBytes := endIP.To16()
		if startBytes == nil || endBytes == nil {
			continue
		}

		var start, end [16]byte
		copy(start[:], startBytes)
		copy(end[:], endBytes)

		if compareIPv6(start, end) <= 0 {
			ranges = append(ranges, ipRangeV6{start: start, end: end})
		}
	}

	if len(ranges) == 0 {
		return 0
	}

	// 排序
	sort.Slice(ranges, func(i, j int) bool {
		return compareIPv6(ranges[i].start, ranges[j].start) < 0
	})

	r.chinaMu.Lock()
	r.chinaIP6 = ranges
	r.chinaMu.Unlock()

	log.Printf("[加载] 已从嵌入资源加载 %d 条 IPv6 范围", len(ranges))
	return len(ranges)
}

// shouldBypassProxy 根据分流模式判断是否应该绕过代理（直连）
func (r *proxyRuntime) shouldBypassProxy(targetHost string) bool {
	switch r.cfg.RoutingMode {
	case "none":
		// "不改变代理"模式：所有流量都直连
		return true
	case "global":
		// "全局代理"模式：所有流量都走代理
		return false
	case "bypass_cn":
		// "跳过中国大陆"模式：检查是否是中国IP
		// 先尝试解析为IP
		if ip := net.ParseIP(targetHost); ip != nil {
			return r.isChinaIP(targetHost)
		}
		// 如果是域名，先解析IP
		ips, err := net.LookupIP(targetHost)
		if err != nil {
			// 解析失败，默认走代理
			return false
		}
		// 检查所有解析到的IP，如果有一个是中国IP，就直连
		for _, ip := range ips {
			if r.isChinaIP(ip.String()) {
				return true
			}
		}
		// 都不是中国IP，走代理
		return false
	}
	// 未知模式，默认走代理
	return false
}
