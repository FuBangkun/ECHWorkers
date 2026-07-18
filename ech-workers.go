package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ======================== 全局参数 ========================

var (
	serverAddr  string
	serverIP    string
	token       string
	dnsServer   string
	echDomain   string
	routingMode string // 分流模式: "global", "bypass_cn", "none"

	echListMu sync.RWMutex
	echList   []byte

	// 中国IP列表（IPv4）
	chinaIPRangesMu sync.RWMutex
	chinaIPRanges   []ipRange

	// 中国IP列表（IPv6）
	chinaIPV6RangesMu sync.RWMutex
	chinaIPV6Ranges   []ipRangeV6

	globalDoHClient *http.Client
	globalDoHMu     sync.Mutex
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

// StartProxy 替代了原先的 main() 函数
func StartProxy(ctx context.Context, server, tunName, tokenStr, ip, dns, ech, routing string, logChan chan string) error {
	// 1. 设置日志重定向
	log.SetOutput(&chanWriter{ch: logChan})
	log.SetFlags(log.Ltime)

	// --- 新增：强制将 serverIP 解析为真实 IP，防止 route add 失败 ---
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

	// 2. 初始化全局参数
	serverAddr = server
	token = tokenStr
	serverIP = ip // 现在这里一定是一个 真实的 IP 地址
	dnsServer = dns
	echDomain = ech
	routingMode = routing

	if serverAddr == "" {
		return errors.New("必须指定服务端地址 server")
	}

	log.Printf("[启动] 正在获取 ECH 配置...")
	if err := prepareECH(); err != nil {
		return fmt.Errorf("获取 ECH 配置失败: %w", err)
	}

	// 加载中国IP列表（如果需要）
	switch routingMode {
	case "bypass_cn":
		log.Printf("[启动] 分流模式: 跳过中国大陆，正在加载中国IP列表...")
		ipv4Count := 0
		ipv6Count := 0

		if err := loadChinaIPList(); err != nil {
			log.Printf("[警告] 加载中国IPv4列表失败: %v", err)
		} else {
			chinaIPRangesMu.RLock()
			ipv4Count = len(chinaIPRanges)
			chinaIPRangesMu.RUnlock()
		}

		if err := loadChinaIPV6List(); err != nil {
			log.Printf("[警告] 加载中国IPv6列表失败: %v", err)
		} else {
			chinaIPV6RangesMu.RLock()
			ipv6Count = len(chinaIPV6Ranges)
			chinaIPV6RangesMu.RUnlock()
		}

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
		log.Printf("[警告] 未知的分流模式: %s，使用默认模式 global", routingMode)
		routingMode = "global"
	}

	// 3. 启动 TUN 代理 (传递 Context 用于优雅退出)
	go func() {
		if err := runTUNProxy(ctx, tunName); err != nil {
			log.Printf("[TUN] 启动失败: %v", err)
		}
	}()

	return nil
}

// ======================== 工具函数 ========================

// ipToUint32 将IP地址转换为uint32
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// isChinaIP 检查IP是否在中国IP列表中（支持IPv4和IPv6）
func isChinaIP(ipStr string) bool {
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

		chinaIPRangesMu.RLock()
		defer chinaIPRangesMu.RUnlock()

		// 二分查找
		left, right := 0, len(chinaIPRanges)
		for left < right {
			mid := (left + right) / 2
			r := chinaIPRanges[mid]
			if ipUint32 < r.start {
				right = mid
			} else if ipUint32 > r.end {
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

	chinaIPV6RangesMu.RLock()
	defer chinaIPV6RangesMu.RUnlock()

	// 二分查找IPv6
	left, right := 0, len(chinaIPV6Ranges)
	for left < right {
		mid := (left + right) / 2
		r := chinaIPV6Ranges[mid]

		// 比较起始IP
		cmpStart := compareIPv6(ipArray, r.start)
		if cmpStart < 0 {
			right = mid
			continue
		}

		// 比较结束IP
		cmpEnd := compareIPv6(ipArray, r.end)
		if cmpEnd > 0 {
			left = mid + 1
			continue
		}

		// 在范围内
		return true
	}
	return false
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

// loadChinaIPList 从嵌入资源中加载中国 IPv4 地址段，用于 bypass_cn 分流模式。
func loadChinaIPList() error {
	// 1. 直接从 main.go 定义的 ipData 读取
	data, err := ipData.ReadFile("chn_ip.txt")
	if err != nil {
		return fmt.Errorf("未能在嵌入资源中找到 chn_ip.txt: %w", err)
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
		return fmt.Errorf("嵌入的 IPv4 列表为空")
	}

	// 2. 排序（二分查找的前提）
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})

	// 3. 写入全局变量
	chinaIPRangesMu.Lock()
	chinaIPRanges = ranges
	chinaIPRangesMu.Unlock()

	log.Printf("[加载] 已从嵌入资源加载 %d 条 IPv4 范围", len(ranges))
	return nil
}

// loadChinaIPV6List 从嵌入资源加载 IPv6 列表
func loadChinaIPV6List() error {
	// 1. 读取文件
	data, err := ipData.ReadFile("chn_ip_v6.txt")
	if err != nil {
		log.Printf("[警告] 未能在嵌入资源中找到 chn_ip_v6.txt，跳过 IPv6 分流")
		return nil
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
		return nil
	}

	// 2. 排序
	sort.Slice(ranges, func(i, j int) bool {
		return compareIPv6(ranges[i].start, ranges[j].start) < 0
	})

	// 3. 写入全局变量
	chinaIPV6RangesMu.Lock()
	chinaIPV6Ranges = ranges
	chinaIPV6RangesMu.Unlock()

	log.Printf("[加载] 已从嵌入资源加载 %d 条 IPv6 范围", len(ranges))
	return nil
}

// shouldBypassProxy 根据分流模式判断是否应该绕过代理（直连）
func shouldBypassProxy(targetHost string) bool {
	if routingMode == "none" {
		// "不改变代理"模式：所有流量都直连
		return true
	}
	if routingMode == "global" {
		// "全局代理"模式：所有流量都走代理
		return false
	}
	if routingMode == "bypass_cn" {
		// "跳过中国大陆"模式：检查是否是中国IP
		// 先尝试解析为IP
		if ip := net.ParseIP(targetHost); ip != nil {
			return isChinaIP(targetHost)
		}
		// 如果是域名，先解析IP
		ips, err := net.LookupIP(targetHost)
		if err != nil {
			// 解析失败，默认走代理
			return false
		}
		// 检查所有解析到的IP，如果有一个是中国IP，就直连
		for _, ip := range ips {
			if isChinaIP(ip.String()) {
				return true
			}
		}
		// 都不是中国IP，走代理
		return false
	}
	// 未知模式，默认走代理
	return false
}

// ======================== ECH 支持 ========================

const typeHTTPS = 65

func prepareECH() error {
	echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
	if err != nil {
		return fmt.Errorf("DNS 查询失败: %w", err)
	}
	if echBase64 == "" {
		return errors.New("未找到 ECH 参数")
	}
	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("ECH 解码失败: %w", err)
	}
	echListMu.Lock()
	echList = raw
	echListMu.Unlock()
	log.Printf("[ECH] 配置已加载，长度: %d 字节", len(raw))
	return nil
}

// refreshECH 刷新 ECH 配置（通常在连接失败时调用）。
func refreshECH() error {
	log.Printf("[ECH] 刷新配置...")
	return prepareECH()
}

// getECHList 返回当前缓存的 ECH 配置（线程安全）。
func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置未加载")
	}
	return echList, nil
}

// buildTLSConfigWithECH 构建带 ECH 支持的 TLS 配置。
func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}

	if len(echList) == 0 {
		return nil, errors.New("ECH 配置为空，这是必需功能")
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    roots,
	}

	// 使用反射设置 ECH 字段（ECH 是核心功能，必须设置成功）
	if err := setECHConfig(config, echList); err != nil {
		return nil, fmt.Errorf("设置 ECH 配置失败（需要 Go 1.23+ 或支持 ECH 的版本）: %w", err)
	}

	return config, nil
}

// setECHConfig 使用反射设置 ECH 配置（ECH 是核心功能，必须成功）
func setECHConfig(config *tls.Config, echList []byte) error {
	configValue := reflect.ValueOf(config).Elem()

	// 设置 EncryptedClientHelloConfigList（必需）
	field1 := configValue.FieldByName("EncryptedClientHelloConfigList")
	if !field1.IsValid() || !field1.CanSet() {
		return fmt.Errorf("EncryptedClientHelloConfigList 字段不可用，需要 Go 1.23+ 版本")
	}
	field1.Set(reflect.ValueOf(echList))

	// 设置 EncryptedClientHelloRejectionVerify（必需）
	field2 := configValue.FieldByName("EncryptedClientHelloRejectionVerify")
	if !field2.IsValid() || !field2.CanSet() {
		return fmt.Errorf("EncryptedClientHelloRejectionVerify 字段不可用，需要 Go 1.23+ 版本")
	}
	rejectionFunc := func(cs tls.ConnectionState) error {
		return errors.New("服务器拒绝 ECH")
	}
	field2.Set(reflect.ValueOf(rejectionFunc))

	return nil
}

// queryHTTPSRecord 通过 DoH 查询域名的 HTTPS 记录，用于获取 ECH 配置。
func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	dohURL := dnsServer
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	return queryDoH(domain, dohURL)
}

// queryDoH 执行 DoH 查询（用于获取 ECH 配置）
func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("无效的 DoH URL: %v", err)
	}

	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)

	q := u.Query()
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH 请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH 服务器返回错误: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取 DoH 响应失败: %v", err)
	}

	return parseDNSResponse(body)
}

// buildDNSQuery 构建标准的 DNS 查询报文。
func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for label := range strings.SplitSeq(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

// parseDNSResponse 解析 DNS 响应报文，提取 HTTPS 记录中的 ECH 参数。
func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("响应过短")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", errors.New("无应答记录")
	}

	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5

	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

// parseHTTPSRecord 从 HTTPS 记录中解析 ECH 配置（Base64 编码）。
func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

// ======================== DoH 代理支持 ========================

// queryDoHForProxy 通过 ECH 转发 DNS 查询到 Cloudflare DoH
func queryDoHForProxy(dnsQuery []byte) ([]byte, error) {
	_, port, _, err := parseServerAddr(serverAddr)
	if err != nil {
		return nil, err
	}

	dohURL := fmt.Sprintf("https://cloudflare-dns.com:%s/dns-query", port)

	// 【关键修复 2】复用 http.Client，利用 HTTP/2 多路复用，极大提升解析速度并防封锁
	globalDoHMu.Lock()
	if globalDoHClient == nil {
		echBytes, err := getECHList()
		if err != nil {
			globalDoHMu.Unlock()
			return nil, fmt.Errorf("获取 ECH 配置失败: %w", err)
		}

		tlsCfg, err := buildTLSConfigWithECH("cloudflare-dns.com", echBytes)
		if err != nil {
			globalDoHMu.Unlock()
			return nil, fmt.Errorf("构建 TLS 配置失败: %w", err)
		}

		transport := &http.Transport{
			TLSClientConfig:   tlsCfg,
			ForceAttemptHTTP2: true, // 强制开启 HTTP/2 多路复用
		}

		// 绑定物理网卡 IP（如果上一轮已定义）
		if serverIP != "" {
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				dialer := &net.Dialer{
					Timeout: 10 * time.Second,
				}
				// 假设 localPhysicalIP 在其他文件中声明过，否则可以注释掉这两行
				if localPhysicalIP != nil {
					dialer.LocalAddr = &net.TCPAddr{IP: localPhysicalIP, Port: 0}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(serverIP, port))
			}
		}

		globalDoHClient = &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		}
	}
	client := globalDoHClient
	globalDoHMu.Unlock()

	// 发送 DoH 请求
	req, err := http.NewRequest("POST", dohURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		// 如果网络断开或连接已死，清空复用池，以便下次重新建立
		globalDoHMu.Lock()
		globalDoHClient = nil
		globalDoHMu.Unlock()
		return nil, fmt.Errorf("DoH 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 响应错误: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// ======================== WebSocket 客户端 ========================

// parseServerAddr 解析服务器地址，返回 host、port、path 和错误信息。
func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	slashIdx := strings.Index(addr, "/")
	if slashIdx != -1 {
		path = addr[slashIdx:]
		addr = addr[:slashIdx]
	}

	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", "", fmt.Errorf("无效的服务器地址格式: %v", err)
	}

	return host, port, path, nil
}

// dialWebSocketWithECH 使用 ECH 配置建立 WebSocket 连接，支持自动重试。
func dialWebSocketWithECH(maxRetries int) (*websocket.Conn, error) {
	host, port, path, err := parseServerAddr(serverAddr)
	if err != nil {
		return nil, err
	}

	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		echBytes, echErr := getECHList()
		if echErr != nil {
			if attempt < maxRetries {
				refreshECH()
				continue
			}
			return nil, echErr
		}

		tlsCfg, tlsErr := buildTLSConfigWithECH(host, echBytes)
		if tlsErr != nil {
			return nil, tlsErr
		}

		dialer := websocket.Dialer{
			TLSClientConfig: tlsCfg,
			Subprotocols: func() []string {
				if token == "" {
					return nil
				}
				return []string{token}
			}(),
			HandshakeTimeout: 10 * time.Second,
		}

		if serverIP != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				// --- 新增：同样绑定本地物理 IP ---
				d := &net.Dialer{
					Timeout: 10 * time.Second,
				}
				// 需要引入 tun.go 中的 localPhysicalIP（在同一个 main 包下可以直接用）
				if localPhysicalIP != nil {
					d.LocalAddr = &net.TCPAddr{IP: localPhysicalIP, Port: 0}
				}
				return d.Dial(network, net.JoinHostPort(serverIP, port))
			}
		}

		wsConn, _, dialErr := dialer.Dial(wsURL, nil)
		if dialErr != nil {
			if strings.Contains(dialErr.Error(), "ECH") && attempt < maxRetries {
				log.Printf("[ECH] 连接失败，尝试刷新配置 (%d/%d)", attempt, maxRetries)
				refreshECH()
				time.Sleep(time.Second)
				continue
			}
			return nil, dialErr
		}

		return wsConn, nil
	}

	return nil, errors.New("连接失败，已达最大重试次数")
}

// 旧的 SOCKS5/HTTP 代理服务器代码已移除，替换为 TUN 模式（见 tun.go）
