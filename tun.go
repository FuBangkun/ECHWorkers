package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	tunMTU = 1500
	nicID  = 1
)

// tunOffset 返回平台相关的 TUN 数据包偏移量。
// wireguard/tun 各平台对 Read/Write 的 offset 有不同硬性要求：
//   - windows: wintun 需要 4 字节地址族前缀空间，由调用方写入 AF 标记；
//   - darwin:  utun 的 Read/Write 要求 offset ≥ 4（模块在 [offset-4:offset]
//     自行写入地址族标记，包体从 offset 开始）；
//   - linux:   CreateTUN 固定启用 IFF_VNET_HDR，Write 会在 [offset-10:offset]
//     预留并填充 virtio_net_hdr（10 字节），因此必须 offset ≥ 10。
func tunOffset() int {
	switch runtime.GOOS {
	case "windows", "darwin":
		return 4
	case "linux":
		return 10
	default:
		return 0
	}
}

// runTUNProxy 创建 TUN 虚拟网卡，启动 gVisor 用户态协议栈，拦截并转发 TCP 流量。
func runTUNProxy(ctx context.Context, rt *proxyRuntime, tunName string) error {
	offset := tunOffset()

	// 获取本机物理网卡 IP，用于绑定出站连接，防止路由死循环
	if conn, err := net.Dial("udp", "8.8.8.8:53"); err == nil {
		rt.localIP = conn.LocalAddr().(*net.UDPAddr).IP
		conn.Close()
		log.Printf("[TUN] 已获取本机物理网卡 IP: %s (用于防死循环)", rt.localIP.String())
	} else {
		log.Printf("[TUN] 警告: 获取本机物理网卡 IP 失败: %v", err)
	}

	// 1. 提取 Wintun DLL（Windows 需要）
	if err := extractWintunDLL(); err != nil {
		return fmt.Errorf("提取 Wintun DLL 失败: %w", err)
	}

	// 2. 创建 TUN 设备（各平台对设备名有不同约束，见各平台实现）
	tunName = tunPlatformDeviceName(tunName)
	tunDev, err := tun.CreateTUN(tunName, tunMTU)
	if err != nil {
		return fmt.Errorf("创建 TUN 设备失败: %w", err)
	}
	defer tunDev.Close()

	realName, _ := tunDev.Name()
	log.Printf("[TUN] 虚拟网卡已创建: %s, MTU: %d", realName, tunMTU)

	// 配置 IP 和路由
	if err := configureTUN(realName, rt.cfg.ServerIP); err != nil {
		return fmt.Errorf("配置 TUN 失败: %w", err)
	}

	// 3. 创建 gVisor channel 端点
	linkEP := channel.New(512, uint32(tunMTU), "")

	// 4. 创建 gVisor 网络协议栈
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{}),
			ipv6.NewProtocolWithOptions(ipv6.Options{}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			func(s *stack.Stack) stack.TransportProtocol { return tcp.NewProtocol(s) },
			func(s *stack.Stack) stack.TransportProtocol { return udp.NewProtocol(s) },
		},
	})

	// 5. 创建虚拟网卡 NIC
	if tcpErr := s.CreateNIC(nicID, linkEP); tcpErr != nil {
		return fmt.Errorf("创建 NIC 失败: %s", tcpErr)
	}

	// === 新增：必须开启混杂模式和欺骗模式，否则 gVisor 会丢弃非本地 IP 的流量 ===
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)

	// 6. 添加协议地址（0.0.0.0/0 让所有 IPv4 包走本地投递，触发 TCP forwarder）
	addr4 := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{}).WithPrefix(),
	}
	if tcpErr := s.AddProtocolAddress(nicID, addr4, stack.AddressProperties{}); tcpErr != nil {
		return fmt.Errorf("添加 IPv4 地址失败: %s", tcpErr)
	}

	addr6 := tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom16([16]byte{}).WithPrefix(),
	}
	s.AddProtocolAddress(nicID, addr6, stack.AddressProperties{})

	// 7. 设置默认路由
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	// 8. TCP 转发器
	tcpForwarder := tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		go handleTCPForward(rt, r, id)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// 9. UDP 处理 —— DNS 走 DoH，其他 UDP 包原样转发
	s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		if id.LocalPort == 53 {
			views := pkt.AsSlices()
			var rawPacket []byte
			for _, v := range views {
				rawPacket = append(rawPacket, v...)
			}

			// 最小长度校验 (IPv4 最小 20，UDP 最小 8)
			if len(rawPacket) < 28 {
				return true
			}

			// 提取 IP 版本
			version := rawPacket[0] >> 4
			var ipHeaderLen int
			if version == 4 {
				ipHeaderLen = int((rawPacket[0] & 0x0F) * 4) // IPv4 头长度可变，通常是 20
			} else if version == 6 {
				ipHeaderLen = 40 // IPv6 固定头部 40 字节
			} else {
				return true
			}

			// 头部总长度 = IP 头 + UDP 头(8字节)
			headerLen := ipHeaderLen + 8
			if len(rawPacket) <= headerLen {
				return true // 没有 Payload
			}

			// 精确提取纯 DNS 数据！
			dnsQuery := make([]byte, len(rawPacket)-headerLen)
			copy(dnsQuery, rawPacket[headerLen:])

			// 此时的 dnsQuery 是完美纯净的 DNS 请求
			go rt.handleDNSViaDoH(tunDev, id, dnsQuery)
			return true
		}
		// 非 DNS 包不处理
		return false
	})

	// 10. TUN → gVisor
	go func() {
		// 【安全修复】将 readBuf 扩大到 65536 (64KB)，防止 Windows 巨型数据包(LSO)导致数组越界崩溃
		// 再加上平台偏移量预留（linux 需 10 字节 vnet 头空间）
		readBuf := make([]byte, offset+65536)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			bufs := [][]byte{readBuf}
			sizes := make([]int, 1)
			_, readErr := tunDev.Read(bufs, sizes, offset)
			if readErr != nil {
				// 忽略取消造成的常规读取错误
				return
			}
			n := sizes[0]
			if n == 0 {
				continue
			}

			// 【安全校验】防止越界
			if offset+n > len(readBuf) {
				continue
			}

			rawPacket := readBuf[offset : offset+n]
			if len(rawPacket) == 0 {
				continue
			}

			var proto tcpip.NetworkProtocolNumber
			switch rawPacket[0] >> 4 {
			case 4:
				proto = ipv4.ProtocolNumber
			case 6:
				proto = ipv6.ProtocolNumber
			default:
				continue
			}

			pktBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(rawPacket),
			})
			linkEP.InjectInbound(proto, pktBuf)
			pktBuf.DecRef()
		}
	}()

	// 11. gVisor → TUN
	go func() {
		for {
			pkt := linkEP.ReadContext(ctx)
			if pkt == nil {
				return
			}

			views := pkt.AsSlices()
			var totalLen int
			for _, v := range views {
				totalLen += len(v)
			}
			data := make([]byte, offset+totalLen)
			pos := offset
			for _, v := range views {
				pos += copy(data[pos:], v)
			}

			if runtime.GOOS == "windows" && totalLen > 0 {
				ver := data[offset] >> 4
				if ver == 4 {
					binary.BigEndian.PutUint32(data[:offset], 0x0800)
				} else {
					binary.BigEndian.PutUint32(data[:offset], 0x86DD)
				}
			}

			pkt.DecRef()
			bufs := [][]byte{data}
			if _, writeErr := tunDev.Write(bufs, offset); writeErr != nil {
				log.Printf("[TUN] 写入失败: %v", writeErr)
				return
			}
		}
	}()

	log.Printf("[TUN] 用户态协议栈已启动，等待流量...")
	<-ctx.Done()
	log.Printf("[TUN] 正在停止...")
	cleanupTUN(realName, rt.cfg.ServerIP)
	return nil
}

// handleTCPForward 处理 gVisor 拦截到的 TCP 连接。
func handleTCPForward(rt *proxyRuntime, r *tcp.ForwarderRequest, id stack.TransportEndpointID) {
	destIP := net.IP(id.LocalAddress.AsSlice()).String()
	destPort := id.LocalPort
	clientAddr := fmt.Sprintf("%s:%d", net.IP(id.RemoteAddress.AsSlice()), id.RemotePort)
	target := fmt.Sprintf("%s:%d", destIP, destPort)

	log.Printf("[TCP] %s -> %s", clientAddr, target)

	if rt.shouldBypassProxy(destIP) {
		log.Printf("[分流] %s -> %s (直连)", clientAddr, target)
		handleDirectTUNForward(rt, r, target, clientAddr)
	} else {
		log.Printf("[分流] %s -> %s (通过代理)", clientAddr, target)
		handleWebSocketTUNForward(rt, r, target, clientAddr)
	}
}

// handleDirectTUNForward 直连转发（绕过代理）。
func handleDirectTUNForward(rt *proxyRuntime, r *tcp.ForwarderRequest, target, clientAddr string) {
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		log.Printf("[TCP] 创建端点失败: %s", tcpErr)
		return
	}
	defer ep.Close()

	conn := gonet.NewTCPConn(&wq, ep)
	defer conn.Close()

	// --- 绑定物理网卡 IP，强制流量走物理网卡，防止再次进入 TUN ---
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	if rt.localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: rt.localIP, Port: 0}
	}

	remoteConn, err := dialer.Dial("tcp", target)
	if err != nil {
		log.Printf("[TCP] 直连 %s 失败: %v", target, err)
		return
	}
	defer remoteConn.Close()

	log.Printf("[TCP] %s 直连已建立: %s", clientAddr, target)

	done := make(chan bool, 2)
	go func() { io.Copy(remoteConn, conn); done <- true }()
	go func() { io.Copy(conn, remoteConn); done <- true }()
	<-done
	log.Printf("[TCP] %s 直连已断开: %s", clientAddr, target)
}

// handleWebSocketTUNForward 通过 mux 会话转发 TCP 连接。
func handleWebSocketTUNForward(rt *proxyRuntime, r *tcp.ForwarderRequest, target, clientAddr string) {
	// 先创建端点：后续任何失败路径都会经 defer 关闭端点，
	// 客户端立即收到 RST，而不是干等到自身超时。
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		log.Printf("[TCP] 创建端点失败: %s", tcpErr)
		return
	}
	defer ep.Close()

	conn := gonet.NewTCPConn(&wq, ep)
	defer conn.Close()

	// 在 mux 会话池上打开流：多条流复用同一条 ECH+TLS+WS 长连接，
	// 新连接零握手开销；会话失效时 open 内部会自动换会话重试。
	stream, err := rt.muxPool.open(target)
	if err != nil {
		log.Printf("[TCP] 打开复用流失败: %v", err)
		return
	}
	defer stream.Close()

	log.Printf("[TCP] %s 代理已建立: %s", clientAddr, target)

	done := make(chan bool, 2)
	go func() { io.Copy(stream, conn); done <- true }()
	go func() { io.Copy(conn, stream); done <- true }()
	<-done
	log.Printf("[TCP] %s 代理已断开: %s", clientAddr, target)
}

// handleDNSViaDoH 拦截 DNS 查询（UDP 53），通过 DoH 转发，并将响应直接写入 TUN 设备。
func (rt *proxyRuntime) handleDNSViaDoH(tunDev tun.Device, id stack.TransportEndpointID, dnsQuery []byte) {
	// 先查缓存：命中直接回包（ID 已重写为本次查询的 ID），免一次 DoH 往返
	var dnsResp []byte
	cached, hit := dnsCacheLookup(dnsQuery)
	if hit {
		dnsResp = cached
	} else {
		resp, err := rt.queryDoHForProxy(dnsQuery)
		if err != nil {
			log.Printf("[DNS] DoH 查询失败: %v", err)
			return
		}
		dnsResp = resp
		dnsCacheStore(dnsQuery, dnsResp)
	}

	// 构建响应 UDP 包（交换源/目标端口）
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], id.LocalPort)
	binary.BigEndian.PutUint16(udpHeader[2:4], id.RemotePort)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(8+len(dnsResp)))
	udpChecksum := checksumUDP(id.LocalAddress, id.RemoteAddress, udpHeader, dnsResp)
	binary.BigEndian.PutUint16(udpHeader[6:8], udpChecksum)
	fullResp := append(udpHeader, dnsResp...)

	// 获取源地址长度，判断是 IPv4 还是 IPv6
	isIPv6 := len(id.LocalAddress.AsSlice()) == 16
	var respPacket []byte

	if isIPv6 {
		// ================= 构建 IPv6 响应包 =================
		ipHeaderLen := 40
		respPacket = make([]byte, ipHeaderLen+len(fullResp))

		// 0-3: Version (6), Traffic Class (0), Flow Label (0)
		binary.BigEndian.PutUint32(respPacket[0:4], 0x60000000)
		// 4-5: Payload Length
		binary.BigEndian.PutUint16(respPacket[4:6], uint16(len(fullResp)))
		// 6: Next Header (UDP = 17)
		respPacket[6] = 17
		// 7: Hop Limit (64)
		respPacket[7] = 64
		// 8-23: Source Address (原目标地址)
		copy(respPacket[8:24], id.LocalAddress.AsSlice())
		// 24-39: Destination Address (原源地址)
		copy(respPacket[24:40], id.RemoteAddress.AsSlice())

		// 拼接 Payload
		copy(respPacket[ipHeaderLen:], fullResp)
	} else {
		// ================= 构建 IPv4 响应包 =================
		ipHeaderLen := 20
		respPacket = make([]byte, ipHeaderLen+len(fullResp))

		respPacket[0] = 0x45
		respPacket[1] = 0
		binary.BigEndian.PutUint16(respPacket[2:4], uint16(len(respPacket)))
		respPacket[4] = 0
		respPacket[5] = 0
		respPacket[6] = 0x40
		respPacket[7] = 0
		respPacket[8] = 64
		respPacket[9] = 17
		copy(respPacket[12:16], id.LocalAddress.AsSlice())
		copy(respPacket[16:20], id.RemoteAddress.AsSlice())
		copy(respPacket[ipHeaderLen:], fullResp)

		ipChecksum := checksumIP(respPacket[:ipHeaderLen])
		binary.BigEndian.PutUint16(respPacket[10:12], ipChecksum)
	}

	// 直接写入 TUN 设备
	offset := tunOffset()
	data := make([]byte, offset+len(respPacket))
	if offset > 0 {
		if isIPv6 {
			binary.BigEndian.PutUint32(data[:offset], 0x86DD) // IPv6 标识
		} else {
			binary.BigEndian.PutUint32(data[:offset], 0x0800) // IPv4 标识
		}
	}
	copy(data[offset:], respPacket)

	bufs := [][]byte{data}
	if _, writeErr := tunDev.Write(bufs, offset); writeErr != nil {
		log.Printf("[DNS] 写入 TUN 失败: %v", writeErr)
	}
}
