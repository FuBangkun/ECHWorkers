package main

// netutil.go —— 纯网络工具函数：IP/UDP 校验和计算。
// 无状态、无 I/O，可独立单测。

import (
	"gvisor.dev/gvisor/pkg/tcpip"
)

// checksumIP 计算 IPv4 头校验和。
func checksumIP(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i == 10 {
			continue // 跳过校验和字段
		}
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// checksumUDP 计算 UDP 校验和（含伪头部）。
func checksumUDP(srcAddr, dstAddr tcpip.Address, udpHeader, payload []byte) uint16 {
	var sum uint32

	// 伪头部：源 IP
	for i := 0; i < len(srcAddr.AsSlice()); i += 2 {
		sum += uint32(srcAddr.AsSlice()[i])<<8 | uint32(srcAddr.AsSlice()[i+1])
	}
	// 伪头部：目标 IP
	for i := 0; i < len(dstAddr.AsSlice()); i += 2 {
		sum += uint32(dstAddr.AsSlice()[i])<<8 | uint32(dstAddr.AsSlice()[i+1])
	}
	// 伪头部：协议号 (UDP=17)
	sum += uint32(17)
	// 伪头部：UDP 长度
	sum += uint32(len(udpHeader) + len(payload))

	// UDP 头部
	for i := 0; i < len(udpHeader); i += 2 {
		sum += uint32(udpHeader[i])<<8 | uint32(udpHeader[i+1])
	}
	// UDP 数据
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(payload[i])<<8 | uint32(payload[i+1])
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	result := ^uint16(sum)
	if result == 0 {
		// UDP 校验和为 0 时用 0xFFFF 表示（RFC 768）
		return 0xFFFF
	}
	return result
}
