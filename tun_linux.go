//go:build linux

package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
)

// Linux 上的 TUN 配置：
//   - 使用 ip 命令配置链路与地址，/1 拆分路由（0.0.0.0/1 + 128.0.0.0/1）接管
//     全局流量，不覆盖原默认路由；用 replace 而非 add，保证幂等；
//   - 关键防死循环手段：给 worker 服务器 IP 添加经原网关的 /32 直连路由
//     （客户端出站绑定物理 IP 只保证源地址正确，路由仍按目的前缀匹配，
//     没有这条直连路由，代理自身的出站流量会被 /1 路由吸回 TUN 形成回环）；
//   - TUN 接口随 fd 关闭由内核自动销毁。
var (
	origGateway    string
	origGatewayDev string // 原默认路由的出接口（恢复默认路由时需要）
	origGatewayMu  sync.Mutex
)

const (
	linuxTunIPv4  = "10.0.0.2/24"
	linuxTunIPv6  = "fdfd::2/126"
	linuxVnetHdr  = 10 // virtio_net_hdr 长度（与 wireguard/tun offload_linux.go 一致）
	ifnamsizLimit = 15 // Linux 接口名上限（IFNAMSIZ-1，不含结尾 NUL）
)

// tunPlatformDeviceName 归一化设备名：Linux 接口名不能超过 15 字节。
func tunPlatformDeviceName(name string) string {
	if name == "" {
		return "echworkers"
	}
	if len(name) > ifnamsizLimit {
		log.Printf("[TUN] 设备名 %q 超过 Linux 15 字节上限，截断为 %q", name, name[:ifnamsizLimit])
		name = name[:ifnamsizLimit]
	}
	return name
}

// configureTUN 给 TUN 网卡配置 IP 地址和路由。
func configureTUN(tunName, serverIP string) error {
	// 1. 保存原默认网关（用于退出时恢复）
	origGatewayMu.Lock()
	origGateway, origGatewayDev = getOriginalGateway()
	origGatewayMu.Unlock()
	log.Printf("[TUN] 原默认网关: %s (dev %s)", origGateway, origGatewayDev)

	// 2. 启用链路
	if out, err := runCmdOutput("ip", "link", "set", "dev", tunName, "mtu", "1500", "up"); err != nil {
		return fmt.Errorf("启用 TUN 链路失败: %w\n%s", err, out)
	}

	// 3. 配置地址（存在残留时 add 会失败，属正常，忽略）
	runCmd("ip", "addr", "add", linuxTunIPv4, "dev", tunName)
	runCmd("ip", "-6", "addr", "add", linuxTunIPv6, "dev", tunName)
	log.Printf("[TUN] 已配置地址: %s, %s", linuxTunIPv4, linuxTunIPv6)

	// 4. 服务器直连路由（防止代理出站流量被 /1 路由吸回 TUN）
	if serverIP != "" {
		args := []string{"route", "replace", serverIP + "/32"}
		if origGateway != "" {
			args = append(args, "via", origGateway)
		}
		if origGatewayDev != "" {
			args = append(args, "dev", origGatewayDev)
		}
		if out, err := runCmdOutput(args[0], args[1:]...); err != nil {
			log.Printf("[TUN] 警告: 服务器直连路由添加失败: %s", out)
		} else {
			log.Printf("[TUN] 服务器 %s 直连路由: via %s dev %s", serverIP, origGateway, origGatewayDev)
		}
	}

	// 5. /1 拆分路由接管 IPv4 全局流量
	if out, err := runCmdOutput("ip", "route", "replace", "0.0.0.0/1", "dev", tunName); err != nil {
		return fmt.Errorf("接管 IPv4 路由失败: %w\n%s", err, out)
	}
	runCmd("ip", "route", "replace", "128.0.0.0/1", "dev", tunName)
	log.Printf("[TUN] 已接管 IPv4 全局流量")

	// 6. /1 拆分路由接管 IPv6 全局流量
	runCmd("ip", "-6", "route", "replace", "::/1", "dev", tunName)
	runCmd("ip", "-6", "route", "replace", "8000::/1", "dev", tunName)
	log.Printf("[TUN] 已接管 IPv6 全局流量 (防止流量绕过代理)")

	return nil
}

// cleanupTUN 删除接管路由；TUN 接口随 fd 关闭由内核自动销毁，
// 其地址无需手工清除。
func cleanupTUN(tunName, serverIP string) {
	runCmd("ip", "route", "del", "0.0.0.0/1")
	runCmd("ip", "route", "del", "128.0.0.0/1")
	runCmd("ip", "-6", "route", "del", "::/1")
	runCmd("ip", "-6", "route", "del", "8000::/1")

	if serverIP != "" {
		runCmd("ip", "route", "del", serverIP+"/32")
	}

	// 安全兜底：如果原默认网关路由丢失，恢复它
	origGatewayMu.Lock()
	gw, dev := origGateway, origGatewayDev
	origGatewayMu.Unlock()
	if gw != "" {
		curGW, _ := getOriginalGateway()
		if curGW == "" {
			args := []string{"route", "add", "default", "via", gw}
			if dev != "" {
				args = append(args, "dev", dev)
			}
			runCmd(args[0], args[1:]...)
			log.Printf("[TUN] 已恢复原默认网关: via %s dev %s", gw, dev)
		}
	}

	log.Printf("[TUN] 路由已清理")
}

// getOriginalGateway 从 "ip route show default" 解析当前默认网关与出接口。
func getOriginalGateway() (gw, dev string) {
	out, err := runCmdStdout("ip", "route", "show", "default")
	if err != nil {
		return "", ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		switch f {
		case "via":
			if i+1 < len(fields) {
				gw = fields[i+1]
			}
		case "dev":
			if i+1 < len(fields) {
				dev = fields[i+1]
			}
		}
	}
	return gw, dev
}
