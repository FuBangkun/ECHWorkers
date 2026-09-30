//go:build darwin

package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
)

// macOS 上的 TUN 配置：
//   - utun 是点对点接口，ifconfig 需要同时给出本机地址和对端地址；
//   - 使用 /1 拆分路由接管全局流量（0.0.0.0/1 + 128.0.0.0/1），不覆盖原默认路由；
//   - 关键防死循环手段：给 worker 服务器 IP 添加经原网关的 /32 直连路由
//     （客户端出站绑定物理 IP 只保证源地址正确，路由仍按目的前缀匹配，
//     没有这条直连路由，代理自身的出站流量会被 /1 路由吸回 TUN 形成回环）；
//   - utun 接口在进程退出（fd 关闭）时由内核自动销毁并连带删除其路由。
var (
	origGateway   string
	origGatewayMu sync.Mutex
)

const (
	darwinTunIPv4 = "10.0.0.2" // TUN 本机地址
	darwinTunGW4  = "10.0.0.1" // TUN 对端地址（作 IPv4 路由网关）
	darwinTunIPv6 = "fdfd::2"  // TUN 本机 IPv6
	darwinTunGW6  = "fdfd::1"  // TUN 对端 IPv6（作 IPv6 路由网关）
)

// tunPlatformDeviceName 归一化设备名。darwin 的 utun 驱动只接受
// "utun"（自动分配）或 "utunN" 两种名字；前端传入的其他名字一律
// 改用自动分配，真实名字稍后通过 tunDev.Name() 取回。
func tunPlatformDeviceName(name string) string {
	if name == "utun" {
		return name
	}
	var n int
	if _, err := fmt.Sscanf(name, "utun%d", &n); err == nil && n >= 0 {
		return name
	}
	log.Printf("[TUN] 设备名 %q 不符合 macOS utun 命名规则，改为自动分配", name)
	return "utun"
}

// configureTUN 给 TUN 网卡配置 IP 地址和路由。
func configureTUN(tunName, serverIP string) error {
	// 1. 保存原默认网关（用于退出时恢复）
	origGatewayMu.Lock()
	origGateway = getOriginalGateway()
	origGatewayMu.Unlock()
	log.Printf("[TUN] 原默认网关: %s", origGateway)

	// 2. 配置 IPv4 地址（点对点：本机 + 对端）与 MTU
	if out, err := runCmdOutput("ifconfig", tunName, darwinTunIPv4, darwinTunGW4, "mtu", "1500", "up"); err != nil {
		return fmt.Errorf("配置 IPv4 地址失败: %w\n%s", err, out)
	}
	// 3. 配置 IPv6 地址
	if out, err := runCmdOutput("ifconfig", tunName, "inet6", darwinTunIPv6, darwinTunGW6, "up"); err != nil {
		log.Printf("[TUN] 警告: 配置 IPv6 地址失败（IPv6 流量将不被接管）: %s", out)
	}
	log.Printf("[TUN] 已配置地址: %s <-> %s, %s <-> %s", darwinTunIPv4, darwinTunGW4, darwinTunIPv6, darwinTunGW6)

	// 4. 服务器直连路由（防止代理出站流量被 /1 路由吸回 TUN）
	if serverIP != "" && origGateway != "" {
		if out, err := runCmdOutput("route", "-n", "add", "-host", serverIP, origGateway); err != nil {
			log.Printf("[TUN] 警告: 服务器直连路由添加失败: %s", out)
		} else {
			log.Printf("[TUN] 服务器 %s 直连路由: 经 %s", serverIP, origGateway)
		}
	}

	// 5. /1 拆分路由接管 IPv4 全局流量
	if out, err := runCmdOutput("route", "-n", "add", "-net", "0.0.0.0/1", darwinTunGW4); err != nil {
		return fmt.Errorf("接管 IPv4 路由失败: %w\n%s", err, out)
	}
	runCmd("route", "-n", "add", "-net", "128.0.0.0/1", darwinTunGW4)
	log.Printf("[TUN] 已接管 IPv4 全局流量")

	// 6. /1 拆分路由接管 IPv6 全局流量
	runCmd("route", "-n", "add", "-inet6", "::/1", darwinTunGW6)
	runCmd("route", "-n", "add", "-inet6", "8000::/1", darwinTunGW6)
	log.Printf("[TUN] 已接管 IPv6 全局流量 (防止流量绕过代理)")

	return nil
}

// cleanupTUN 删除接管路由；utun 接口随 fd 关闭由内核自动销毁，
// 其点对点地址无需手工清除。
func cleanupTUN(tunName, serverIP string) {
	runCmd("route", "-n", "delete", "-net", "0.0.0.0/1", darwinTunGW4)
	runCmd("route", "-n", "delete", "-net", "128.0.0.0/1", darwinTunGW4)
	runCmd("route", "-n", "delete", "-inet6", "::/1", darwinTunGW6)
	runCmd("route", "-n", "delete", "-inet6", "8000::/1", darwinTunGW6)

	if serverIP != "" {
		runCmd("route", "-n", "delete", "-host", serverIP)
	}

	// 安全兜底：如果原默认网关路由丢失，恢复它
	origGatewayMu.Lock()
	gw := origGateway
	origGatewayMu.Unlock()
	if gw != "" && getOriginalGateway() == "" {
		runCmd("route", "-n", "add", "default", gw)
		log.Printf("[TUN] 已恢复原默认网关: %s", gw)
	}

	log.Printf("[TUN] 路由已清理")
}

// getOriginalGateway 通过 route get default 获取当前默认网关。
func getOriginalGateway() string {
	out, err := runCmdStdout("route", "-n", "get", "default")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
	}
	return ""
}
