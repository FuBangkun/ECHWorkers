//go:build windows

package main

import (
	"fmt"
	"log"
	"os/exec"
	"sync"
	"syscall"
)

var (
	origGateway   string
	origGatewayMu sync.Mutex
)

// runCmd 静默执行 Windows 命令（隐藏控制台窗口），忽略输出。
func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()
}

// runCmdOutput 静默执行 Windows 命令，返回合并后的 stdout+stderr。
func runCmdOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runCmdStdout 静默执行 Windows 命令，仅返回 stdout。
func runCmdStdout(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Output()
}

// configureTUN 给 TUN 网卡配置 IP 地址和路由。
func configureTUN(tunName, serverIP string) error {
	// 1. 保存原默认网关（用于退出时恢复）
	origGatewayMu.Lock()
	origGateway = getOriginalGateway()
	origGatewayMu.Unlock()
	log.Printf("[TUN] 原默认网关: %s", origGateway)

	// 2. 配置 IPv4 (不带网关参数，避免冲突)
	if out, err := runCmdOutput("netsh", "interface", "ipv4", "set", "address", tunName, "static", "10.0.0.2", "255.255.255.0"); err != nil {
		return fmt.Errorf("配置 IPv4 失败: %w\n%s", err, out)
	}

	// 3. 关闭 DAD (重复地址检测)，解决 "10.0.0.2(试验)" 状态
	runCmd("netsh", "interface", "ipv4", "set", "interface", tunName, "dadtransmits=0", "store=active")
	log.Printf("[TUN] 已配置 IP: 10.0.0.2/24 (已跳过 DAD 检测)")

	// 4. 设置 IPv4 DNS
	runCmd("netsh", "interface", "ipv4", "set", "dns", tunName, "static", "1.1.1.1")

	// 5. 服务器直连路由 (IPv4)
	if serverIP != "" && origGateway != "" {
		if out, err := runCmdOutput("route", "add", serverIP, "mask", "255.255.255.255", origGateway, "metric", "1"); err != nil {
			log.Printf("[TUN] 警告: 服务器直连路由添加失败: %s", out)
		} else {
			log.Printf("[TUN] 服务器 %s 直连路由: %s", serverIP, origGateway)
		}
	}

	// 清理旧的错误路由
	runCmd("route", "delete", "0.0.0.0", "mask", "0.0.0.0", "10.0.0.2")

	// 6. 添加 IPv4 全局默认路由 (使用 /1 拆分路由，避免与物理网卡打架)
	runCmd("netsh", "interface", "ipv4", "add", "route", "0.0.0.0/1", tunName, "10.0.0.1", "metric=1")
	runCmd("netsh", "interface", "ipv4", "add", "route", "128.0.0.0/1", tunName, "10.0.0.1", "metric=1")
	log.Printf("[TUN] 已接管 IPv4 全局流量")

	// 7. 劫持 IPv6 (使用 /1 拆分路由)
	runCmd("netsh", "interface", "ipv6", "add", "route", "::/1", tunName, "metric=1")
	runCmd("netsh", "interface", "ipv6", "add", "route", "8000::/1", tunName, "metric=1")
	log.Printf("[TUN] 已接管 IPv6 全局流量 (防止流量绕过代理)")

	return nil
}

// cleanupTUN 恢复路由和 IP 配置，确保原网关不丢失。
func cleanupTUN(tunName string) {
	// 1. 删除全局路由
	runCmd("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", tunName)
	runCmd("netsh", "interface", "ipv6", "delete", "route", "::/1", tunName)

	// 2. 删除服务器直连路由
	if serverIP != "" {
		runCmd("route", "delete", serverIP)
	}

	// 3. 恢复网卡为 DHCP 模式
	runCmd("netsh", "interface", "ipv4", "set", "address", tunName, "dhcp")
	runCmd("netsh", "interface", "ipv4", "set", "dns", tunName, "dhcp")
	runCmd("netsh", "interface", "ipv6", "set", "dns", tunName, "dhcp")

	// 4. 安全兜底：如果原网关路由丢失，恢复它
	origGatewayMu.Lock()
	gw := origGateway
	origGatewayMu.Unlock()
	if gw != "" {
		currentGW := getOriginalGateway()
		if currentGW == "" || currentGW == "0.0.0.0" {
			runCmd("route", "add", "0.0.0.0", "mask", "0.0.0.0", gw)
		}
	}

	log.Printf("[TUN] 路由和 IP 已清理")
}

// getOriginalGateway 获取当前默认网关。
func getOriginalGateway() string {
	out, err := runCmdStdout("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.RouteMetric -gt 0} | Sort-Object RouteMetric | Select-Object -First 1).NextHop`)
	if err != nil {
		return ""
	}
	return trimString(string(out))
}

// trimString 去除字符串末尾的换行符、回车符和空格。
func trimString(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
