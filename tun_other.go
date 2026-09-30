//go:build !windows && !darwin && !linux

package main

// 其余平台（freebsd/js 等）暂不支持透明代理：仅保证可编译。
// 透明代理需要平台级的接口配置与路由接管，参见 tun_windows.go /
// tun_darwin.go / tun_linux.go。

func configureTUN(tunName, serverIP string) error {
	return nil
}

func cleanupTUN(tunName, serverIP string) {}

func getOriginalGateway() string {
	return ""
}

func tunPlatformDeviceName(name string) string {
	return name
}

func trimString(s string) string {
	return s
}
