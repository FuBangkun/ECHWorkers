package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/wailsapp/wails/v3/pkg/application"
)

type WorkerService struct {
	app           *application.App
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	trayProxyMenu *application.MenuItem
}

func (s *WorkerService) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cancel != nil
}

func (s *WorkerService) updateTrayMenuText(text string) {
	if s.trayProxyMenu != nil {
		s.trayProxyMenu.SetLabel(text)
	}
}

func (s *WorkerService) StartWorker(server, listen, token, ip, dns, ech, routingMode string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		return "进程已经在运行"
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.cancel = cancel

	s.updateTrayMenuText("停止代理")

	logChannel := make(chan string, 100)
	go func() {
		for logLine := range logChannel {
			s.app.Event.Emit("log-output", logLine)
		}
	}()

	go func() {
		logChannel <- "[系统] 正在初始化网络核心...\n"

		err := StartProxy(ctx, server, listen, token, ip, dns, ech, routingMode, logChannel)
		if err != nil {
			logChannel <- fmt.Sprintf("[错误] 核心启动失败: %v\n", err)
			s.mu.Lock()
			s.cancel = nil
			s.mu.Unlock()
			close(logChannel)
			s.app.Event.Emit("process-finished", "")
			return
		}

		<-ctx.Done()

		logChannel <- "[系统] 核心服务已收到停止信号，正在退出...\n"

		s.mu.Lock()
		s.cancel = nil
		s.mu.Unlock()

		s.updateTrayMenuText("启动代理")

		close(logChannel)
		s.app.Event.Emit("process-finished", "")
	}()

	return ""
}

func (s *WorkerService) StopWorker() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
		s.updateTrayMenuText("启动代理")
	}
}

func (s *WorkerService) SetSystemProxy(enable bool, listen, routingMode string) string {
	switch runtime.GOOS {
	case "windows":
		return s.setWindowsProxy(enable, listen)
	case "darwin":
		return s.setMacProxy(enable, listen)
	default:
		return "当前系统暂不支持自动设置代理"
	}
}

func (s *WorkerService) setWindowsProxy(enable bool, listen string) string {
	var cmd *exec.Cmd
	regPath := `HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

	if enable {
		proxyServer := listen
		if !strings.Contains(listen, ":") {
			proxyServer = "127.0.0.1:" + listen
		}
		bypass := "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

		script := fmt.Sprintf(
			`Set-ItemProperty -Path "%s" -Name ProxyEnable -Value 1; `+
				`Set-ItemProperty -Path "%s" -Name ProxyServer -Value "%s"; `+
				`Set-ItemProperty -Path "%s" -Name ProxyOverride -Value "%s"`,
			regPath, regPath, proxyServer, regPath, bypass,
		)
		cmd = exec.Command("powershell", "-Command", script)
	} else {
		script := fmt.Sprintf(`Set-ItemProperty -Path "%s" -Name ProxyEnable -Value 0`, regPath)
		cmd = exec.Command("powershell", "-Command", script)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}

	if err := cmd.Run(); err != nil {
		return fmt.Sprintf("修改注册表失败: %v", err)
	}

	flushCmd := exec.Command("cmd", "/c", "ipconfig /flushdns")
	flushCmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	flushCmd.Run()
	return ""
}

func (s *WorkerService) setMacProxy(enable bool, listen string) string {
	host := "127.0.0.1"
	port := listen
	if strings.Contains(listen, ":") {
		parts := strings.Split(listen, ":")
		host = parts[0]
		port = parts[1]
	}
	service := "Wi-Fi"

	if enable {
		exec.Command("networksetup", "-setsocksfirewallproxy", service, host, port).Run()
		exec.Command("networksetup", "-setsocksfirewallproxystate", service, "on").Run()
	} else {
		exec.Command("networksetup", "-setsocksfirewallproxystate", service, "off").Run()
	}
	return ""
}
