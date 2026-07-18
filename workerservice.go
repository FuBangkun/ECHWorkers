package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// WorkerService 是 Wails 服务层的核心结构体，负责代理进程的生命周期管理。
// 通过 Wails 的 Service 机制与前端通信，控制代理的启动和停止。
type WorkerService struct {
	app           *application.App
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	trayProxyMenu *application.MenuItem // 系统托盘中的代理启停菜单项
}

// IsRunning 返回代理是否正在运行。
func (s *WorkerService) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cancel != nil
}

// updateTrayMenuText 更新系统托盘菜单中代理相关项的显示文本。
func (s *WorkerService) updateTrayMenuText(text string) {
	if s.trayProxyMenu != nil {
		s.trayProxyMenu.SetLabel(text)
	}
}

// StartWorker 启动代理核心服务。通过 Wails 前端调用，传入用户配置的各种参数。
// 返回空字符串表示成功启动，否则返回错误信息。
func (s *WorkerService) StartWorker(server, tunName, token, ip, dns, ech, routingMode string) string {
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
		logChannel <- "[系统] 正在初始化 TUN 网络核心 (请确保拥有管理员/Root权限)...\n"

		err := StartProxy(ctx, server, tunName, token, ip, dns, ech, routingMode, logChannel)
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

		log.SetOutput(os.Stderr)
		close(logChannel)
		s.app.Event.Emit("process-finished", "")
	}()

	return ""
}

// StopWorker 停止正在运行的代理核心服务，并更新托盘菜单状态。
func (s *WorkerService) StopWorker() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
		s.updateTrayMenuText("启动代理")
	}
}
