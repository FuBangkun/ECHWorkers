// ECHWorkers 是一个基于 Wails v3 的桌面代理工具，通过 TUN 虚拟网卡 +
// gVisor 用户态协议栈实现透明代理，并利用 ECH (Encrypted Client Hello) 技术
// 隐藏 TLS 握手中的 SNI 信息，提升网络访问的隐匿性。
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS // 前端静态资源（Wails 构建产物）

//go:embed chn_ip.txt chn_ip_v6.txt
var ipData embed.FS // 中国 IP 地址段数据（用于分流）

func main() {
	workerService := &WorkerService{}
	var mainWindow *application.WebviewWindow
	var proxyMenuItem *application.MenuItem

	// 初始化 Wails 应用
	app := application.New(application.Options{
		Name:        "ech-workers",
		Description: "ECHWorkers",
		Services: []application.Service{
			application.NewService(workerService),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "com.fubangkun.echworkers",
			OnSecondInstanceLaunch: func(data application.SecondInstanceData) {
				if mainWindow != nil {
					mainWindow.Restore()
					mainWindow.Focus()
				}
			},
		},
	})

	workerService.app = app

	// 创建主窗口
	mainWindow = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  "ECH Workers",
		Width:  1000,
		Height: 618,
		URL:    "/",
	})

	// 构建系统托盘菜单
	trayMenu := app.NewMenu()

	trayMenu.Add("显示窗口").OnClick(func(ctx *application.Context) {
		mainWindow.Show()
		mainWindow.Focus()
	})
	trayMenu.AddSeparator()

	// 代理启停菜单项
	proxyMenuItem = trayMenu.Add("启动代理")
	proxyMenuItem.OnClick(func(ctx *application.Context) {
		if workerService.IsRunning() {
			workerService.StopWorker()
		} else {
			app.Event.Emit("tray-request-start", "")
		}
	})

	trayMenu.AddSeparator()
	trayMenu.Add("退出").OnClick(func(ctx *application.Context) {
		workerService.StopWorker()
		app.Quit()
	})

	// 注册系统托盘
	tray := app.SystemTray.New()
	tray.SetMenu(trayMenu)

	tray.OnClick(func() {
		if mainWindow.IsVisible() {
			mainWindow.Hide()
		} else {
			mainWindow.Show()
			mainWindow.Focus()
		}
	})

	workerService.trayProxyMenu = proxyMenuItem

	// 启动应用主循环
	err := app.Run()
	if err != nil {
		log.Fatal(err)
	}
}
