package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed chn_ip.txt chn_ip_v6.txt
var ipData embed.FS

func main() {
	workerService := &WorkerService{}
	var mainWindow *application.WebviewWindow
	var proxyMenuItem *application.MenuItem

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

	mainWindow = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  "ECH Workers",
		Width:  1000,
		Height: 618,
		URL:    "/",
	})

	trayMenu := app.NewMenu()

	trayMenu.Add("显示窗口").OnClick(func(ctx *application.Context) {
		mainWindow.Show()
		mainWindow.Focus()
	})
	trayMenu.AddSeparator()

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

	err := app.Run()
	if err != nil {
		log.Fatal(err)
	}
}
