package main

import (
	"embed"
	"github.com/wailsapp/wails/v3/pkg/events"
	"log"
	"os"
	"runtime"

	"github.com/marcsauter/single"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var iconData []byte

//go:embed build/darwin/appicon.png
var macIconData []byte

var (
	mainApp    *application.App
	mainWindow *application.WebviewWindow
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--unregister-helper" {
		if err := unregisterPlatformHelper(); err != nil {
			log.Print(err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--register-helper" {
		if err := (&VPNService{}).ensureServiceIsRunning(); err != nil {
			log.Print(err)
			os.Exit(1)
		}
		return
	}
	s := single.New("aes128-app-instance")
	if err := s.CheckLock(); err != nil {
		if err == single.ErrAlreadyRunning {
			return
		}
		log.Fatalf("failed to check for single instance: %v", err)
	}
	defer s.Unlock()

	vpnService := NewVPNService()

	defer vpnService.Shutdown()

	appIcon := iconData
	if runtime.GOOS == "darwin" {
		appIcon = macIconData
	}
	app := application.New(application.Options{
		Name:        "AES128 VPN",
		Icon:        appIcon,
		Description: "AES128 VPN Client",
		OnShutdown:  vpnService.Shutdown,
		Services: []application.Service{
			application.NewService(vpnService),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})

	mainApp = app

	mainWindow = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "AES128 VPN",
		Width:            1000,
		Height:           600,
		MinWidth:         1000,
		MinHeight:        600,
		MaxWidth:         1000,
		MaxHeight:        600,
		DisableResize:    true,
		Frameless:        runtime.GOOS != "darwin",
		Hidden:           false,
		BackgroundColour: application.NewRGB(10, 10, 10),
		Windows: application.WindowsWindow{
			Theme: application.SystemDefault,
		},
		Mac: application.MacWindow{
			TitleBar: application.MacTitleBarHidden,
		},
		MinimiseButtonState: application.ButtonHidden,
		MaximiseButtonState: application.ButtonHidden,
		CloseButtonState:    application.ButtonHidden,
		URL:                 "/",
	})

	if runtime.GOOS == "darwin" {
		mainWindow.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) { mainWindow.Hide(); e.Cancel() })
	}
	setupSystemTray(app)

	if err := app.Run(); err != nil {
		log.Printf("application stopped with an error: %v", err)
	}
}

func setupSystemTray(app *application.App) {
	tray := app.SystemTray.New()

	tray.SetIcon(trayIconDisconnected)
	tray.SetTooltip("AES128 VPN - Disconnected")

	trayMenu := app.NewMenu()

	connectItem := trayMenu.Add("Connect")
	connectItem.OnClick(func(ctx *application.Context) {
		app.Event.Emit("tray:toggle_connect", "connect")
	})

	disconnectItem := trayMenu.Add("Disconnect")
	disconnectItem.SetHidden(true)
	disconnectItem.OnClick(func(ctx *application.Context) {
		app.Event.Emit("tray:toggle_connect", "disconnect")
	})

	trayMenu.AddSeparator()

	showItem := trayMenu.Add("Show Window")
	showItem.OnClick(func(ctx *application.Context) {
		if mainWindow != nil {
			mainWindow.Show()
			mainWindow.Focus()
		}
	})

	trayMenu.AddSeparator()

	exitItem := trayMenu.Add("Exit")
	exitItem.OnClick(func(ctx *application.Context) {
		app.Quit()
	})

	tray.SetMenu(trayMenu)

	app.Event.On("app:status", func(event *application.CustomEvent) {
		if status, ok := event.Data.(string); ok {
			if status == "connected" {
				connectItem.SetHidden(true)
				disconnectItem.SetHidden(false)
				tray.SetIcon(trayIconConnected)
				tray.SetTooltip("AES128 VPN - Connected")
			} else {
				connectItem.SetHidden(false)
				disconnectItem.SetHidden(true)
				tray.SetIcon(trayIconDisconnected)
				tray.SetTooltip("AES128 VPN - Disconnected")
			}
		}
	})

	tray.OnClick(func() {
		if mainWindow != nil {
			mainWindow.Show()
			mainWindow.Focus()
		}
	})
}
