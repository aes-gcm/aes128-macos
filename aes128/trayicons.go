package main

import _ "embed"

//go:embed build/tray_disconnected.png
var trayIconDisconnected []byte

//go:embed build/tray_connected.png
var trayIconConnected []byte
