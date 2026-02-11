package gui

import (
	"bytes"
	_ "embed"
	"image/png"
	"log"

	"github.com/lxn/walk"
)

// Встроенные PNG-иконки, сгенерированные из assets/*.svg утилитой cmd/icongen.

//go:embed icondata/disconnected.png
var disconnectedPNG []byte

//go:embed icondata/connecting.png
var connectingPNG []byte

//go:embed icondata/connected.png
var connectedPNG []byte

//go:embed icondata/logo.png
var logoPNG []byte

// makeShieldIcons загружает иконки трея из встроенных PNG.
//
//	disconnected — assets/1.svg (серый щит, #919191)
//	connecting   — assets/2.svg (жёлтый щит, #ffbb00)
//	connected    — assets/3.svg (зелёный щит с галочкой, #1a9617)
func makeShieldIcons() (disconnected, connecting, connected *walk.Icon) {
	disconnected = iconFromPNG(disconnectedPNG)
	connecting = iconFromPNG(connectingPNG)
	connected = iconFromPNG(connectedPNG)
	return
}

// loadAppIcon загружает иконку приложения из встроенного PNG (assets/logo.svg).
func loadAppIcon() *walk.Icon {
	return iconFromPNG(logoPNG)
}

func iconFromPNG(data []byte) *walk.Icon {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		log.Printf("[GUI] Ошибка декодирования иконки: %v", err)
		return nil
	}
	icon, err := walk.NewIconFromImage(img)
	if err != nil {
		log.Printf("[GUI] Ошибка создания иконки: %v", err)
		return nil
	}
	return icon
}
