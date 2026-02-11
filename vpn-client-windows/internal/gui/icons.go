package gui

import (
	"bytes"
	_ "embed"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"

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

// createDotBitmap создаёт растровый кружок заданного цвета (size×size с антиалиасингом).
func createDotBitmap(size int, c color.RGBA) *walk.Bitmap {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	center := float64(size) / 2
	radius := center - 1.0

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) + 0.5 - center
			dy := float64(y) + 0.5 - center
			dist := math.Sqrt(dx*dx + dy*dy)
			if dist <= radius-0.5 {
				img.SetRGBA(x, y, c)
			} else if dist <= radius+0.5 {
				// Антиалиасинг на границе
				alpha := uint8(float64(c.A) * (radius + 0.5 - dist))
				img.SetRGBA(x, y, color.RGBA{c.R, c.G, c.B, alpha})
			}
		}
	}

	bmp, err := walk.NewBitmapFromImage(img)
	if err != nil {
		log.Printf("[GUI] Ошибка создания bitmap точки: %v", err)
		return nil
	}
	return bmp
}

// makeDotBitmaps создаёт набор цветных точек для индикаторов.
func makeDotBitmaps() (red, yellow, green, gray *walk.Bitmap) {
	const sz = 10
	red = createDotBitmap(sz, color.RGBA{200, 0, 0, 255})
	yellow = createDotBitmap(sz, color.RGBA{200, 170, 0, 255})
	green = createDotBitmap(sz, color.RGBA{0, 150, 0, 255})
	gray = createDotBitmap(sz, color.RGBA{160, 160, 160, 255})
	return
}
