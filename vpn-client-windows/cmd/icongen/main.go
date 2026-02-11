// Package main генерирует PNG-иконки для трея и ICO для встраивания в exe/инсталлятор.
//
// Рендерит SVG-описания щитов из assets/ (1.svg, 2.svg, 3.svg, logo.svg)
// в растровые изображения с антиалиасингом (4×4 суперсэмплинг).
//
// Запуск из каталога vpn-client-windows/:
//
//	go run ./cmd/icongen/
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
)

// ---------------------------------------------------------------------------
// Векторные примитивы
// ---------------------------------------------------------------------------

type pt struct{ x, y float64 }

// cubicBezier аппроксимирует кубическую кривую Безье n отрезками.
func cubicBezier(p0, p1, p2, p3 pt, n int) []pt {
	out := make([]pt, 0, n)
	for i := 1; i <= n; i++ {
		t := float64(i) / float64(n)
		u := 1 - t
		out = append(out, pt{
			x: u*u*u*p0.x + 3*u*u*t*p1.x + 3*u*t*t*p2.x + t*t*t*p3.x,
			y: u*u*u*p0.y + 3*u*u*t*p1.y + 3*u*t*t*p2.y + t*t*t*p3.y,
		})
	}
	return out
}

// shieldPoly возвращает контур щита (viewBox 0 0 16 16), масштабированный до size×size.
//
// SVG path из assets/1.svg:
//
//	M4.35009,13.3929 L8,16 L11.6499,13.3929
//	C13.7523,11.8912 15,9.46667 15,6.88306
//	V3 L8,0 L1,3 V6.88306
//	C1,9.46667 2.24773,11.8912 4.35009,13.3929 Z
func shieldPoly(size int) []pt {
	s := float64(size) / 16.0
	sp := func(x, y float64) pt { return pt{x * s, y * s} }

	start := sp(4.35009, 13.3929)
	b1From := sp(11.6499, 13.3929)
	b1To := sp(15, 6.88306)
	b2From := sp(1, 6.88306)

	var p []pt
	p = append(p, start)
	p = append(p, sp(8, 16))
	p = append(p, b1From)
	p = append(p, cubicBezier(b1From, sp(13.7523, 11.8912), sp(15, 9.46667), b1To, 32)...)
	p = append(p, sp(15, 3))
	p = append(p, sp(8, 0))
	p = append(p, sp(1, 3))
	p = append(p, b2From)
	p = append(p, cubicBezier(b2From, sp(1, 9.46667), sp(2.24773, 11.8912), start, 32)...)
	return p
}

// checkPoly возвращает контур галочки (viewBox 0 0 16 16), масштабированный до size×size.
//
// SVG path из assets/3.svg:
//
//	M12.2071,5.70711 L10.7929,4.29289 L7,8.08579
//	L5.20711,6.29289 L3.79289,7.70711 L7,10.9142 Z
func checkPoly(size int) []pt {
	s := float64(size) / 16.0
	return []pt{
		{12.2071 * s, 5.70711 * s},
		{10.7929 * s, 4.29289 * s},
		{7 * s, 8.08579 * s},
		{5.20711 * s, 6.29289 * s},
		{3.79289 * s, 7.70711 * s},
		{7 * s, 10.9142 * s},
	}
}

// inPoly — ray-casting тест принадлежности точки полигону.
func inPoly(px, py float64, poly []pt) bool {
	n := len(poly)
	inside := false
	j := n - 1
	for i := 0; i < n; i++ {
		if (poly[i].y > py) != (poly[j].y > py) {
			xHit := (poly[j].x-poly[i].x)*(py-poly[i].y)/(poly[j].y-poly[i].y) + poly[i].x
			if px < xHit {
				inside = !inside
			}
		}
		j = i
	}
	return inside
}

// ---------------------------------------------------------------------------
// Рендеринг
// ---------------------------------------------------------------------------

// renderShield рисует щит заданного цвета.
// withCheck=true вырезает галочку (эффект SVG fill-rule: evenodd).
func renderShield(size int, fill color.RGBA, withCheck bool) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	shield := shieldPoly(size)
	var check []pt
	if withCheck {
		check = checkPoly(size)
	}

	const ss = 4 // 4×4 суперсэмплинг для антиалиасинга
	total := ss * ss
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var hit int
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := float64(x) + (float64(sx)+0.5)/float64(ss)
					py := float64(y) + (float64(sy)+0.5)/float64(ss)
					if !inPoly(px, py, shield) {
						continue
					}
					if withCheck && inPoly(px, py, check) {
						continue // evenodd: галочка вырезается
					}
					hit++
				}
			}
			if hit > 0 {
				a := uint8(hit * 255 / total)
				img.SetRGBA(x, y, color.RGBA{fill.R, fill.G, fill.B, a})
			}
		}
	}
	return img
}

// ---------------------------------------------------------------------------
// ICO-кодировщик (PNG-in-ICO, Windows Vista+)
// ---------------------------------------------------------------------------

func writeICO(path string, sizes []int, fill color.RGBA, withCheck bool) error {
	pngs := make([][]byte, len(sizes))
	for i, sz := range sizes {
		var buf bytes.Buffer
		if err := png.Encode(&buf, renderShield(sz, fill, withCheck)); err != nil {
			return err
		}
		pngs[i] = buf.Bytes()
	}

	var out bytes.Buffer
	// Заголовок ICO
	binary.Write(&out, binary.LittleEndian, uint16(0))          // reserved
	binary.Write(&out, binary.LittleEndian, uint16(1))          // type = ICO
	binary.Write(&out, binary.LittleEndian, uint16(len(sizes))) // count

	offset := uint32(6 + 16*len(sizes))
	for i, sz := range sizes {
		w, h := byte(sz), byte(sz)
		if sz >= 256 {
			w, h = 0, 0 // 0 означает 256 в формате ICO
		}
		out.Write([]byte{w, h, 0, 0})
		binary.Write(&out, binary.LittleEndian, uint16(1))            // planes
		binary.Write(&out, binary.LittleEndian, uint16(32))           // bpp
		binary.Write(&out, binary.LittleEndian, uint32(len(pngs[i]))) // data size
		binary.Write(&out, binary.LittleEndian, offset)               // offset
		offset += uint32(len(pngs[i]))
	}
	for _, p := range pngs {
		out.Write(p)
	}
	return os.WriteFile(path, out.Bytes(), 0644)
}

// ---------------------------------------------------------------------------
// Утилиты
// ---------------------------------------------------------------------------

func savePNG(path string, img *image.RGBA) {
	f, err := os.Create(path)
	if err != nil {
		fatal("создание %s: %v", path, err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		fatal("кодирование PNG %s: %v", path, err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[icongen] ОШИБКА: "+format+"\n", args...)
	os.Exit(1)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	assetsDir := filepath.Join("..", "assets")
	dataDir := filepath.Join("internal", "gui", "icondata")

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		fatal("создание каталога icondata: %v", err)
	}

	// Цвета из SVG-файлов assets/
	grey := color.RGBA{0x91, 0x91, 0x91, 255}   // 1.svg  — отключён
	yellow := color.RGBA{0xFF, 0xBB, 0x00, 255} // 2.svg  — подключение
	green := color.RGBA{0x1A, 0x96, 0x17, 255}  // 3.svg  — подключён
	logoC := color.RGBA{0x00, 0x80, 0x02, 255}  // logo.svg

	// Иконки трея: PNG 64×64
	fmt.Print("  Иконки трея (PNG 64×64)... ")
	savePNG(filepath.Join(dataDir, "disconnected.png"), renderShield(64, grey, false))
	savePNG(filepath.Join(dataDir, "connecting.png"), renderShield(64, yellow, false))
	savePNG(filepath.Join(dataDir, "connected.png"), renderShield(64, green, true))
	savePNG(filepath.Join(dataDir, "logo.png"), renderShield(64, logoC, true))
	fmt.Println("OK")

	// ICO для exe-ресурса и инсталлятора: 16 / 32 / 48 / 256
	fmt.Print("  logo.ico (16/32/48/256)... ")
	if err := writeICO(
		filepath.Join(assetsDir, "logo.ico"),
		[]int{16, 32, 48, 256},
		logoC, true,
	); err != nil {
		fatal("запись ICO: %v", err)
	}
	fmt.Println("OK")

	fmt.Println("  Готово.")
}
