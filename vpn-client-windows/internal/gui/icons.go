package gui

import (
	"image"
	"image/color"
	"math"

	"github.com/lxn/walk"
)

// createShieldIcon генерирует иконку щита заданного цвета (32x32).
func createShieldIcon(fill, border color.RGBA) *walk.Icon {
	const size = 32
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	// Центр и параметры щита
	cx := float64(size) / 2

	// Функция: точка внутри щита?
	inShield := func(x, y int) bool {
		fx, fy := float64(x)+0.5, float64(y)+0.5

		// Верх щита: скруглённая трапеция (y: 2..16)
		if fy >= 2 && fy <= 17 {
			// Ширина плавно сужается к низу
			halfW := 13.0 - (fy-2)*0.15
			if fy <= 5 {
				// Скруглённый верх
				halfW = 12.0 + math.Sqrt(math.Max(0, 9-(fy-5)*(fy-5)))
			}
			return math.Abs(fx-cx) <= halfW
		}

		// Низ щита: сужение к точке (y: 17..29)
		if fy > 17 && fy <= 29 {
			t := (fy - 17) / 12.0 // 0..1
			halfW := 10.7 * (1 - t*t)
			return math.Abs(fx-cx) <= halfW
		}

		return false
	}

	// Функция: точка на границе щита?
	onBorder := func(x, y int) bool {
		if !inShield(x, y) {
			return false
		}
		// Проверяем соседей — если хотя бы один сосед за пределами, это граница
		for _, d := range [][2]int{{-1, 0}, {1, 0}, {0, -1}, {0, 1}} {
			if !inShield(x+d[0], y+d[1]) {
				return true
			}
		}
		return false
	}

	// Рисуем щит
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if onBorder(x, y) {
				img.SetRGBA(x, y, border)
			} else if inShield(x, y) {
				// Градиент: светлее сверху
				t := float64(y) / float64(size)
				r := uint8(math.Min(255, float64(fill.R)+(1-t)*40))
				g := uint8(math.Min(255, float64(fill.G)+(1-t)*40))
				b := uint8(math.Min(255, float64(fill.B)+(1-t)*40))
				img.SetRGBA(x, y, color.RGBA{r, g, b, fill.A})
			}
			// Остальное — прозрачный (нулевой)
		}
	}

	// Рисуем галочку/символ внутри щита
	drawCheckmark(img, fill)

	icon, err := walk.NewIconFromImage(img)
	if err != nil {
		return nil
	}
	return icon
}

// drawCheckmark рисует символ внутри щита в зависимости от цвета.
func drawCheckmark(img *image.RGBA, fill color.RGBA) {
	white := color.RGBA{255, 255, 255, 255}

	// Рисуем вертикальную полоску (замок/ключ) — универсально
	// Верхняя часть: маленький кружок
	cx, cy := 16, 11
	for dy := -3; dy <= 3; dy++ {
		for dx := -3; dx <= 3; dx++ {
			dist := math.Sqrt(float64(dx*dx + dy*dy))
			if dist <= 3.2 && dist >= 1.5 {
				img.SetRGBA(cx+dx, cy+dy, white)
			}
		}
	}
	// Нижняя часть: прямоугольник-тельце замка
	for y := 14; y <= 21; y++ {
		for x := 13; x <= 19; x++ {
			img.SetRGBA(x, y, white)
		}
	}
	// Скважина
	for y := 15; y <= 19; y++ {
		for x := 15; x <= 17; x++ {
			img.SetRGBA(x, y, fill)
		}
	}
}

// makeShieldIcons создаёт три иконки щита для разных состояний.
func makeShieldIcons() (disconnected, connecting, connected *walk.Icon) {
	// Серый щит — отключён
	disconnected = createShieldIcon(
		color.RGBA{140, 140, 140, 255},
		color.RGBA{80, 80, 80, 255},
	)
	// Жёлтый щит — подключение
	connecting = createShieldIcon(
		color.RGBA{240, 180, 20, 255},
		color.RGBA{180, 130, 0, 255},
	)
	// Зелёный щит — подключён
	connected = createShieldIcon(
		color.RGBA{40, 180, 60, 255},
		color.RGBA{20, 120, 30, 255},
	)
	return
}
