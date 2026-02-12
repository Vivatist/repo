//go:build windows

// Package elevation предоставляет функцию запуска процесса с повышенными привилегиями (UAC).
// Используется GUI для установки/запуска сервиса без запроса админ-прав для самого GUI.
package elevation

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SEE_MASK_NOCLOSEPROCESS — ожидать завершения процесса.
const seeMaskNoCloseProcess = 0x00000040

// SHELLEXECUTEINFOW — структура для ShellExecuteExW.
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     windows.Handle
}

var (
	shell32         = windows.NewLazySystemDLL("shell32.dll")
	shellExecuteExW = shell32.NewProc("ShellExecuteExW")
)

// RunElevated запускает exe с аргументами от имени администратора (с UAC-запросом).
// Блокирует до завершения запущенного процесса.
func RunElevated(exe string, args string) error {
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	params, err := windows.UTF16PtrFromString(args)
	if err != nil {
		return err
	}

	sei := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		nShow:        0, // SW_HIDE
	}
	sei.cbSize = uint32(unsafe.Sizeof(sei))

	r1, _, errCall := shellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if r1 == 0 {
		return fmt.Errorf("ShellExecuteEx: %w", errCall)
	}

	// Ожидаем завершения запущенного процесса
	if sei.hProcess != 0 {
		windows.WaitForSingleObject(sei.hProcess, windows.INFINITE)
		windows.CloseHandle(sei.hProcess)
	}

	return nil
}
