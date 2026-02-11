.PHONY: build clean deps service installer icongen

# NovaVPN Client — Makefile (для сборки из PowerShell/cmd)

build: deps icongen winres-gui winres-service gui service
	@echo "Готово: NovaVPN.exe + novavpn-service.exe"

gui:
	go build -trimpath -ldflags="-w -H windowsgui" -o NovaVPN.exe ./cmd/novavpn/

service:
	go build -trimpath -ldflags="-w" -o novavpn-service.exe ./cmd/novavpn-service/

deps:
	go mod tidy

icongen:
	go run ./cmd/icongen/

winres-gui:
	@go-winres make --in winres/gui.json --out cmd/novavpn/winres --product-version 1.0.0.0 --file-version 1.0.0.0 2>nul || true

winres-service:
	@go-winres make --in winres/winres.json --out cmd/novavpn-service/winres --product-version 1.0.0.0 --file-version 1.0.0.0 2>nul || true

installer: build
	@if not exist dist mkdir dist
	iscc installer\novavpn.iss
	@echo "Готово: dist\NovaVPN-Setup-1.0.0.exe"

clean:
	@del /Q NovaVPN.exe 2>nul || true
	@del /Q novavpn-service.exe 2>nul || true
	@del /Q cmd\novavpn\winres_windows_*.syso 2>nul || true
	@del /Q cmd\novavpn-service\winres_windows_*.syso 2>nul || true
	@del /Q dist\*.exe 2>nul || true

install-tools:
	go install github.com/akavel/rsrc@latest
	go install github.com/tc-hib/go-winres@latest
