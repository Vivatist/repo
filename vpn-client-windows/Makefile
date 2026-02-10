.PHONY: build clean deps

# NovaVPN Client — Makefile (для сборки из PowerShell/cmd)

build: deps manifest
	go build -ldflags="-s -w -H windowsgui" -o NovaVPN.exe ./cmd/novavpn/
	@echo "Готово: NovaVPN.exe"

deps:
	go mod tidy

manifest:
	@cd cmd/novavpn && rsrc -manifest NovaVPN.exe.manifest -o rsrc.syso 2>nul || true

clean:
	@del /Q NovaVPN.exe 2>nul || true
	@del /Q cmd\novavpn\rsrc.syso 2>nul || true

install-tools:
	go install github.com/akavel/rsrc@latest
