.PHONY: build clean deps service

# NovaVPN Client — Makefile (для сборки из PowerShell/cmd)

build: deps manifest gui service
	@echo "Готово: NovaVPN.exe + novavpn-service.exe"

gui:
	go build -ldflags="-s -w -H windowsgui" -o NovaVPN.exe ./cmd/novavpn/

service:
	go build -ldflags="-s -w" -o novavpn-service.exe ./cmd/novavpn-service/

deps:
	go mod tidy

manifest:
	@cd cmd/novavpn && rsrc -manifest NovaVPN.exe.manifest -o rsrc.syso 2>nul || true

clean:
	@del /Q NovaVPN.exe 2>nul || true
	@del /Q novavpn-service.exe 2>nul || true
	@del /Q cmd\novavpn\rsrc.syso 2>nul || true

install-tools:
	go install github.com/akavel/rsrc@latest
