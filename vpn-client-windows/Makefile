.PHONY: build clean deps service installer

# NovaVPN Client — Makefile (для сборки из PowerShell/cmd)

build: deps manifest-gui manifest-service winres gui service
	@echo "Готово: NovaVPN.exe + novavpn-service.exe"

gui:
	go build -trimpath -ldflags="-w -H windowsgui" -o NovaVPN.exe ./cmd/novavpn/

service:
	go build -trimpath -ldflags="-w" -o novavpn-service.exe ./cmd/novavpn-service/

deps:
	go mod tidy

manifest-gui:
	@cd cmd/novavpn && rsrc -manifest NovaVPN.exe.manifest -o rsrc.syso 2>nul || true

manifest-service:
	@cd cmd/novavpn-service && rsrc -manifest novavpn-service.exe.manifest -o rsrc.syso 2>nul || true

winres:
	@go-winres make --in winres/winres.json --product-version 1.0.0.0 --file-version 1.0.0.0 2>nul || true

installer: build
	@if not exist dist mkdir dist
	iscc installer\novavpn.iss
	@echo "Готово: dist\NovaVPN-Setup-1.0.0.exe"

clean:
	@del /Q NovaVPN.exe 2>nul || true
	@del /Q novavpn-service.exe 2>nul || true
	@del /Q cmd\novavpn\rsrc.syso 2>nul || true
	@del /Q cmd\novavpn-service\rsrc.syso 2>nul || true
	@del /Q dist\*.exe 2>nul || true

install-tools:
	go install github.com/akavel/rsrc@latest
	go install github.com/tc-hib/go-winres@latest
