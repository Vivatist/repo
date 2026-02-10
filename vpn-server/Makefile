GOOS=linux
GOARCH=amd64
CGO_ENABLED=0
BINARY=novavpn-server
CMD_DIR=./cmd/vpnserver
LDFLAGS=-ldflags="-s -w"

.PHONY: build clean test run

build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) go build $(LDFLAGS) -o $(BINARY) $(CMD_DIR)

build-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY)-arm64 $(CMD_DIR)

clean:
	rm -f $(BINARY) $(BINARY)-arm64

test:
	go test ./...

run:
	sudo go run $(CMD_DIR)/main.go -config /etc/novavpn/server.yaml

genkey:
	go run $(CMD_DIR)/main.go -genkey

genconfig:
	go run $(CMD_DIR)/main.go -genconfig

adduser:
	@read -p "Email: " email; \
	read -sp "Password: " pass; echo; \
	go run $(CMD_DIR)/main.go -adduser -email $$email -password $$pass

listusers:
	go run $(CMD_DIR)/main.go -listusers

install: build
	sudo cp $(BINARY) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY)

tidy:
	go mod tidy
