package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	host := "212.118.43.43:22"
	user := "root"
	pass := os.Args[1]
	cmd := strings.Join(os.Args[2:], " ")

	// Определяем физический IP
	localIP := getPhysicalIP()
	fmt.Printf("Local IP: %s\n", localIP)

	// Dial TCP с привязкой к физическому IP
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP)},
		Timeout:   15 * time.Second,
	}

	conn, err := dialer.Dial("tcp4", host)
	if err != nil {
		fmt.Printf("TCP dial error: %v\n", err)
		// Попробуем без привязки
		fmt.Println("Trying without binding...")
		conn, err = net.DialTimeout("tcp4", host, 15*time.Second)
		if err != nil {
			fmt.Printf("TCP dial error (unbound): %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("TCP connected: %s -> %s\n", conn.LocalAddr(), conn.RemoteAddr())

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, host, config)
	if err != nil {
		fmt.Printf("SSH error: %v\n", err)
		os.Exit(1)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		fmt.Printf("Session error: %v\n", err)
		os.Exit(1)
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		fmt.Printf("Command error: %v\n", err)
	}
	fmt.Print(string(output))
}

func getPhysicalIP() string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		if strings.Contains(name, "tailscale") || strings.Contains(name, "tun") ||
			strings.Contains(name, "tap") || strings.Contains(name, "nova") ||
			strings.Contains(name, "virtualbox") {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 != nil && !ip4.IsLoopback() {
				return ip4.String()
			}
		}
	}
	return "0.0.0.0"
}
