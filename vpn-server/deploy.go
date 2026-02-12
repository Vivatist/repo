// +build ignore

package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	host := "212.118.54.76"
	port := "22"
	user := "root"
	password := "h#r-5=4Cz6q284iSpSkM"

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(host, port), config)
	if err != nil {
		log.Fatalf("SSH dial failed: %v", err)
	}
	defer client.Close()
	fmt.Println("SSH connected")

	// Stop server first
	fmt.Println("Stopping service...")
	runSSH(client, "systemctl stop novavpn")

	// Upload via cat
	localFile := "novavpn-server-linux"
	remotePath := "/usr/local/bin/novavpn-server"

	if err := uploadViaCat(client, localFile, remotePath); err != nil {
		log.Fatalf("Upload failed: %v", err)
	}
	fmt.Println("Binary uploaded")

	commands := []string{
		"chmod +x /usr/local/bin/novavpn-server",
		"systemctl start novavpn",
		"sleep 1",
		"systemctl status novavpn --no-pager",
	}

	for _, cmd := range commands {
		fmt.Printf(">> %s\n", cmd)
		output, err := runSSH(client, cmd)
		if err != nil {
			fmt.Printf("   Error: %v\n", err)
		}
		if output != "" {
			fmt.Println(output)
		}
	}

	fmt.Println("\nDeploy complete!")
}

func uploadViaCat(client *ssh.Client, localPath, remotePath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local file: %w", err)
	}
	defer f.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	w, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		defer w.Close()
		_, err := io.Copy(w, f)
		errCh <- err
	}()

	if err := session.Run(fmt.Sprintf("cat > %s", remotePath)); err != nil {
		return fmt.Errorf("run cat: %w", err)
	}

	if err := <-errCh; err != nil {
		return fmt.Errorf("copy data: %w", err)
	}

	return nil
}

func runSSH(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	out, err := session.CombinedOutput(cmd)
	return string(out), err
}
