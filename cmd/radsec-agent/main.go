// cmd/radsec-agent/main.go
// HAProxy agent-check sidecar for FreeRADIUS.
// Listens on TCP and responds "up\n" or "down\n" based on a Status-Server
// probe to the local FreeRADIUS status virtual server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ComputerScienceHouse/pint/internal/radius"
)

func main() {
	listenAddr := flag.String("listen", ":2084", "TCP address for HAProxy agent-check connections")
	statusAddr := flag.String("status", "127.0.0.1:18121", "FreeRADIUS status server UDP address")
	secretFile := flag.String("secret-file", "/etc/pint/config/status-secret", "File containing the RADIUS status server secret")
	flag.Parse()

	secretBytes, err := os.ReadFile(*secretFile)
	if err != nil {
		log.Fatalf("read secret file: %v", err)
	}
	secret := strings.TrimSpace(string(secretBytes))

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("radsec-agent listening on %s, checking %s", *listenAddr, *statusAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn, *statusAddr, secret)
	}
}

func handle(conn net.Conn, statusAddr, secret string) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	response := "down\n"
	if radius.QueryRADIUSStats(ctx, statusAddr, secret) != nil {
		response = "up\n"
	}
	fmt.Fprint(conn, response)
}
