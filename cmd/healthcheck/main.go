// Package main implements the lancert healthcheck command.
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := os.Getenv("LANCERT_HTTP_ADDR")
	if addr == "" {
		addr = ":8443"
	}

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid LANCERT_HTTP_ADDR %q: %v\n", addr, err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get("http://localhost:" + port + "/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "health check failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "health check failed: status %d\n", resp.StatusCode)
		os.Exit(1)
	}
}
