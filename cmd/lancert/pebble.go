package main

import (
	"context"
	"fmt"
	"net"
	"path/filepath"

	acmeissue "lucor.dev/lancert/internal/acme"
)

// acmeRuntimeConfig returns extra client settings needed only by local Pebble.
func acmeRuntimeConfig(environment acmeissue.Environment, dnsAddr string) (*net.Resolver, string, error) {
	if environment != acmeissue.EnvironmentLocal {
		return nil, "", nil
	}
	host, port, err := net.SplitHostPort(dnsAddr)
	if err != nil {
		return nil, "", fmt.Errorf("local ACME requires LANCERT_DNS_ADDR with host and port: %w", err)
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host, port))
	}}
	return resolver, filepath.Join(".mise", "pebble", "rootCA.pem"), nil
}
