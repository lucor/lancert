package metrics

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClientFamilyFromUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      ClientFamily
	}{
		{"Lancert CLI", "lancert-cli/1.2.0", ClientFamilyLancertCLI},
		{"acme.sh", "acme.sh/3.0.7 (https://github.com/acmesh-official/acme.sh)", ClientFamilyACMESh},
		{"cert-manager", "cert-manager/1.15.0", ClientFamilyCertManager},
		{"Caddy", "Caddy/2.8.4 CertMagic acmez", ClientFamilyCaddy},
		{"lego", "lego/v4.21.0", ClientFamilyLego},
		{"embedded lego", "go-acme/lego/v4.21.0", ClientFamilyLego},
		{"Traefik", "Traefik/3.1.0", ClientFamilyTraefik},
		{"Traefik before lego", "Traefik/3.1.0 go-acme/lego/v4.21.0", ClientFamilyTraefik},
		{"Certbot", "Certbot/2.10.0", ClientFamilyCertbot},
		{"curl", "curl/8.9.1", ClientFamilyCurl},
		{"generic Go", "Go-http-client/1.1", ClientFamilyOther},
		{"python requests", "python-requests/2.32.3", ClientFamilyOther},
		{"generic Caddy library", "CertMagic acmez", ClientFamilyOther},
		{"product substring", "notcaddy/1.0", ClientFamilyOther},
		{"empty", "", ClientFamilyUnknown},
		{"unknown", "custom-acme-client/1.0", ClientFamilyOther},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ClientFamilyFromUserAgent(test.userAgent); got != test.want {
				t.Fatalf("ClientFamilyFromUserAgent(%q) = %q, want %q", test.userAgent, got, test.want)
			}
		})
	}
}

func TestStoredUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{"unchanged", " Lego/v4.21.0 ", " Lego/v4.21.0 "},
		{"invalid UTF-8 and controls", "Agent/\xff1\r\n\t\x00Done", "Agent/\uFFFD1    Done"},
		{"empty", "", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := storedUserAgent(test.userAgent); got != test.want {
				t.Fatalf("storedUserAgent(%q) = %q, want %q", test.userAgent, got, test.want)
			}
		})
	}

	got := storedUserAgent(strings.Repeat("a", maxStoredUserAgentBytes-1) + "é")
	if len(got) > maxStoredUserAgentBytes || !utf8.ValidString(got) {
		t.Fatalf("storedUserAgent returned %d bytes of invalid UTF-8", len(got))
	}
	if got != strings.Repeat("a", maxStoredUserAgentBytes-1) {
		t.Fatalf("storedUserAgent split a UTF-8 encoding: %q", got)
	}
}
