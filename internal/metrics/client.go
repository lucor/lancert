package metrics

import "strings"

// ClientFamily is a bounded client classification derived from an HTTP User-Agent.
type ClientFamily string

const (
	ClientFamilyLancertCLI  ClientFamily = "lancert-cli"
	ClientFamilyACMESh      ClientFamily = "acme.sh"
	ClientFamilyCertManager ClientFamily = "cert-manager"
	ClientFamilyCaddy       ClientFamily = "caddy"
	ClientFamilyLego        ClientFamily = "lego"
	ClientFamilyTraefik     ClientFamily = "traefik"
	ClientFamilyCertbot     ClientFamily = "certbot"
	ClientFamilyCurl        ClientFamily = "curl"
	ClientFamilyOther       ClientFamily = "other"
	ClientFamilyUnknown     ClientFamily = "unknown"
)

// ClientFamilyFromUserAgent recognizes only explicit product names. It never
// returns a version or the raw User-Agent value.
func ClientFamilyFromUserAgent(userAgent string) ClientFamily {
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	if ua == "" {
		return ClientFamilyUnknown
	}
	switch {
	case containsProduct(ua, "lancert-cli"):
		return ClientFamilyLancertCLI
	case containsProduct(ua, "acme.sh"):
		return ClientFamilyACMESh
	case containsProduct(ua, "cert-manager"):
		return ClientFamilyCertManager
	case containsProduct(ua, "traefik"):
		return ClientFamilyTraefik
	case containsProduct(ua, "caddy"):
		return ClientFamilyCaddy
	case containsProduct(ua, "certbot"):
		return ClientFamilyCertbot
	case containsProduct(ua, "lego"):
		return ClientFamilyLego
	case containsProduct(ua, "curl"):
		return ClientFamilyCurl
	default:
		return ClientFamilyOther
	}
}

func containsProduct(userAgent, product string) bool {
	for offset := 0; offset < len(userAgent); {
		index := strings.Index(userAgent[offset:], product)
		if index < 0 {
			return false
		}
		index += offset
		end := index + len(product)
		if (index == 0 || !clientTokenByte(userAgent[index-1])) && (end == len(userAgent) || !clientTokenByte(userAgent[end])) {
			return true
		}
		offset = end
	}
	return false
}

func clientTokenByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '-' || value == '_' || value == '.'
}

func normalizeClientFamily(family ClientFamily) ClientFamily {
	switch family {
	case ClientFamilyLancertCLI, ClientFamilyACMESh, ClientFamilyCertManager,
		ClientFamilyCaddy, ClientFamilyLego, ClientFamilyTraefik,
		ClientFamilyCertbot, ClientFamilyCurl, ClientFamilyOther, ClientFamilyUnknown:
		return family
	case "":
		return ClientFamilyUnknown
	default:
		return ClientFamilyOther
	}
}
