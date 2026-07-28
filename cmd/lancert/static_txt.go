package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/miekg/dns"

	"lucor.dev/lancert/internal/dnssrv"
)

const defaultStaticTXTTTL uint32 = 300

type staticTXTConfig struct {
	TTL    *uint32  `json:"ttl"`
	Values []string `json:"values"`
}

func parseStaticTXT(raw, zone string) (map[string]dnssrv.StaticTXTRecord, error) {
	if raw == "" {
		return nil, nil
	}

	var configured map[string]staticTXTConfig
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&configured); err != nil {
		return nil, fmt.Errorf("invalid LANCERT_STATIC_TXT JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid LANCERT_STATIC_TXT JSON: trailing content")
	}
	if len(configured) == 0 {
		return nil, fmt.Errorf("invalid LANCERT_STATIC_TXT: at least one record is required")
	}

	zone = strings.ToLower(dns.Fqdn(zone))
	records := make(map[string]dnssrv.StaticTXTRecord, len(configured))
	for configuredName, configuredRecord := range configured {
		name, err := staticTXTFQDN(configuredName, zone)
		if err != nil {
			return nil, fmt.Errorf("invalid LANCERT_STATIC_TXT name %q: %w", configuredName, err)
		}
		if _, exists := records[name]; exists {
			return nil, fmt.Errorf("invalid LANCERT_STATIC_TXT name %q: duplicate normalized name %s", configuredName, name)
		}
		if len(configuredRecord.Values) == 0 {
			return nil, fmt.Errorf("invalid LANCERT_STATIC_TXT record %q: at least one value is required", configuredName)
		}
		for _, value := range configuredRecord.Values {
			if value == "" {
				return nil, fmt.Errorf("invalid LANCERT_STATIC_TXT record %q: values must not be empty", configuredName)
			}
		}

		ttl := defaultStaticTXTTTL
		if configuredRecord.TTL != nil {
			ttl = *configuredRecord.TTL
		}
		records[name] = dnssrv.StaticTXTRecord{
			TTL:    ttl,
			Values: append([]string(nil), configuredRecord.Values...),
		}
	}
	return records, nil
}

func staticTXTFQDN(configuredName, zone string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(configuredName))
	switch {
	case name == "":
		return "", fmt.Errorf("name must not be empty")
	case name == "@":
		name = zone
	case strings.HasSuffix(name, "."):
		// Already an FQDN.
	default:
		name = dns.Fqdn(name + "." + strings.TrimSuffix(zone, "."))
	}

	if _, ok := dns.IsDomainName(name); !ok {
		return "", fmt.Errorf("not a valid DNS name")
	}
	if name != zone && !strings.HasSuffix(name, "."+zone) {
		return "", fmt.Errorf("name must belong to zone %s", zone)
	}

	relative := strings.TrimSuffix(name, zone)
	relative = strings.TrimSuffix(relative, ".")
	if relative == "_acme-challenge" || strings.HasPrefix(relative, "_acme-challenge.") {
		return "", fmt.Errorf("_acme-challenge is reserved for ACME")
	}
	return name, nil
}
