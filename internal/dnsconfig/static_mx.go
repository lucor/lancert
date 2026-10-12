package dnsconfig

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"go.lucor.dev/lancert/internal/dnssrv"
)

const defaultStaticMXTTL uint32 = 300

type staticMXConfig struct {
	TTL     *uint32           `json:"ttl"`
	Records []dnssrv.MXRecord `json:"records"`
}

// ParseStaticMX parses LANCERT_STATIC_MX and normalizes mail server names to
// absolute DNS names, since exchanges can belong to an external provider.
func ParseStaticMX(raw, zone string) (map[string]dnssrv.StaticMXRecord, error) {
	if raw == "" {
		return nil, nil
	}

	var configured map[string]staticMXConfig
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&configured); err != nil {
		return nil, fmt.Errorf("invalid LANCERT_STATIC_MX JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid LANCERT_STATIC_MX JSON: trailing content")
	}
	if len(configured) == 0 {
		return nil, fmt.Errorf("invalid LANCERT_STATIC_MX: at least one record is required")
	}

	zone = strings.ToLower(dns.Fqdn(zone))
	records := make(map[string]dnssrv.StaticMXRecord, len(configured))
	for configuredName, configuredRecord := range configured {
		name, err := staticRecordFQDN(configuredName, zone)
		if err != nil {
			return nil, fmt.Errorf("invalid LANCERT_STATIC_MX name %q: %w", configuredName, err)
		}
		if _, exists := records[name]; exists {
			return nil, fmt.Errorf("invalid LANCERT_STATIC_MX name %q: duplicate normalized name %s", configuredName, name)
		}
		if len(configuredRecord.Records) == 0 {
			return nil, fmt.Errorf("invalid LANCERT_STATIC_MX record %q: at least one exchange is required", configuredName)
		}
		for i := range configuredRecord.Records {
			record := &configuredRecord.Records[i]
			exchange := strings.ToLower(strings.TrimSpace(record.Exchange))
			if exchange == "" {
				return nil, fmt.Errorf("invalid LANCERT_STATIC_MX record %q: exchange must not be empty", configuredName)
			}
			if _, ok := dns.IsDomainName(exchange); !ok {
				return nil, fmt.Errorf("invalid LANCERT_STATIC_MX record %q: exchange %q is not a valid DNS name", configuredName, record.Exchange)
			}
			if _, err := netip.ParseAddr(strings.TrimSuffix(exchange, ".")); err == nil {
				return nil, fmt.Errorf("invalid LANCERT_STATIC_MX record %q: exchange %q must be a DNS name, not an IP address", configuredName, record.Exchange)
			}
			if strings.Contains(exchange, "*") {
				return nil, fmt.Errorf("invalid LANCERT_STATIC_MX record %q: exchange %q must not contain a wildcard", configuredName, record.Exchange)
			}
			// A null MX explicitly disables email and cannot accompany a mail server.
			if exchange == "." && (record.Preference != 0 || len(configuredRecord.Records) != 1) {
				return nil, fmt.Errorf("invalid LANCERT_STATIC_MX record %q: null MX must be the sole record with preference 0", configuredName)
			}
			record.Exchange = dns.Fqdn(exchange)
		}
		ttl := defaultStaticMXTTL
		if configuredRecord.TTL != nil {
			ttl = *configuredRecord.TTL
		}
		records[name] = dnssrv.StaticMXRecord{TTL: ttl, Records: configuredRecord.Records}
	}
	return records, nil
}
