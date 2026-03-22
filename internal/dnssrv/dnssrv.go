// Package dnssrv implements an authoritative DNS server for the lancert.dev zone.
//
// # Why lancert runs its own DNS server
//
// ACME DNS-01 validation requires provisioning TXT records under
// _acme-challenge.<domain> and having them visible to Let's Encrypt's resolvers.
// The only way to do this without calling an external DNS API (Cloudflare,
// Route53, etc.) is to be the authoritative nameserver for the zone yourself.
// lancert owns the zone, so it can provision challenge records in-process with
// zero external dependencies.
//
// # Record types served
//
//   - A: zone apex and NS glue records resolve to the server's public IP;
//     subdomains resolve to the RFC 1918 IP encoded in the label
//     (e.g. 192-168-1-50.lancert.dev. → 192.168.1.50).
//   - TXT: serves ACME DNS-01 challenge values from the in-memory TXTStore.
//     TTL is 0 so resolvers do not cache them — LE must see the current value.
//   - SOA, NS: required by the DNS protocol for an authoritative zone.
//   - CAA: restricts certificate issuance to configured CAs (e.g. letsencrypt.org),
//     preventing misissurance by other CAs even if they are publicly trusted.
//
// # Why UDP and TCP
//
// The DNS spec requires both transports. UDP handles the vast majority of
// queries; TCP is used for responses that exceed the 512-byte UDP limit and
// is required by some resolvers and the ACME spec.
//
// # Why TXT records are in-memory
//
// Challenge records are ephemeral: they are created immediately before calling
// Accept and removed as soon as validation completes (or fails). Persisting
// them to disk would add latency and complexity with no benefit — they are
// never needed across restarts.
package dnssrv

import (
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"lucor.dev/lancert/internal/privateip"
)

// Config holds the DNS server configuration.
type Config struct {
	// Zone is the authoritative zone with trailing dot, e.g. "lancert.dev."
	Zone string

	// NSRecords are the nameserver hostnames for NS responses, e.g.
	// ["ns1.lancert.dev.", "ns2.lancert.dev."]
	NSRecords []string

	// ServerIP is the public IP of this server, used for NS A record
	// glue responses.
	ServerIP netip.Addr

	// SOAMname is the primary nameserver for the SOA record.
	SOAMname string

	// SOARname is the admin email in DNS format (e.g. "admin.lancert.dev.").
	SOARname string

	// CAAIssuers is the list of CAs allowed to issue certs (e.g. ["letsencrypt.org"]).
	CAAIssuers []string
}

// Server is an authoritative DNS server for the lancert.dev zone.
// It resolves A records by parsing the IP from subdomain labels and
// serves TXT records from the in-memory TXTStore for ACME challenges.
type Server struct {
	config   Config
	txtStore *TXTStore
	mux      *dns.ServeMux
	udp      *dns.Server
	tcp      *dns.Server
}

// New creates a DNS server with the given config and TXT store.
func New(cfg Config, store *TXTStore) *Server {
	s := &Server{
		config:   cfg,
		txtStore: store,
	}

	s.mux = dns.NewServeMux()
	s.mux.HandleFunc(cfg.Zone, s.handleQuery)

	return s
}

// ListenAndServe starts UDP and TCP listeners on the given address
// (e.g. ":53"). If ready is non-nil it is called once both listeners
// are bound and serving. Blocks until a listener error or Shutdown.
func (s *Server) ListenAndServe(addr string, ready func()) error {
	s.udp = &dns.Server{Addr: addr, Net: "udp", Handler: s.mux}
	s.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: s.mux}

	errCh := make(chan error, 2)

	// Track when both listeners are bound.
	var wg sync.WaitGroup
	wg.Add(2)
	s.udp.NotifyStartedFunc = func() { wg.Done() }
	s.tcp.NotifyStartedFunc = func() { wg.Done() }

	go func() { errCh <- s.udp.ListenAndServe() }()
	go func() { errCh <- s.tcp.ListenAndServe() }()

	// Wait for both listeners to bind, or return early on error.
	readyCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(readyCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-readyCh:
		if ready != nil {
			ready()
		}
	}

	// Block until a listener fails or is shut down.
	return <-errCh
}

// Shutdown gracefully shuts down both listeners.
func (s *Server) Shutdown() error {
	var firstErr error

	if s.udp != nil {
		if err := s.udp.Shutdown(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.tcp != nil {
		if err := s.tcp.Shutdown(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// handleQuery is the miekg/dns handler for all queries in the zone.
func (s *Server) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA:
			s.handleA(msg, q)
		case dns.TypeTXT:
			s.handleTXT(msg, q)
		case dns.TypeSOA:
			s.handleSOA(msg, q)
		case dns.TypeNS:
			s.handleNS(msg, q)
		case dns.TypeCAA:
			s.handleCAA(msg, q)
		default:
			msg.Rcode = dns.RcodeSuccess
		}
	}

	if err := w.WriteMsg(msg); err != nil {
		slog.Error("dns write error", "error", err)
	}
}

// handleA resolves A queries by parsing the IP from the subdomain.
// Queries for the zone apex or NS hostnames return the server IP.
// Example: 192-168-1-50.lancert.dev. -> 192.168.1.50
// Example: foo.192-168-1-50.lancert.dev. -> 192.168.1.50
func (s *Server) handleA(msg *dns.Msg, q dns.Question) {
	name := strings.ToLower(q.Name)

	// Zone apex -> server IP
	if name == s.config.Zone {
		s.appendA(msg, q.Name, s.config.ServerIP)
		return
	}

	// NS glue records -> server IP
	for _, ns := range s.config.NSRecords {
		if name == strings.ToLower(ns) {
			s.appendA(msg, q.Name, s.config.ServerIP)
			return
		}
	}

	// Extract IP label from subdomain
	ipLabel := extractIPLabel(name, s.config.Zone)
	if ipLabel == "" {
		msg.Rcode = dns.RcodeNameError
		return
	}

	addr, err := privateip.ParseSubdomain(ipLabel)
	if err != nil {
		msg.Rcode = dns.RcodeNameError
		return
	}

	s.appendA(msg, q.Name, addr)
}

// handleTXT serves challenge records from the in-memory store.
func (s *Server) handleTXT(msg *dns.Msg, q dns.Question) {
	values := s.txtStore.Lookup(q.Name)
	if len(values) == 0 {
		return
	}

	for _, v := range values {
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			Txt: []string{v},
		})
	}
}

// handleSOA appends the SOA record for the zone.
func (s *Server) handleSOA(msg *dns.Msg, q dns.Question) {
	msg.Answer = append(msg.Answer, &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:      s.config.SOAMname,
		Mbox:    s.config.SOARname,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	})
}

// handleNS appends NS records for the zone.
func (s *Server) handleNS(msg *dns.Msg, q dns.Question) {
	for _, ns := range s.config.NSRecords {
		msg.Answer = append(msg.Answer, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns: ns,
		})
	}
}

// handleCAA appends CAA records restricting issuance to configured CAs.
func (s *Server) handleCAA(msg *dns.Msg, q dns.Question) {
	for _, issuer := range s.config.CAAIssuers {
		msg.Answer = append(msg.Answer, &dns.CAA{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeCAA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Flag:  0,
			Tag:   "issue",
			Value: issuer,
		})
	}
}

// appendA adds an A record to the message answer section.
func (s *Server) appendA(msg *dns.Msg, name string, addr netip.Addr) {
	ip := net.IP(addr.AsSlice())
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: ip,
	})
}

// extractIPLabel finds the IP-bearing label from a subdomain within the zone.
// For "foo.192-168-1-50.lancert.dev." with zone "lancert.dev.", returns "192-168-1-50".
// For "192-168-1-50.lancert.dev." returns "192-168-1-50".
// Returns "" if the name is not under the zone or has no subdomain.
func extractIPLabel(name, zone string) string {
	if !strings.HasSuffix(name, "."+zone) && name != zone {
		return ""
	}

	// Strip the zone suffix to get subdomain part
	sub := strings.TrimSuffix(name, "."+zone)
	if sub == "" || sub == name {
		return ""
	}

	// The IP label is the rightmost subdomain label before the zone.
	// "foo.192-168-1-50" -> "192-168-1-50"
	// "192-168-1-50" -> "192-168-1-50"
	parts := strings.Split(sub, ".")
	return parts[len(parts)-1]
}

// PacketConnAddr returns the local address of the UDP listener,
// useful in tests to find the assigned port when using ":0".
func (s *Server) PacketConnAddr() net.Addr {
	if s.udp == nil {
		return nil
	}
	return s.udp.PacketConn.LocalAddr()
}

