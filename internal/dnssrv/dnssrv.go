// Package dnssrv implements the authoritative DNS server for the Lancert zone.
package dnssrv

import (
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"go.lucor.dev/lancert/internal/registration"
)

const (
	soaMinTTL       = 5
	registrationTTL = 300
	challengeTTL    = 1
)

// Config holds authoritative zone configuration.
type Config struct {
	Zone      string
	NSRecords []string
	ServerIP  netip.Addr
	SOAMname  string
	SOARname  string
	StaticTXT map[string]StaticTXTRecord
	Recorder  Recorder
}

// StaticTXTRecord is a configured TXT RRset.
type StaticTXTRecord struct {
	TTL    uint32
	Values []string
}

// Recorder receives aggregate observations and must not block. An empty
// registration ID means the request did not resolve to a registration.
type Recorder interface {
	RecordDNSQuery(registrationID string)
	RecordResponse(bool, time.Duration)
}

// RegistrationView is the committed in-memory state needed by DNS.
type RegistrationView interface {
	Lookup(hostname string) (registration.Registration, bool)
}

// Server serves authoritative UDP and TCP DNS from a registration snapshot.
type Server struct {
	config   Config
	state    RegistrationView
	mux      *dns.ServeMux
	udp      *dns.Server
	tcp      *dns.Server
	recorder Recorder
}

// New creates a DNS server using state for dynamic A and TXT records.
func New(cfg Config, state RegistrationView) *Server {
	s := &Server{config: cfg, state: state, recorder: cfg.Recorder}
	s.mux = dns.NewServeMux()
	s.mux.HandleFunc(cfg.Zone, s.handleQuery)
	return s
}

// ListenAndServe starts UDP and TCP listeners. It calls ready after both bind.
func (s *Server) ListenAndServe(addr string, ready func()) error {
	s.udp = &dns.Server{Addr: addr, Net: "udp", Handler: s.mux}
	s.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: s.mux}

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	s.udp.NotifyStartedFunc = func() { wg.Done() }
	s.tcp.NotifyStartedFunc = func() { wg.Done() }
	go func() { errCh <- s.udp.ListenAndServe() }()
	go func() { errCh <- s.tcp.ListenAndServe() }()

	readyCh := make(chan struct{})
	go func() { wg.Wait(); close(readyCh) }()
	select {
	case err := <-errCh:
		return err
	case <-readyCh:
		if ready != nil {
			ready()
		}
	}
	return <-errCh
}

// Shutdown gracefully shuts down both listeners.
func (s *Server) Shutdown() error {
	var firstErr error
	if s.udp != nil {
		if err := s.udp.Shutdown(); err != nil {
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

func (s *Server) handleQuery(w dns.ResponseWriter, request *dns.Msg) {
	started := time.Now()
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true

	var registrationID string
	if len(request.Question) != 1 {
		response.Rcode = dns.RcodeFormatError
	} else {
		registrationID = s.answer(response, request.Question[0]).registration.ID
	}

	err := w.WriteMsg(response)
	if s.recorder != nil {
		s.recorder.RecordDNSQuery(registrationID)
		s.recorder.RecordResponse(err == nil, time.Since(started))
	}
	if err != nil {
		slog.Error("dns write error", "error", err)
	}
}

type ownerKind uint8

const (
	ownerUnknown ownerKind = iota
	ownerApex
	ownerNameserver
	ownerStatic
	ownerRegistration
	ownerWildcard
	ownerChallenge
)

type owner struct {
	kind         ownerKind
	registration registration.Registration
	static       StaticTXTRecord
}

func (s *Server) answer(msg *dns.Msg, q dns.Question) owner {
	resolved := s.resolveOwner(strings.ToLower(q.Name))
	if resolved.kind == ownerUnknown {
		s.negative(msg, true)
		return resolved
	}

	switch q.Qtype {
	case dns.TypeA:
		s.answerA(msg, q, resolved)
	case dns.TypeTXT:
		s.answerTXT(msg, q, resolved)
	case dns.TypeSOA:
		if resolved.kind == ownerApex {
			msg.Answer = append(msg.Answer, s.soaRR(s.config.Zone))
		} else {
			s.negative(msg, false)
		}
	case dns.TypeNS:
		if resolved.kind == ownerApex {
			s.appendNS(msg, q.Name)
		} else {
			s.negative(msg, false)
		}
	default:
		s.negative(msg, false)
	}
	return resolved
}

func (s *Server) resolveOwner(name string) owner {
	if name == strings.ToLower(s.config.Zone) {
		return owner{kind: ownerApex, static: s.config.StaticTXT[name]}
	}
	for _, ns := range s.config.NSRecords {
		if name == strings.ToLower(ns) {
			return owner{kind: ownerNameserver, static: s.config.StaticTXT[name]}
		}
	}
	if static, ok := s.config.StaticTXT[name]; ok {
		return owner{kind: ownerStatic, static: static}
	}

	labels, ok := relativeLabels(name, strings.ToLower(s.config.Zone))
	if !ok {
		return owner{}
	}
	var hostname string
	kind := ownerUnknown
	switch {
	case len(labels) == 1:
		hostname, kind = labels[0], ownerRegistration
	case len(labels) == 2 && labels[0] == "_acme-challenge":
		hostname, kind = labels[1], ownerChallenge
	case len(labels) == 2:
		hostname, kind = labels[1], ownerWildcard
	default:
		return owner{}
	}
	if !validHostname(hostname) || s.state == nil {
		return owner{}
	}
	registered, found := s.state.Lookup(hostname)
	if !found {
		return owner{}
	}
	return owner{kind: kind, registration: registered}
}

func (s *Server) answerA(msg *dns.Msg, q dns.Question, resolved owner) {
	switch resolved.kind {
	case ownerApex, ownerNameserver:
		s.appendA(msg, q.Name, s.config.ServerIP)
	case ownerRegistration, ownerWildcard:
		s.appendA(msg, q.Name, resolved.registration.TargetIP)
	default:
		s.negative(msg, false)
	}
}

func (s *Server) answerTXT(msg *dns.Msg, q dns.Question, resolved owner) {
	if resolved.kind == ownerChallenge {
		for _, value := range resolved.registration.Challenges {
			if value != "" {
				s.appendTXT(msg, q.Name, challengeTTL, value)
			}
		}
		if len(msg.Answer) == 0 {
			s.negative(msg, false)
		}
		return
	}
	if len(resolved.static.Values) > 0 {
		for _, value := range resolved.static.Values {
			s.appendTXT(msg, q.Name, resolved.static.TTL, value)
		}
		return
	}
	s.negative(msg, false)
}

func (s *Server) negative(msg *dns.Msg, nameError bool) {
	if nameError {
		msg.Rcode = dns.RcodeNameError
	}
	if len(msg.Ns) == 0 {
		msg.Ns = append(msg.Ns, s.soaRR(s.config.Zone))
	}
}

func (s *Server) appendA(msg *dns.Msg, name string, addr netip.Addr) {
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: registrationTTL},
		A:   net.IP(addr.AsSlice()),
	})
}

func (s *Server) appendTXT(msg *dns.Msg, name string, ttl uint32, value string) {
	msg.Answer = append(msg.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
		Txt: splitTXTValue(value),
	})
}

func (s *Server) appendNS(msg *dns.Msg, name string) {
	for _, ns := range s.config.NSRecords {
		msg.Answer = append(msg.Answer, &dns.NS{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  ns,
		})
	}
}

func (s *Server) soaRR(name string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaMinTTL},
		Ns:      s.config.SOAMname,
		Mbox:    s.config.SOARname,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  soaMinTTL,
	}
}

func splitTXTValue(value string) []string {
	const maxLen = 255
	parts := make([]string, 0, (len(value)+maxLen-1)/maxLen)
	for len(value) > maxLen {
		parts = append(parts, value[:maxLen])
		value = value[maxLen:]
	}
	return append(parts, value)
}

func relativeLabels(name, zone string) ([]string, bool) {
	suffix := "." + zone
	if !strings.HasSuffix(name, suffix) {
		return nil, false
	}
	relative := strings.TrimSuffix(name, suffix)
	if relative == "" {
		return nil, false
	}
	return strings.Split(relative, "."), true
}

func validHostname(hostname string) bool {
	if len(hostname) < 1 || len(hostname) > 63 || hostname[0] == '-' || hostname[len(hostname)-1] == '-' {
		return false
	}
	for i := range len(hostname) {
		c := hostname[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// PacketConnAddr returns the UDP listener address for tests.
func (s *Server) PacketConnAddr() net.Addr {
	if s.udp == nil {
		return nil
	}
	return s.udp.PacketConn.LocalAddr()
}
