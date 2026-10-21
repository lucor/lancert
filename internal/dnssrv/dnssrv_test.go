package dnssrv

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lucor.dev/lancert/internal/registration"
)

// Build and inspect wire packets directly, independently of the library's client.
func TestDNSWireCompatibilityOverUDPAndTCP(t *testing.T) {
	server := New(Config{Zone: testZone, ServerIP: netip.MustParseAddr("192.0.2.53")}, nil)
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe("127.0.0.1:0", func() { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("DNS startup failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("DNS startup timed out")
	}
	t.Cleanup(func() {
		require.NoError(t, server.Shutdown())
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("DNS shutdown timed out")
		}
	})

	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			addr := server.PacketConnAddr().String()
			if network == "tcp" {
				addr = server.tcp.Listener.Addr().String()
			}
			conn, err := net.DialTimeout(network, addr, time.Second)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, conn.Close()) })
			// Reuse the connection to cover multiple TCP requests and pooled UDP buffers.
			for _, id := range []uint16{0x1234, 0x5678} {
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				packet := []byte{
					byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
					7, 'L', 'a', 'N', 'c', 'E', 'r', 'T', 3, 'D', 'e', 'V', 0,
					0, 1, 0, 1, // A, IN
				}
				wire := packet
				if network == "tcp" {
					wire = binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
					wire = append(wire, packet...)
				}
				_, err := conn.Write(wire)
				require.NoError(t, err)
				response := make([]byte, 512)
				if network == "tcp" {
					var prefix [2]byte
					_, err = io.ReadFull(conn, prefix[:])
					require.NoError(t, err)
					response = make([]byte, binary.BigEndian.Uint16(prefix[:]))
					_, err = io.ReadFull(conn, response)
				} else {
					var n int
					n, err = conn.Read(response)
					response = response[:n]
				}
				require.NoError(t, err)
				require.GreaterOrEqual(t, len(response), len(packet)+16)
				assert.Equal(t, id, binary.BigEndian.Uint16(response[:2]))
				assert.Equal(t, uint16(0x8500), binary.BigEndian.Uint16(response[2:4])) // QR, AA, RD
				assert.Equal(t, []byte{0, 1, 0, 1, 0, 0, 0, 0}, response[4:12])
				assert.Equal(t, packet[12:], response[12:len(packet)])
				assert.Equal(t, []byte{192, 0, 2, 53}, response[len(response)-4:])
			}
		})
	}
}

const (
	testZone     = "lancert.dev."
	testHostname = "quiet-otter"
)

type testState struct {
	mu      sync.RWMutex
	records map[string]registration.Registration
}

func (s *testState) Lookup(hostname string) (registration.Registration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[hostname]
	return r, ok
}

type testRecorder struct {
	mu            sync.Mutex
	registrations []string
	responses     int
}

func (r *testRecorder) RecordDNSQuery(registrationID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registrations = append(r.registrations, registrationID)
}

func (r *testRecorder) RecordResponse(bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.responses++
}

func startTestServer(t *testing.T, recorder Recorder) (*Server, string, *testState) {
	t.Helper()
	state := &testState{records: map[string]registration.Registration{
		testHostname: {
			ID:         "01900000-0000-7000-8000-000000000000",
			Hostname:   testHostname,
			TargetIP:   netip.MustParseAddr("192.168.1.50"),
			Challenges: [2]string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},
		},
	}}
	cfg := Config{
		Zone:      testZone,
		NSRecords: []string{"ns1.lancert.dev.", "ns2.lancert.dev."},
		ServerIP:  netip.MustParseAddr("5.9.100.1"),
		SOAMname:  "ns1.lancert.dev.",
		SOARname:  "admin.lancert.dev.",
		StaticTXT: map[string]StaticTXTRecord{
			testZone: {TTL: 600, Values: []string{"verification"}},
		},
		StaticMX: map[string]StaticMXRecord{
			testZone: {TTL: 600, Records: []MXRecord{
				{Preference: 10, Exchange: "mx1.example.net."},
				{Preference: 20, Exchange: "mx2.example.net."},
			}},
			"mail.lancert.dev.": {TTL: 300, Records: []MXRecord{{Preference: 10, Exchange: "mx1.example.net."}}},
		},
		Recorder: recorder,
	}
	srv := New(cfg, state)
	srv.udp = &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: srv.mux, MsgAcceptFunc: srv.acceptQuery}
	started := make(chan struct{})
	srv.udp.NotifyStartedFunc = func(context.Context) { close(started) }
	errCh := make(chan error, 1)
	go func() { errCh <- srv.udp.ListenAndServe() }()
	select {
	case <-started:
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out starting DNS server")
	}
	t.Cleanup(func() { require.NoError(t, srv.Shutdown()) })
	return srv, srv.PacketConnAddr().String(), state
}

func query(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	request := new(dns.Msg)
	dnsutil.SetQuestion(request, dnsutil.Fqdn(name), qtype)
	response, _, err := new(dns.Client).Exchange(context.Background(), request, "udp", addr)
	require.NoError(t, err)
	return response
}

func TestRejectsMultipleQuestions(t *testing.T) {
	_, addr, _ := startTestServer(t, nil)
	// The new client only packs one question, so send a malformed packet directly.
	packet := []byte{0x12, 0x34, 0x01, 0, 0, 2, 0, 0, 0, 0, 0, 0}
	question := []byte{7, 'l', 'a', 'n', 'c', 'e', 'r', 't', 3, 'd', 'e', 'v', 0, 0, 1, 0, 1}
	packet = append(packet, question...)
	packet = append(packet, question...)
	conn, err := net.DialTimeout("udp", addr, time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write(packet)
	require.NoError(t, err)
	response := make([]byte, 512)
	n, err := conn.Read(response)
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, 12)
	assert.Equal(t, uint16(0x1234), binary.BigEndian.Uint16(response[:2]))
	assert.Equal(t, uint16(dns.RcodeFormatError), binary.BigEndian.Uint16(response[2:4])&0xf)
	assert.Equal(t, uint16(0), binary.BigEndian.Uint16(response[6:8]))
}

func TestRegisteredAOwners(t *testing.T) {
	_, addr, _ := startTestServer(t, nil)
	for _, name := range []string{
		testHostname + ".lancert.dev.",
		"app." + testHostname + ".lancert.dev.",
		"APP." + strings.ToUpper(testHostname) + ".LANCERT.DEV.",
	} {
		response := query(t, addr, name, dns.TypeA)
		require.Len(t, response.Answer, 1)
		record, ok := response.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "192.168.1.50", record.Addr.String())
		assert.Equal(t, uint32(300), record.Hdr.TTL)
	}
	response := query(t, addr, testHostname+"."+testZone, dns.TypeAAAA)
	assertAddressFamilyNODATA(t, response)
}

func TestRegisteredAAAAOwnersAndAddressFamilyNODATA(t *testing.T) {
	_, addr, state := startTestServer(t, nil)
	ula := netip.MustParseAddr("fd12:3456:789a:1::25")
	state.mu.Lock()
	registration := state.records[testHostname]
	registration.TargetIP = ula
	state.records[testHostname] = registration
	state.mu.Unlock()

	for _, name := range []string{
		testHostname + ".lancert.dev.",
		"app." + testHostname + ".lancert.dev.",
	} {
		response := query(t, addr, name, dns.TypeAAAA)
		require.Len(t, response.Answer, 1)
		record, ok := response.Answer[0].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, ula, netip.MustParseAddr(record.Addr.String()))
		assert.Equal(t, uint32(registrationTTL), record.Hdr.TTL)

		response = query(t, addr, name, dns.TypeA)
		assertAddressFamilyNODATA(t, response)
	}
}

func assertAddressFamilyNODATA(t *testing.T, response *dns.Msg) {
	t.Helper()
	assert.Equal(t, uint16(dns.RcodeSuccess), response.Rcode)
	assert.Empty(t, response.Answer)
	require.Len(t, response.Ns, 1)
	assert.IsType(t, &dns.SOA{}, response.Ns[0])
}

func TestRegistrationOwnerBoundaries(t *testing.T) {
	_, addr, _ := startTestServer(t, nil)

	challengeA := query(t, addr, "_acme-challenge."+testHostname+".lancert.dev.", dns.TypeA)
	assert.Equal(t, uint16(dns.RcodeSuccess), challengeA.Rcode)
	assert.Empty(t, challengeA.Answer)
	require.Len(t, challengeA.Ns, 1)

	for _, name := range []string{
		"foo.bar." + testHostname + ".lancert.dev.",
		"unknownunknownunknown2.lancert.dev.",
		"192-168-1-50.lancert.dev.",
	} {
		response := query(t, addr, name, dns.TypeA)
		assert.Equal(t, uint16(dns.RcodeNameError), response.Rcode)
		assert.Empty(t, response.Answer)
		require.Len(t, response.Ns, 1)
		soa, ok := response.Ns[0].(*dns.SOA)
		require.True(t, ok)
		assert.Equal(t, uint32(5), soa.Minttl)
	}
}

func TestChallengeTXTTwoSlotsAndNODATA(t *testing.T) {
	_, addr, state := startTestServer(t, nil)
	name := "_AcMe-ChAlLeNgE." + strings.ToUpper(testHostname) + ".LaNcErT.DeV."
	response := query(t, addr, name, dns.TypeTXT)
	require.Len(t, response.Answer, 2)
	var values []string
	for _, answer := range response.Answer {
		record, ok := answer.(*dns.TXT)
		require.True(t, ok)
		assert.Equal(t, uint32(1), record.Hdr.TTL)
		values = append(values, strings.Join(record.Txt, ""))
	}
	assert.ElementsMatch(t, []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	}, values)

	state.mu.Lock()
	r := state.records[testHostname]
	r.Challenges = [2]string{}
	state.records[testHostname] = r
	state.mu.Unlock()
	response = query(t, addr, name, dns.TypeTXT)
	assert.Equal(t, uint16(dns.RcodeSuccess), response.Rcode)
	assert.Empty(t, response.Answer)
	require.Len(t, response.Ns, 1)
}

func TestDisabledOrRemovedRegistrationIsUnavailable(t *testing.T) {
	_, addr, state := startTestServer(t, nil)
	state.mu.Lock()
	delete(state.records, testHostname)
	state.mu.Unlock()

	for _, test := range []struct {
		name  string
		qtype uint16
	}{
		{testHostname + ".lancert.dev.", dns.TypeA},
		{"app." + testHostname + ".lancert.dev.", dns.TypeA},
		{"_acme-challenge." + testHostname + ".lancert.dev.", dns.TypeTXT},
	} {
		response := query(t, addr, test.name, test.qtype)
		assert.Equal(t, uint16(dns.RcodeNameError), response.Rcode)
	}
}

func TestInfrastructureStaticAndNoCAA(t *testing.T) {
	_, addr, _ := startTestServer(t, nil)

	apex := query(t, addr, testZone, dns.TypeA)
	require.Len(t, apex.Answer, 1)
	assert.Equal(t, "5.9.100.1", apex.Answer[0].(*dns.A).Addr.String())

	ns := query(t, addr, testZone, dns.TypeNS)
	require.Len(t, ns.Answer, 2)
	soa := query(t, addr, testZone, dns.TypeSOA)
	require.Len(t, soa.Answer, 1)
	static := query(t, addr, testZone, dns.TypeTXT)
	require.Len(t, static.Answer, 1)
	assert.Equal(t, uint32(600), static.Answer[0].Header().TTL)

	caa := query(t, addr, testZone, dns.TypeCAA)
	assert.Equal(t, uint16(dns.RcodeSuccess), caa.Rcode)
	assert.Empty(t, caa.Answer)
	require.Len(t, caa.Ns, 1)
}

func TestStaticMX(t *testing.T) {
	_, addr, _ := startTestServer(t, nil)
	response := query(t, addr, "LANCERT.DEV.", dns.TypeMX)
	require.Equal(t, uint16(dns.RcodeSuccess), response.Rcode)
	assert.True(t, response.Authoritative)
	require.Len(t, response.Answer, 2)
	for i, exchange := range []string{"mx1.example.net.", "mx2.example.net."} {
		record := response.Answer[i].(*dns.MX)
		assert.Equal(t, exchange, record.Mx)
		assert.Equal(t, uint16((i+1)*10), record.Preference)
		assert.Equal(t, uint32(600), record.Hdr.TTL)
		assert.Equal(t, "LANCERT.DEV.", record.Hdr.Name)
	}

	// MX-only owners exist even when queried for a type without a record.
	response = query(t, addr, "mail.lancert.dev.", dns.TypeMX)
	require.Len(t, response.Answer, 1)
	assert.Equal(t, uint32(300), response.Answer[0].Header().TTL)
	for _, qtype := range []uint16{dns.TypeA, dns.TypeTXT} {
		response = query(t, addr, "mail.lancert.dev.", qtype)
		assert.Equal(t, uint16(dns.RcodeSuccess), response.Rcode)
		assert.Empty(t, response.Answer)
		require.Len(t, response.Ns, 1)
	}

	// Apex mail routes must not spread to registered or wildcard hostnames.
	for _, name := range []string{testHostname + ".lancert.dev.", "www." + testHostname + ".lancert.dev.", "ns1.lancert.dev."} {
		response = query(t, addr, name, dns.TypeMX)
		assert.Equal(t, uint16(dns.RcodeSuccess), response.Rcode)
		assert.Empty(t, response.Answer)
		require.Len(t, response.Ns, 1)
	}
	response = query(t, addr, "unknown.lancert.dev.", dns.TypeMX)
	assert.Equal(t, uint16(dns.RcodeNameError), response.Rcode)
}

func TestStaticMXUnset(t *testing.T) {
	server := New(Config{Zone: testZone}, nil)
	response := new(dns.Msg)
	server.answer(response, &dns.MX{Hdr: dns.Header{Name: testZone, Class: dns.ClassINET}})
	assert.Equal(t, uint16(dns.RcodeSuccess), response.Rcode)
	assert.Empty(t, response.Answer)
	require.Len(t, response.Ns, 1)
}

func TestRecorderTracksDNSAndRegistrationActivity(t *testing.T) {
	recorder := &testRecorder{}
	_, addr, _ := startTestServer(t, recorder)
	query(t, addr, testHostname+".lancert.dev.", dns.TypeA)
	query(t, addr, "unknownunknownunknown2.lancert.dev.", dns.TypeA)
	query(t, addr, "_acme-challenge."+testHostname+".lancert.dev.", dns.TypeTXT)

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	assert.Equal(t, []string{
		"01900000-0000-7000-8000-000000000000",
		"",
		"01900000-0000-7000-8000-000000000000",
	}, recorder.registrations)
	assert.Equal(t, 3, recorder.responses)
}

func TestSplitTXTValue(t *testing.T) {
	value := strings.Repeat("a", 300)
	assert.Equal(t, []string{strings.Repeat("a", 255), strings.Repeat("a", 45)}, splitTXTValue(value))
}

func TestRelativeLabelsAndHostnameValidation(t *testing.T) {
	labels, ok := relativeLabels(testHostname+".lancert.dev.", testZone)
	assert.True(t, ok)
	assert.Equal(t, []string{testHostname}, labels)
	_, ok = relativeLabels("example.com.", testZone)
	assert.False(t, ok)
	assert.True(t, validHostname(testHostname))
	assert.True(t, validHostname("quiet-otter-k7"))
	assert.False(t, validHostname("Quiet-otter"))
}
