package dnssrv

import (
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lucor.dev/lancert/internal/registration"
)

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
		Recorder: recorder,
	}
	srv := New(cfg, state)
	srv.udp = &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: srv.mux}
	started := make(chan struct{})
	srv.udp.NotifyStartedFunc = func() { close(started) }
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
	request.SetQuestion(dns.Fqdn(name), qtype)
	response, _, err := new(dns.Client).Exchange(request, addr)
	require.NoError(t, err)
	return response
}

func TestRejectsMultipleQuestions(t *testing.T) {
	_, addr, _ := startTestServer(t, nil)
	request := new(dns.Msg)
	request.Question = []dns.Question{
		{Name: testZone, Qtype: dns.TypeSOA, Qclass: dns.ClassINET},
		{Name: testHostname + "." + testZone, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	response, _, err := new(dns.Client).Exchange(request, addr)
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeFormatError, response.Rcode)
	assert.Empty(t, response.Answer)
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
		assert.Equal(t, "192.168.1.50", record.A.String())
		assert.Equal(t, uint32(300), record.Hdr.Ttl)
	}
}

func TestRegistrationOwnerBoundaries(t *testing.T) {
	_, addr, _ := startTestServer(t, nil)

	challengeA := query(t, addr, "_acme-challenge."+testHostname+".lancert.dev.", dns.TypeA)
	assert.Equal(t, dns.RcodeSuccess, challengeA.Rcode)
	assert.Empty(t, challengeA.Answer)
	require.Len(t, challengeA.Ns, 1)

	for _, name := range []string{
		"foo.bar." + testHostname + ".lancert.dev.",
		"unknownunknownunknown2.lancert.dev.",
		"192-168-1-50.lancert.dev.",
	} {
		response := query(t, addr, name, dns.TypeA)
		assert.Equal(t, dns.RcodeNameError, response.Rcode)
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
		assert.Equal(t, uint32(1), record.Hdr.Ttl)
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
	assert.Equal(t, dns.RcodeSuccess, response.Rcode)
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
		assert.Equal(t, dns.RcodeNameError, response.Rcode)
	}
}

func TestInfrastructureStaticAndNoCAA(t *testing.T) {
	_, addr, _ := startTestServer(t, nil)

	apex := query(t, addr, testZone, dns.TypeA)
	require.Len(t, apex.Answer, 1)
	assert.Equal(t, "5.9.100.1", apex.Answer[0].(*dns.A).A.String())

	ns := query(t, addr, testZone, dns.TypeNS)
	require.Len(t, ns.Answer, 2)
	soa := query(t, addr, testZone, dns.TypeSOA)
	require.Len(t, soa.Answer, 1)
	static := query(t, addr, testZone, dns.TypeTXT)
	require.Len(t, static.Answer, 1)
	assert.Equal(t, uint32(600), static.Answer[0].Header().Ttl)

	caa := query(t, addr, testZone, dns.TypeCAA)
	assert.Equal(t, dns.RcodeSuccess, caa.Rcode)
	assert.Empty(t, caa.Answer)
	require.Len(t, caa.Ns, 1)
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
