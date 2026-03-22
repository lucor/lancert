package dnssrv

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testZone = "lancert.dev."

// startTestServer launches a DNS server on a random port and returns
// the address and a cleanup function.
func startTestServer(t *testing.T) (*Server, string) {
	t.Helper()

	store := NewTXTStore()
	cfg := Config{
		Zone:       testZone,
		NSRecords:  []string{"ns1.lancert.dev.", "ns2.lancert.dev."},
		ServerIP:   netip.MustParseAddr("5.9.100.1"),
		SOAMname:   "ns1.lancert.dev.",
		SOARname:   "admin.lancert.dev.",
		CAAIssuers: []string{"letsencrypt.org"},
	}

	srv := New(cfg, store)

	// Start on random port
	mux := dns.NewServeMux()
	mux.HandleFunc(cfg.Zone, srv.handleQuery)

	srv.udp = &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}

	started := make(chan struct{})
	srv.udp.NotifyStartedFunc = func() { close(started) }

	go func() {
		if err := srv.udp.ListenAndServe(); err != nil {
			t.Logf("test dns server: %v", err)
		}
	}()

	<-started

	addr := srv.PacketConnAddr().String()
	t.Cleanup(func() { srv.Shutdown() })

	return srv, addr
}

// query sends a DNS query and returns the response.
func query(t *testing.T, addr string, name string, qtype uint16) *dns.Msg {
	t.Helper()

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)

	r, _, err := c.Exchange(m, addr)
	require.NoError(t, err)
	return r
}

func TestDNS_A_PrivateIP(t *testing.T) {
	_, addr := startTestServer(t)

	r := query(t, addr, "192-168-1-50.lancert.dev.", dns.TypeA)
	require.Len(t, r.Answer, 1)

	a, ok := r.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "192.168.1.50", a.A.String())
}

func TestDNS_A_Subdomain(t *testing.T) {
	_, addr := startTestServer(t)

	// foo.192-168-1-50.lancert.dev should also resolve
	r := query(t, addr, "foo.192-168-1-50.lancert.dev.", dns.TypeA)
	require.Len(t, r.Answer, 1)

	a, ok := r.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "192.168.1.50", a.A.String())
}

func TestDNS_A_ZoneApex(t *testing.T) {
	_, addr := startTestServer(t)

	r := query(t, addr, "lancert.dev.", dns.TypeA)
	require.Len(t, r.Answer, 1)

	a, ok := r.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "5.9.100.1", a.A.String())
}

func TestDNS_A_PublicIP_NXDOMAIN(t *testing.T) {
	_, addr := startTestServer(t)

	r := query(t, addr, "8-8-8-8.lancert.dev.", dns.TypeA)
	assert.Equal(t, dns.RcodeNameError, r.Rcode)
	assert.Empty(t, r.Answer)
}

func TestDNS_TXT_ChallengeRecord(t *testing.T) {
	srv, addr := startTestServer(t)
	ctx := context.Background()

	fqdn := "_acme-challenge.192-168-1-50.lancert.dev."

	// Add two challenge values (bare + wildcard)
	cleanup1, err := srv.txtStore.SetTXTWithCleanup(ctx, fqdn, "token-bare", 120*time.Second)
	require.NoError(t, err)
	cleanup2, err := srv.txtStore.SetTXTWithCleanup(ctx, fqdn, "token-wild", 120*time.Second)
	require.NoError(t, err)

	r := query(t, addr, fqdn, dns.TypeTXT)
	require.Len(t, r.Answer, 2)

	var values []string
	for _, rr := range r.Answer {
		txt, ok := rr.(*dns.TXT)
		require.True(t, ok)
		values = append(values, txt.Txt...)
	}
	assert.ElementsMatch(t, []string{"token-bare", "token-wild"}, values)

	// Cleanup both
	require.NoError(t, cleanup1(ctx))
	require.NoError(t, cleanup2(ctx))

	r = query(t, addr, fqdn, dns.TypeTXT)
	assert.Empty(t, r.Answer)
}

func TestDNS_SOA(t *testing.T) {
	_, addr := startTestServer(t)

	r := query(t, addr, "lancert.dev.", dns.TypeSOA)
	require.Len(t, r.Answer, 1)

	soa, ok := r.Answer[0].(*dns.SOA)
	require.True(t, ok)
	assert.Equal(t, "ns1.lancert.dev.", soa.Ns)
}

func TestDNS_NS(t *testing.T) {
	_, addr := startTestServer(t)

	r := query(t, addr, "lancert.dev.", dns.TypeNS)
	require.Len(t, r.Answer, 2)
}

func TestDNS_CAA(t *testing.T) {
	_, addr := startTestServer(t)

	r := query(t, addr, "lancert.dev.", dns.TypeCAA)
	require.Len(t, r.Answer, 1)

	caa, ok := r.Answer[0].(*dns.CAA)
	require.True(t, ok)
	assert.Equal(t, "issue", caa.Tag)
	assert.Equal(t, "letsencrypt.org", caa.Value)
}

func TestExtractIPLabel(t *testing.T) {
	tests := []struct {
		name string
		fqdn string
		want string
	}{
		{name: "bare", fqdn: "192-168-1-50.lancert.dev.", want: "192-168-1-50"},
		{name: "sub", fqdn: "app.192-168-1-50.lancert.dev.", want: "192-168-1-50"},
		{name: "deep sub", fqdn: "a.b.192-168-1-50.lancert.dev.", want: "192-168-1-50"},
		{name: "challenge", fqdn: "_acme-challenge.192-168-1-50.lancert.dev.", want: "192-168-1-50"},
		{name: "apex", fqdn: "lancert.dev.", want: ""},
		{name: "other zone", fqdn: "example.com.", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractIPLabel(tt.fqdn, testZone))
		})
	}
}
