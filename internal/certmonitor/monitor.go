// Package certmonitor polls SSLMate's indexed CT search for Lancert issuances.
package certmonitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"go.lucor.dev/lancert/internal/metrics"
	"go.lucor.dev/lancert/internal/registration"
)

const (
	issuanceURL     = "https://api.certspotter.com/v1/issuances"
	defaultInterval = time.Hour
	requestTimeout  = 15 * time.Second
	maxResponseSize = 8 << 20
	maxPagesPerPoll = 10
)

type revocation struct {
	Time      *time.Time `json:"time"`
	CheckedAt *time.Time `json:"checked_at"`
}

type issuance struct {
	ID         string      `json:"id"`
	TBS        string      `json:"tbs_sha256"`
	DNSNames   []string    `json:"dns_names"`
	NotBefore  time.Time   `json:"not_before"`
	NotAfter   time.Time   `json:"not_after"`
	Revoked    *bool       `json:"revoked"`
	Revocation *revocation `json:"revocation"`
	Issuer     struct {
		FriendlyName string   `json:"friendly_name"`
		CAADomains   []string `json:"caa_domains"`
	} `json:"issuer"`
}

type issuanceStore interface {
	InitializeSSLMate(context.Context, time.Time) error
	BeginSSLMatePoll(context.Context, time.Time) (bool, error)
	SSLMateState(context.Context) (after string, complete bool, err error)
	SSLMateRevocationState(context.Context, time.Time) (after string, due bool, err error)
	RecordSSLMatePage(context.Context, []metrics.CertificateIssuance, string, bool) error
	RecordSSLMateRevocationPage(context.Context, []metrics.CertificateIssuance, string, bool) error
	SetSSLMateMonitorStatus(context.Context, time.Time, error) error
	RebuildSnapshot(context.Context) error
}

// Monitor consumes SSLMate's discovery cursor. The token is only read from the
// deployment environment and is never included in errors or logs.
type Monitor struct {
	store         issuanceStore
	zone, token   string
	endpoint      string
	client        *http.Client
	interval      time.Duration
	registrations func(context.Context) ([]registration.CertificateRegistration, error)
}

// New creates a best-effort monitor for one registered zone.
func New(store issuanceStore, zone, token string, since time.Time, registrations func(context.Context) ([]registration.CertificateRegistration, error)) (*Monitor, error) {
	if store == nil || registrations == nil {
		return nil, errors.New("certificate monitor requires metrics and registration stores")
	}
	zone = strings.Trim(strings.ToLower(strings.TrimSpace(zone)), ".")
	if zone == "" {
		return nil, errors.New("certificate monitor requires a DNS zone")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("SSLMATE_API_KEY is required")
	}
	if err := store.InitializeSSLMate(context.Background(), since); err != nil {
		return nil, fmt.Errorf("initialize SSLMate monitor: %w", err)
	}
	return &Monitor{store: store, zone: zone, token: token, endpoint: issuanceURL, registrations: registrations, client: &http.Client{Timeout: requestTimeout}, interval: defaultInterval}, nil
}

// Run performs a catch-up immediately and then polls hourly to stay within the
// API's full-domain query budget, retrying failures on the next interval.
func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		if err := m.Poll(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("SSLMate CT poll failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Poll pages the complete initial unexpired snapshot, then uses SSLMate's
// opaque discovery cursor to fetch only later issuances.
func (m *Monitor) Poll(ctx context.Context) error {
	claimed, err := m.store.BeginSSLMatePoll(ctx, time.Now().UTC())
	if err != nil {
		return m.finish(ctx, err)
	}
	if !claimed {
		return nil
	}
	after, complete, err := m.store.SSLMateState(ctx)
	if err != nil {
		return m.finish(ctx, err)
	}
	var refreshAfter string
	var refreshDue bool
	if complete {
		refreshAfter, refreshDue, err = m.store.SSLMateRevocationState(ctx, time.Now().UTC())
		if err != nil {
			return m.finish(ctx, err)
		}
	}
	// Discovery runs first; revocation refreshes use only the remaining hourly
	// allowance so refresh failures cannot block new certificate observations.
	used, err := m.pollIssuances(ctx, after, complete)
	if err == nil && refreshDue && used < maxPagesPerPoll {
		err = m.pollRevocations(ctx, refreshAfter, maxPagesPerPoll-used)
	}
	return m.finish(ctx, err)
}

// pollIssuances saves discovery pages and reports requests used so refreshes
// can use the remaining hourly allowance without exceeding it.
func (m *Monitor) pollIssuances(ctx context.Context, after string, complete bool) (int, error) {
	registrations, err := m.registrations(ctx)
	if err != nil {
		return 0, fmt.Errorf("load registered hostnames: %w", err)
	}
	for pageNumber := 0; pageNumber < maxPagesPerPoll; pageNumber++ {
		page, err := m.fetch(ctx, after)
		if err != nil {
			return pageNumber + 1, err
		}
		if len(page) == 0 {
			if !complete {
				if err := m.store.RecordSSLMatePage(ctx, nil, after, true); err != nil {
					return pageNumber + 1, err
				}
			}
			return pageNumber + 1, nil
		}
		stored := make([]metrics.CertificateIssuance, 0, len(page))
		for _, item := range page {
			if item.ID == "" || item.TBS == "" {
				return pageNumber + 1, errors.New("SSLMate returned issuance without id or tbs_sha256")
			}
			names := normalizeNames(item.DNSNames)
			if !matchesZone(names, m.zone) {
				continue
			}
			matched := matchRegistrations(names, registrations, m.zone)
			if len(matched) == 0 {
				continue
			}
			stored = append(stored, metrics.CertificateIssuance{TBS: item.TBS, Issuer: item.Issuer.FriendlyName, CAADomains: normalizeNames(item.Issuer.CAADomains), DNSNames: names, NotBefore: item.NotBefore, NotAfter: item.NotAfter, Revoked: item.Revoked, RevocationTime: revocationObservedAt(item.Revocation), RevocationCheckedAt: revocationCheckedAt(item.Revocation), Registrations: matched})
		}
		after = page[len(page)-1].ID
		if err := m.store.RecordSSLMatePage(ctx, stored, after, false); err != nil {
			return pageNumber + 1, err
		}
	}
	// Persisted cursors let the next run resume when this window is exhausted.
	return maxPagesPerPoll, nil
}

// pollRevocations refreshes existing certificate states from a full domain
// snapshot. It shares the hourly request reservation with discovery, so one
// invocation can never exceed SSLMate's ten full-domain queries per hour.
func (m *Monitor) pollRevocations(ctx context.Context, after string, maxPages int) error {
	for pageNumber := 0; pageNumber < maxPages; pageNumber++ {
		page, err := m.fetch(ctx, after)
		if err != nil {
			return err
		}
		if len(page) == 0 {
			if err := m.store.RecordSSLMateRevocationPage(ctx, nil, "", true); err != nil {
				return err
			}
			return nil
		}
		events := make([]metrics.CertificateIssuance, 0, len(page))
		for _, item := range page {
			if item.ID == "" || item.TBS == "" {
				return errors.New("SSLMate returned issuance without id or tbs_sha256")
			}
			events = append(events, metrics.CertificateIssuance{TBS: item.TBS, Revoked: item.Revoked, RevocationTime: revocationObservedAt(item.Revocation), RevocationCheckedAt: revocationCheckedAt(item.Revocation)})
		}
		after = page[len(page)-1].ID
		if err := m.store.RecordSSLMateRevocationPage(ctx, events, after, false); err != nil {
			return err
		}
	}
	return nil
}

func revocationObservedAt(revocation *revocation) *time.Time {
	if revocation == nil {
		return nil
	}
	return revocation.Time
}

func revocationCheckedAt(revocation *revocation) *time.Time {
	if revocation == nil {
		return nil
	}
	return revocation.CheckedAt
}

func (m *Monitor) fetch(ctx context.Context, after string) ([]issuance, error) {
	query := url.Values{"domain": {m.zone}, "include_subdomains": {"true"}, "match_wildcards": {"true"}, "expand": {"dns_names", "issuer", "issuer.caa_domains", "revocation"}}
	if after != "" {
		query.Set("after", after)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query SSLMate CT search: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query SSLMate CT search: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read SSLMate response: %w", err)
	}
	if len(body) > maxResponseSize {
		return nil, errors.New("SSLMate response exceeds size limit")
	}
	var page []issuance
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("decode SSLMate response: %w", err)
	}
	return page, nil
}

func (m *Monitor) finish(ctx context.Context, pollErr error) error {
	if statusErr := m.store.SetSSLMateMonitorStatus(ctx, time.Now().UTC(), pollErr); statusErr != nil {
		pollErr = errors.Join(pollErr, statusErr)
	}
	if rebuildErr := m.store.RebuildSnapshot(ctx); rebuildErr != nil {
		pollErr = errors.Join(pollErr, rebuildErr)
	}
	return pollErr
}

func normalizeNames(names []string) []string {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name != "" {
			set[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func matchesZone(names []string, zone string) bool {
	for _, name := range names {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}
	return false
}

func matchRegistrations(names []string, registrations []registration.CertificateRegistration, zone string) []metrics.RegistrationIssuance {
	matched := make([]metrics.RegistrationIssuance, 0)
	for _, registration := range registrations {
		fqdn := strings.Trim(strings.ToLower(registration.Hostname), ".") + "." + zone
		wildcard := "*." + fqdn
		for _, name := range names {
			if name == fqdn || name == wildcard {
				matched = append(matched, metrics.RegistrationIssuance{Hostname: registration.Hostname})
				break
			}
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Hostname < matched[j].Hostname })
	return matched
}
