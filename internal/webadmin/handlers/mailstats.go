package handlers

import (
	"math"
	"net/http"
	"sort"

	"github.com/infodancer/maildancer/internal/webadmin/promclient"
	"github.com/infodancer/maildancer/internal/webadmin/session"
	"log/slog"
)

// MailStatsHandler handles GET /api/mailstats.
type MailStatsHandler struct {
	prom     *promclient.Client
	sessions *session.Store
	logger   *slog.Logger
}

// NewMailStatsHandler creates a MailStatsHandler.
func NewMailStatsHandler(prom *promclient.Client, sessions *session.Store, logger *slog.Logger) *MailStatsHandler {
	return &MailStatsHandler{prom: prom, sessions: sessions, logger: logger}
}

// domainCount is a domain name with a message count.
type domainCount struct {
	Domain string  `json:"domain"`
	Count  float64 `json:"count"`
}

// mailStatsResponse is the JSON response for GET /api/mailstats.
type mailStatsResponse struct {
	Available bool `json:"available"`

	ActiveConnections struct {
		SMTP float64 `json:"smtp"`
		POP3 float64 `json:"pop3"`
		IMAP float64 `json:"imap"`
	} `json:"active_connections"`

	Incoming24h struct {
		Total    float64       `json:"total"`
		ByDomain []domainCount `json:"by_domain"`
	} `json:"incoming_24h"`

	Verdict24h struct {
		Ham   float64 `json:"ham"`
		Spam  float64 `json:"spam"`
		Maybe float64 `json:"maybe"` // soft_reject + greylist
	} `json:"verdict_24h"`

	AcceptReject24h struct {
		Accepted float64 `json:"accepted"`
		Rejected float64 `json:"rejected"`
	} `json:"accept_reject_24h"`

	Delivery24h struct {
		Success     float64 `json:"success"`
		TempFailure float64 `json:"temp_failure"`
		PermFailure float64 `json:"perm_failure"`
	} `json:"delivery_24h"`
}

// HandleGetMailStats serves GET /api/mailstats.
func (h *MailStatsHandler) HandleGetMailStats(w http.ResponseWriter, r *http.Request) {
	resp := mailStatsResponse{}

	if !h.prom.Available() {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	ctx := r.Context()
	resp.Available = true

	// Active connections (instant gauges).
	resp.ActiveConnections.SMTP = round(h.prom.Scalar(ctx, "smtpd_connections_active"))
	resp.ActiveConnections.POP3 = round(h.prom.Scalar(ctx, "pop3d_connections_active"))
	resp.ActiveConnections.IMAP = round(h.prom.Scalar(ctx, "imapd_connections_active"))

	// Incoming messages over last 24h — total and per domain.
	resp.Incoming24h.Total = round(h.prom.Scalar(ctx, `sum(increase(smtpd_messages_received_total[24h]))`))

	byDomain := h.prom.LabelValues(ctx,
		`sum by (recipient_domain)(increase(smtpd_messages_received_total[24h]))`,
		"recipient_domain")
	for domain, count := range byDomain {
		resp.Incoming24h.ByDomain = append(resp.Incoming24h.ByDomain, domainCount{
			Domain: domain,
			Count:  round(count),
		})
	}
	sort.Slice(resp.Incoming24h.ByDomain, func(i, j int) bool {
		return resp.Incoming24h.ByDomain[i].Count > resp.Incoming24h.ByDomain[j].Count
	})
	if resp.Incoming24h.ByDomain == nil {
		resp.Incoming24h.ByDomain = []domainCount{}
	}

	// Ham / spam / maybe verdicts from rspamd.
	verdicts := h.prom.LabelValues(ctx,
		`sum by (result)(increase(smtpd_rspamd_checks_total[24h]))`,
		"result")
	resp.Verdict24h.Ham = round(verdicts["ham"])
	resp.Verdict24h.Spam = round(verdicts["spam"])
	resp.Verdict24h.Maybe = round(verdicts["soft_reject"] + verdicts["greylist"])

	// Accept vs reject.
	resp.AcceptReject24h.Accepted = resp.Incoming24h.Total
	resp.AcceptReject24h.Rejected = round(h.prom.Scalar(ctx, `sum(increase(smtpd_messages_rejected_total[24h]))`))

	// Local delivery results.
	delivery := h.prom.LabelValues(ctx,
		`sum by (result)(increase(smtpd_deliveries_total[24h]))`,
		"result")
	resp.Delivery24h.Success = round(delivery["success"])
	resp.Delivery24h.TempFailure = round(delivery["temp_failure"])
	resp.Delivery24h.PermFailure = round(delivery["perm_failure"])

	writeJSON(w, http.StatusOK, resp)
}

// round rounds to the nearest integer as a float64, avoiding -0.
func round(v float64) float64 {
	r := math.Round(v)
	if r == 0 {
		return 0
	}
	return r
}
