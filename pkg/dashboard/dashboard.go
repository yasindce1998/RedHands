package dashboard

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/yasindce1998/redhands/pkg/targetdb"
)

//go:embed static
var staticFiles embed.FS

type StatusResponse struct {
	Hosts          int              `json:"hosts"`
	Findings       int              `json:"findings"`
	Credentials    int              `json:"credentials"`
	Critical       int              `json:"critical"`
	RecentFindings []*targetdb.Finding `json:"recent_findings"`
}

type Dashboard struct {
	store *targetdb.Store
	mux   *http.ServeMux
}

func New(store *targetdb.Store) *Dashboard {
	d := &Dashboard{
		store: store,
		mux:   http.NewServeMux(),
	}

	staticFS, _ := fs.Sub(staticFiles, "static")
	d.mux.Handle("/dashboard/", http.StripPrefix("/dashboard/", http.FileServer(http.FS(staticFS))))
	d.mux.HandleFunc("/api/status", d.handleStatus)

	return d
}

func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mux.ServeHTTP(w, r)
}

func (d *Dashboard) handleStatus(w http.ResponseWriter, r *http.Request) {
	findings := d.store.QueryFindings("", "", "")

	critical := 0
	for _, f := range findings {
		if f.Severity == "critical" {
			critical++
		}
	}

	recent := findings
	if len(recent) > 20 {
		recent = recent[len(recent)-20:]
	}

	resp := StatusResponse{
		Hosts:          len(d.store.ListHosts()),
		Findings:       len(findings),
		Credentials:    len(d.store.ListCredentials()),
		Critical:       critical,
		RecentFindings: recent,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
