package app

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yasindce1998/redhands/pkg/targetdb"
	"github.com/yasindce1998/redhands/pkg/workflow"
)

// CampaignRecorder persists structured campaign output into the target
// database. Hosts, services, credentials, and findings recorded by campaign
// record rules become queryable via the targetdb_* tools and feed the attack
// graph.
type CampaignRecorder struct {
	db *targetdb.Store
}

// NewCampaignRecorder wraps a target database store.
func NewCampaignRecorder(db *targetdb.Store) *CampaignRecorder {
	return &CampaignRecorder{db: db}
}

// RecordStep implements workflow.StepRecorder.
func (r *CampaignRecorder) RecordStep(workflowID, stepID, tool string, rule workflow.RecordRule, items []any, stepMITRE []string) error {
	if r.db == nil {
		return fmt.Errorf("target database not configured")
	}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		field := func(name string) string {
			relPath, ok := rule.Fields[name]
			if !ok {
				return ""
			}
			value, ok := workflow.LookupPathValue(object, relPath)
			if !ok {
				return ""
			}
			return strings.TrimSpace(workflow.ValueToString(value))
		}
		campaignTag := "campaign:" + workflowID
		switch rule.Type {
		case "host":
			ip := field("ip")
			if ip == "" {
				continue
			}
			if err := r.db.AddHost(&targetdb.Host{
				IP:        ip,
				Hostname:  field("hostname"),
				OS:        field("os"),
				Tags:      []string{campaignTag},
				FirstSeen: time.Now().UTC(),
				LastSeen:  time.Now().UTC(),
			}); err != nil {
				return err
			}
		case "service":
			host := field("host")
			port, err := strconv.Atoi(field("port"))
			if host == "" || err != nil || port < 1 || port > 65535 {
				continue
			}
			protocol := field("protocol")
			if protocol == "" {
				protocol = "tcp"
			}
			if err := r.db.AddService(&targetdb.Service{
				Host:     host,
				Port:     port,
				Protocol: protocol,
				Name:     field("name"),
				Version:  field("version"),
				Banner:   field("banner"),
			}); err != nil {
				return err
			}
		case "credential":
			username := field("username")
			secret := field("secret")
			if username == "" || secret == "" {
				continue
			}
			credType := field("type")
			if credType == "" {
				credType = "password"
			}
			if err := r.db.AddCredential(&targetdb.Credential{
				Host:     field("host"),
				Username: username,
				Secret:   secret,
				Type:     credType,
				Domain:   field("domain"),
				Source:   tool,
			}); err != nil {
				return err
			}
		case "finding":
			host := field("host")
			if host == "" {
				host = "unknown"
			}
			severity := strings.ToLower(field("severity"))
			if severity == "" {
				severity = "info"
			}
			mitre := stepMITRE
			if custom := field("mitre"); custom != "" {
				for _, id := range strings.Split(custom, ",") {
					id = strings.TrimSpace(id)
					if workflow.ValidMITREID(id) {
						mitre = append(mitre, id)
					}
				}
			}
			if err := r.db.AddFinding(&targetdb.Finding{
				Host:        host,
				Tool:        tool,
				Severity:    severity,
				Title:       field("title"),
				Description: field("description"),
				Evidence:    field("evidence"),
				MITRE:       mitre,
				Timestamp:   time.Now().UTC(),
			}); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported record type %q", rule.Type)
		}
	}
	return nil
}
