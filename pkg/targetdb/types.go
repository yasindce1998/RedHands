package targetdb

import (
	"encoding/json"
	"time"
)

type Host struct {
	IP        string            `json:"ip"`
	Hostname  string            `json:"hostname,omitempty"`
	OS        string            `json:"os,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
}

type Service struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

type Credential struct {
	ID       string `json:"id"`
	Host     string `json:"host,omitempty"`
	Username string `json:"username"`
	Secret   string `json:"secret"`
	Type     string `json:"type"`
	Domain   string `json:"domain,omitempty"`
	Source   string `json:"source"`
	Valid    bool   `json:"valid"`
}

type Finding struct {
	ID          string          `json:"id"`
	Host        string          `json:"host"`
	Tool        string          `json:"tool"`
	Severity    string          `json:"severity"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Evidence    string          `json:"evidence,omitempty"`
	MITRE       []string        `json:"mitre,omitempty"`
	RiskScore   float64         `json:"risk_score,omitempty"`
	Timestamp   time.Time       `json:"timestamp"`
	Raw         json.RawMessage `json:"raw,omitempty"`
}

type Snapshot struct {
	Hosts       map[string]*Host      `json:"hosts"`
	Services    map[string][]*Service `json:"services"`
	Credentials []*Credential         `json:"credentials"`
	Findings    []*Finding            `json:"findings"`
}
