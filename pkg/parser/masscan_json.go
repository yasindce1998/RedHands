package parser

import (
	"encoding/json"
	"fmt"
)

// MasscanJSONParser parses masscan JSON output.
type MasscanJSONParser struct{}

func (p *MasscanJSONParser) Name() string { return "masscan_json" }

func (p *MasscanJSONParser) Parse(data []byte) (json.RawMessage, error) {
	var raw []masscanRawEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("masscan json parse: %w", err)
	}

	hosts := make(map[string]*masscanHost)

	for _, entry := range raw {
		ip := entry.IP
		if ip == "" {
			continue
		}

		host, ok := hosts[ip]
		if !ok {
			host = &masscanHost{Address: ip}
			hosts[ip] = host
		}

		for _, port := range entry.Ports {
			host.Ports = append(host.Ports, masscanPort{
				Port:     port.Port,
				Protocol: port.Proto,
				State:    port.Status,
				TTL:      port.TTL,
			})
		}
	}

	result := masscanResult{
		TotalHosts: len(hosts),
		Hosts:      make([]masscanHost, 0, len(hosts)),
	}
	for _, h := range hosts {
		result.Hosts = append(result.Hosts, *h)
	}

	return json.Marshal(result)
}

type masscanRawEntry struct {
	IP    string            `json:"ip"`
	Ports []masscanRawPort  `json:"ports"`
}

type masscanRawPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
	TTL    int    `json:"ttl"`
}

type masscanResult struct {
	TotalHosts int            `json:"total_hosts"`
	Hosts      []masscanHost  `json:"hosts"`
}

type masscanHost struct {
	Address string        `json:"address"`
	Ports   []masscanPort `json:"ports,omitempty"`
}

type masscanPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	TTL      int    `json:"ttl,omitempty"`
}
