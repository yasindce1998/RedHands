package parser

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
)

// NmapXMLParser parses nmap XML output into structured JSON.
type NmapXMLParser struct{}

func (p *NmapXMLParser) Name() string { return "nmap_xml" }

func (p *NmapXMLParser) Parse(data []byte) (json.RawMessage, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("nmap xml parse: %w", err)
	}

	result := nmapResult{
		Scanner:  run.Scanner,
		Args:     run.Args,
		StartStr: run.StartStr,
		Hosts:    make([]nmapHost, 0, len(run.Hosts)),
	}

	for _, h := range run.Hosts {
		host := nmapHost{}
		for _, addr := range h.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				host.Address = addr.Addr
				break
			}
		}
		for _, hn := range h.Hostnames {
			if hn.Name != "" {
				host.Hostname = hn.Name
				break
			}
		}

		if h.Ports != nil {
			for _, port := range h.Ports.Ports {
				host.Ports = append(host.Ports, nmapPort{
					Port:     port.PortID,
					Protocol: port.Protocol,
					State:    port.State.State,
					Service:  port.Service.Name,
					Product:  port.Service.Product,
					Version:  port.Service.Version,
				})
			}
		}

		if h.OS != nil {
			for _, m := range h.OS.Matches {
				host.OS = append(host.OS, nmapOSMatch{
					Name:     m.Name,
					Accuracy: m.Accuracy,
				})
			}
		}

		result.Hosts = append(result.Hosts, host)
	}

	return json.Marshal(result)
}

// XML structures for nmap output
type nmapRun struct {
	XMLName  xml.Name       `xml:"nmaprun"`
	Scanner  string         `xml:"scanner,attr"`
	Args     string         `xml:"args,attr"`
	StartStr string         `xml:"startstr,attr"`
	Hosts    []nmapXMLHost  `xml:"host"`
}

type nmapXMLHost struct {
	Addresses []nmapXMLAddr     `xml:"address"`
	Hostnames []nmapXMLHostname `xml:"hostnames>hostname"`
	Ports     *nmapXMLPorts     `xml:"ports"`
	OS        *nmapXMLOS        `xml:"os"`
}

type nmapXMLAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapXMLHostname struct {
	Name string `xml:"name,attr"`
}

type nmapXMLPorts struct {
	Ports []nmapXMLPort `xml:"port"`
}

type nmapXMLPort struct {
	Protocol string         `xml:"protocol,attr"`
	PortID   int            `xml:"portid,attr"`
	State    nmapXMLState   `xml:"state"`
	Service  nmapXMLService `xml:"service"`
}

type nmapXMLState struct {
	State string `xml:"state,attr"`
}

type nmapXMLService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type nmapXMLOS struct {
	Matches []nmapXMLOSMatch `xml:"osmatch"`
}

type nmapXMLOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

// JSON output structures
type nmapResult struct {
	Scanner  string     `json:"scanner"`
	Args     string     `json:"args"`
	StartStr string     `json:"start"`
	Hosts    []nmapHost `json:"hosts"`
}

type nmapHost struct {
	Address  string       `json:"address"`
	Hostname string       `json:"hostname,omitempty"`
	Ports    []nmapPort   `json:"ports,omitempty"`
	OS       []nmapOSMatch `json:"os,omitempty"`
}

type nmapPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
}

type nmapOSMatch struct {
	Name     string `json:"name"`
	Accuracy int    `json:"accuracy"`
}
