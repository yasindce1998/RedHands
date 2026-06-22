package nmap

import "encoding/xml"

type NmapRun struct {
	XMLName          xml.Name `xml:"nmaprun"`
	Scanner          string   `xml:"scanner,attr"`
	Args             string   `xml:"args,attr"`
	Start            int64    `xml:"start,attr"`
	StartStr         string   `xml:"startstr,attr"`
	Version          string   `xml:"version,attr"`
	XMLOutputVersion string   `xml:"xmloutputversion,attr"`
	ScanInfo         ScanInfo `xml:"scaninfo"`
	Hosts            []Host   `xml:"host"`
	RunStats         RunStats `xml:"runstats"`
}

type ScanInfo struct {
	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices int    `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
}

type Host struct {
	StartTime int64      `xml:"starttime,attr"`
	EndTime   int64      `xml:"endtime,attr"`
	Status    HostStatus `xml:"status"`
	Addresses []Address  `xml:"address"`
	Hostnames []Hostname `xml:"hostnames>hostname"`
	Ports     []Port     `xml:"ports>port"`
	OS        OS         `xml:"os"`
	Scripts   []Script   `xml:"hostscript>script"`
}

type HostStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type Port struct {
	Protocol string   `xml:"protocol,attr"`
	PortID   int      `xml:"portid,attr"`
	State    State    `xml:"state"`
	Service  Service  `xml:"service"`
	Scripts  []Script `xml:"script"`
}

type State struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type Service struct {
	Name       string `xml:"name,attr"`
	Product    string `xml:"product,attr"`
	Version    string `xml:"version,attr"`
	ExtraInfo  string `xml:"extrainfo,attr"`
	Method     string `xml:"method,attr"`
	Conf       int    `xml:"conf,attr"`
	CPE        string `xml:"cpe,attr"`
	Tunnel     string `xml:"tunnel,attr"`
	OSType     string `xml:"ostype,attr"`
	DeviceType string `xml:"devicetype,attr"`
}

type OS struct {
	PortsUsed []PortUsed  `xml:"portused"`
	Matches   []OSMatch   `xml:"osmatch"`
	Classes   []OSClass   `xml:"osclass"`
}

type PortUsed struct {
	State  string `xml:"state,attr"`
	Proto  string `xml:"proto,attr"`
	PortID int    `xml:"portid,attr"`
}

type OSMatch struct {
	Name     string    `xml:"name,attr"`
	Accuracy int       `xml:"accuracy,attr"`
	Classes  []OSClass `xml:"osclass"`
}

type OSClass struct {
	Type     string `xml:"type,attr"`
	Vendor   string `xml:"vendor,attr"`
	Family   string `xml:"osfamily,attr"`
	Gen      string `xml:"osgen,attr"`
	Accuracy int    `xml:"accuracy,attr"`
	CPEs     []CPE  `xml:"cpe"`
}

type CPE struct {
	Value string `xml:",chardata"`
}

type Script struct {
	ID       string    `xml:"id,attr"`
	Output   string    `xml:"output,attr"`
	Elements []Element `xml:"elem"`
	Tables   []Table   `xml:"table"`
}

type Element struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type Table struct {
	Key      string    `xml:"key,attr"`
	Elements []Element `xml:"elem"`
	Tables   []Table   `xml:"table"`
}

type RunStats struct {
	Finished Finished `xml:"finished"`
	Hosts    Stats    `xml:"hosts"`
}

type Finished struct {
	Time    int64  `xml:"time,attr"`
	TimeStr string `xml:"timestr,attr"`
	Elapsed float64 `xml:"elapsed,attr"`
	Summary string `xml:"summary,attr"`
	Exit    string `xml:"exit,attr"`
}

type Stats struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

type Finding struct {
	ScriptID    string
	Port        int
	Protocol    string
	Title       string
	Severity    string
	Description string
	CVEs        []string
}
