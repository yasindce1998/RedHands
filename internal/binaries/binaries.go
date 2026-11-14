package binaries

import "os/exec"

// pip uses upstream *.py entry-point names, while distro packages commonly
// provide impacket-* aliases. Resolve both without requiring shell wrappers.
var aliases = map[string]string{
	"impacket-secretsdump": "secretsdump.py",
	"impacket-psexec":      "psexec.py",
	"impacket-wmiexec":     "wmiexec.py",
	"impacket-smbclient":   "smbclient.py",
	"impacket-dcomexec":    "dcomexec.py",
	"impacket-getTGT":      "getTGT.py",
	"impacket-getST":       "getST.py",
	"impacket-ntlmrelayx":  "ntlmrelayx.py",
	// Aegis-Shadow binaries may be built under either name; prefer the
	// collision-safe one and fall back to the short historical name.
	"aegis-shadow-defense": "defense",
	"aegis-shadow-offense": "offense",
}

func Resolve(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err == nil {
		return path, nil
	}
	if alias, ok := aliases[name]; ok {
		return exec.LookPath(alias)
	}
	return "", err
}

var All = []string{
	"nmap", "subfinder", "httpx", "nuclei", "ffuf",
	"dig", "amass", "katana", "nikto", "gobuster",
	"waybackurls", "testssl.sh", "whatweb", "sqlmap",
	"masscan", "rustscan", "feroxbuster", "arjun", "gau",
	"kubedagger-client", "kubedagger-operator", "kubedagger-server",
	"impacket-secretsdump", "impacket-psexec", "impacket-wmiexec",
	"impacket-smbclient", "impacket-dcomexec", "impacket-getTGT",
	"impacket-getST", "impacket-ntlmrelayx",
	"sliver-client",
	"chisel", "ligolo-proxy",
	"hashcat", "john",
	"hydra",
	"crackmapexec",
	"certipy",
	"tshark",
	"barzakh-adversary", "barzakh-scanner", "barzakh-server",
	"staticzero-defense", "staticzero-offense", "modem-firmware", "sdr-bridge",
	"protocol-correlator",
	"aegis-shadow-defense", "aegis-shadow-offense",
	"aegis-c2",
	"bloodhound-python", "responder", "evil-winrm", "python3",
	"rubeus",
	"airmon-ng", "airodump-ng", "aircrack-ng", "bettercap",
	"msfconsole", "msfvenom",
	"searchsploit",
	"frida", "objection", "apktool", "adb",
	"scout", "prowler", "pacu", "roadtx",
	"cutycapt",
	"wkhtmltopdf",
}

func Discover() map[string]string {
	paths := make(map[string]string)
	for _, bin := range All {
		if p, err := Resolve(bin); err == nil {
			paths[bin] = p
		}
	}
	return paths
}
