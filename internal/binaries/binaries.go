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
	"kubedagger-client", "kubedagger-operator",
	"impacket-secretsdump", "impacket-psexec", "impacket-wmiexec",
	"impacket-smbclient", "impacket-dcomexec", "impacket-getTGT",
	"impacket-getST", "impacket-ntlmrelayx",
	"sliver-client",
	"chisel", "ligolo-proxy",
	"hashcat", "john",
	"crackmapexec",
	"certipy",
	"tshark",
	"barzakh-adversary", "barzakh-scanner",
	"staticzero-defense", "modem-firmware", "sdr-bridge",
	"bloodhound-python", "responder", "evil-winrm", "python3",
	"airmon-ng", "airodump-ng", "aircrack-ng", "bettercap",
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
