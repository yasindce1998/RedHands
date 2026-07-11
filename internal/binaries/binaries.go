package binaries

import "os/exec"

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
		if p, err := exec.LookPath(bin); err == nil {
			paths[bin] = p
		}
	}
	return paths
}
