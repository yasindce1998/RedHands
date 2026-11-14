package searchsploit

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func runTool(t *testing.T, tool mcp.Tool, params any) *mcp.ToolResult {
	t.Helper()
	result, err := tool.Execute(context.Background(), mustJSON(params))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("Execute() returned empty content")
	}
	return result
}

func expectError(t *testing.T, result *mcp.ToolResult, wantSub string) {
	t.Helper()
	if !result.IsError {
		t.Fatalf("expected IsError=true, got success: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, wantSub) {
		t.Errorf("error text should contain %q, got: %s", wantSub, result.Content[0].Text)
	}
}

func allTools(m *executor.MockExecutor) []mcp.Tool {
	return []mcp.Tool{
		NewSearch(m),
		NewCve(m),
		NewEdb(m),
		NewEnrich(m),
	}
}

// cveJSONOut mirrors real `searchsploit --disable-colour --json --cve
// CVE-2021-44228` output (captured against the upstream script with a stub
// database, Kali-style paths): a .rb exploit that maps to a Metasploit
// module and a .py exploit that does not.
const cveJSONOut = `{
	"SEARCH": "CVE-2021-44228",
	"DB_PATH_EXPLOIT": "/usr/share/exploitdb",
	"RESULTS_EXPLOIT": [
		{"Title":"Apache Log4j 2.14 - JNDI RCE (CVE-2021-44228)","EDB-ID":"50542","Date_Published":"2021-12-10","Date_Added":"2021-12-11","Date_Updated":"2021-12-12","Author":"someone","Type":"remote","Platform":"java","Port":"0","Verified":"1","Codes":"CVE-2021-44228","Tags":"","Aliases":"","Screenshot":"","Application":"","Source":"","Path":"/usr/share/exploitdb/exploits/linux/remote/50542.rb"},
		{"Title":"Apache Log4j 2.14 - JNDI RCE (Python)","EDB-ID":"50543","Date_Published":"2021-12-10","Date_Added":"2021-12-11","Date_Updated":"2021-12-12","Author":"someone","Type":"remote","Platform":"java","Port":"0","Verified":"0","Codes":"CVE-2021-44228","Tags":"","Aliases":"","Screenshot":"","Application":"","Source":"","Path":"/usr/share/exploitdb/exploits/multi/50543.py"}
	],
	"DB_PATH_SHELLCODE": "/usr/share/exploitdb",
	"RESULTS_SHELLCODE": [	]
}`

const cve2021JSONOut = `{
	"SEARCH": "CVE-2015-1701",
	"DB_PATH_EXPLOIT": "/usr/share/exploitdb",
	"RESULTS_EXPLOIT": [
		{"Title":"Windows NetUserModalsGetInfo - Local Privilege Escalation","EDB-ID":"39446","Date_Published":"2015-07-01","Date_Added":"2015-07-02","Date_Updated":"2015-07-03","Author":"someone","Type":"local","Platform":"windows","Port":"0","Verified":"1","Codes":"CVE-2015-1701","Tags":"","Aliases":"","Screenshot":"","Application":"","Source":"","Path":"/usr/share/exploitdb/exploits/windows/local/39446.py"}
	],
	"DB_PATH_SHELLCODE": "/usr/share/exploitdb",
	"RESULTS_SHELLCODE": [	]
}`

// edbPathOut mirrors real `searchsploit --path 39446` output.
const edbPathOut = `  Exploit: Windows NetUserModalsGetInfo - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/39446
     Path: /usr/share/exploitdb/exploits/windows/local/39446.py
    Codes: CVE-2015-1701
 Verified: True
File Type: ASCII text`

// mockCVEOutput wires per-CVE JSON responses into a MockExecutor.
func mockCVEOutput(m *executor.MockExecutor, byCVE map[string]string) {
	m.StdoutFn = func(_ string, args []string) []byte {
		for i, a := range args {
			if a == "--cve" && i+1 < len(args) {
				if out, ok := byCVE[args[i+1]]; ok {
					return []byte(out)
				}
			}
		}
		return []byte("{}\n")
	}
}

// --- TestName ---

func TestName(t *testing.T) {
	mock := executor.NewMock()
	expected := []string{
		"searchsploit_search",
		"searchsploit_cve",
		"searchsploit_edb",
		"cve_enrich",
	}
	for i, tool := range allTools(mock) {
		if tool.Name() != expected[i] {
			t.Errorf("tool %d Name() = %q, want %q", i, tool.Name(), expected[i])
		}
	}
}

// --- TestDescription ---

func TestDescription(t *testing.T) {
	mock := executor.NewMock()
	tools := allTools(mock)

	for _, tool := range tools {
		desc := tool.Description()
		if len(desc) < 40 {
			t.Errorf("%s Description() too short: %q", tool.Name(), desc)
		}
		if !strings.Contains(strings.ToLower(desc), "authorized") {
			t.Errorf("%s Description() must frame authorized use only, got: %s", tool.Name(), desc)
		}
		// searchsploit is a distro package: every tool must document the
		// manual, non-pinnable install.
		if !strings.Contains(desc, "exploitdb") {
			t.Errorf("%s Description() must document the exploitdb package install, got: %s", tool.Name(), desc)
		}
	}

	byName := make(map[string]mcp.Tool)
	for _, tool := range tools {
		byName[tool.Name()] = tool
	}

	// The chaining tools must point at msf_module_run explicitly.
	for _, name := range []string{"searchsploit_search", "searchsploit_cve", "searchsploit_edb", "cve_enrich"} {
		if !strings.Contains(byName[name].Description(), "msf_module_run") {
			t.Errorf("%s Description() must mention msf_module_run chaining, got: %s", name, byName[name].Description())
		}
	}

	// The CVE tool must frame itself as the scanner chaining step.
	if !strings.Contains(byName["searchsploit_cve"].Description(), "nuclei") {
		t.Error("searchsploit_cve Description() must mention nuclei findings as the chaining source")
	}
	if !strings.Contains(byName["cve_enrich"].Description(), "nuclei") {
		t.Error("cve_enrich Description() must mention nuclei findings as the chaining source")
	}
}

// --- TestInputSchema ---

func TestInputSchema(t *testing.T) {
	mock := executor.NewMock()
	requiredByTool := map[string][]string{
		"searchsploit_search": {"query"},
		"searchsploit_cve":    {"cve"},
		"searchsploit_edb":    {"edb_id"},
		"cve_enrich":          nil,
	}

	for _, tool := range allTools(mock) {
		var parsed map[string]any
		if err := json.Unmarshal(tool.InputSchema(), &parsed); err != nil {
			t.Fatalf("%s InputSchema() is not valid JSON: %v", tool.Name(), err)
		}
		if parsed["type"] != "object" {
			t.Errorf("%s InputSchema() type = %v, want \"object\"", tool.Name(), parsed["type"])
		}
		if _, ok := parsed["properties"]; !ok {
			t.Errorf("%s InputSchema() missing \"properties\" key", tool.Name())
		}
		var required []string
		if raw, ok := parsed["required"].([]any); ok {
			for _, v := range raw {
				if s, ok := v.(string); ok {
					required = append(required, s)
				}
			}
		}
		want := requiredByTool[tool.Name()]
		if !reflect.DeepEqual(required, want) {
			t.Errorf("%s InputSchema() required = %v, want %v", tool.Name(), required, want)
		}
	}
}

// --- TestSearchExactArgs ---

func TestSearchExactArgs(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   []string
	}{
		{
			name:   "default json",
			params: map[string]any{"query": "oracle windows"},
			want:   []string{"--disable-colour", "--json", "oracle windows"},
		},
		{
			name:   "table mode",
			params: map[string]any{"query": "oracle windows", "json": false},
			want:   []string{"--disable-colour", "oracle windows"},
		},
		{
			name:   "title only",
			params: map[string]any{"query": "oracle windows", "title_only": true},
			want:   []string{"--disable-colour", "--json", "--title", "oracle windows"},
		},
		{
			name:   "exclude term",
			params: map[string]any{"query": "linux kernel 3.2", "exclude": "PoC"},
			want:   []string{"--disable-colour", "--json", "--exclude=PoC", "linux kernel 3.2"},
		},
		{
			name: "all options",
			params: map[string]any{
				"query":      "linux kernel 3.2",
				"title_only": true,
				"exclude":    "dos",
				"json":       false,
			},
			want: []string{"--disable-colour", "--title", "--exclude=dos", "linux kernel 3.2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte(cveJSONOut)
			}
			result := runTool(t, NewSearch(mock), tc.params)
			if result.IsError {
				t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
			}

			if len(mock.Calls) != 1 {
				t.Fatalf("expected exactly 1 executor call, got %d", len(mock.Calls))
			}
			call := mock.Calls[0]
			if call.Binary != "searchsploit" {
				t.Fatalf("expected binary searchsploit, got %q", call.Binary)
			}
			if !reflect.DeepEqual(call.Args, tc.want) {
				t.Errorf("searchsploit args mismatch:\n got: %v\nwant: %v", call.Args, tc.want)
			}
		})
	}
}

// --- TestSearchOutput ---

func TestSearchOutput(t *testing.T) {
	t.Run("json mode fences structured output", func(t *testing.T) {
		mock := executor.NewMock()
		mock.StdoutFn = func(_ string, _ []string) []byte { return []byte(cveJSONOut) }
		result := runTool(t, NewSearch(mock), map[string]any{"query": "apache log4j"})
		if result.IsError {
			t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
		}
		text := result.Content[0].Text
		for _, want := range []string{"```json", "RESULTS_EXPLOIT", "**Query**: apache log4j", "msf_module_run"} {
			if !strings.Contains(text, want) {
				t.Errorf("result text should contain %q, got: %s", want, text)
			}
		}
	})

	t.Run("table mode fences raw output", func(t *testing.T) {
		mock := executor.NewMock()
		table := " Exploit Title  |  Path\n----------------|--------\nApache Log4j    | linux/remote/50542.rb\n"
		mock.StdoutFn = func(_ string, _ []string) []byte { return []byte(table) }
		result := runTool(t, NewSearch(mock), map[string]any{"query": "apache log4j", "json": false})
		if result.IsError {
			t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
		}
		if !strings.Contains(result.Content[0].Text, "linux/remote/50542.rb") {
			t.Errorf("result should include table output, got: %s", result.Content[0].Text)
		}
		if strings.Contains(result.Content[0].Text, "```json") {
			t.Errorf("table mode must not fence as json, got: %s", result.Content[0].Text)
		}
	})
}

// --- TestSearchInvalid ---

func TestSearchInvalid(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]any
		wantSub string
	}{
		{"missing query", map[string]any{}, "query is required"},
		{"empty query", map[string]any{"query": "   "}, "query is required"},
		{"query metachar", map[string]any{"query": "linux;id"}, "forbidden character"},
		{"query subshell", map[string]any{"query": "linux $(id)"}, "forbidden character"},
		{"query backtick", map[string]any{"query": "linux `id`"}, "forbidden character"},
		{"query newline", map[string]any{"query": "linux\nid"}, "forbidden character"},
		{"leading dash", map[string]any{"query": "-t oracle"}, "must not start with '-'"},
		{"double dash", map[string]any{"query": "foo --exclude=bar"}, "must not contain '--'"},
		{"exclude regex parens", map[string]any{"query": "linux kernel", "exclude": "(PoC)"}, "exclude must be a single plain term"},
		{"exclude pipe", map[string]any{"query": "linux kernel", "exclude": "PoC|dos"}, "exclude must be a single plain term"},
		{"exclude metachar", map[string]any{"query": "linux kernel", "exclude": "PoC;id"}, "exclude must be a single plain term"},
		{"exclude too long", map[string]any{"query": "linux kernel", "exclude": strings.Repeat("a", 65)}, "exclude too long"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewSearch(mock), tc.params)
			expectError(t, result, tc.wantSub)
			if len(mock.Calls) != 0 {
				t.Errorf("no executor call expected on invalid input, got %v", mock.Calls)
			}
		})
	}
}

// --- TestCve ---

func TestCve(t *testing.T) {
	t.Run("normalizes and renders results", func(t *testing.T) {
		mock := executor.NewMock()
		mockCVEOutput(mock, map[string]string{"CVE-2021-44228": cveJSONOut})
		result := runTool(t, NewCve(mock), map[string]any{"cve": "cve-2021-44228"})
		if result.IsError {
			t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
		}

		if len(mock.Calls) != 1 {
			t.Fatalf("expected exactly 1 executor call, got %d", len(mock.Calls))
		}
		call := mock.Calls[0]
		if call.Binary != "searchsploit" {
			t.Fatalf("expected binary searchsploit, got %q", call.Binary)
		}
		expected := []string{"--disable-colour", "--json", "--cve", "CVE-2021-44228"}
		if !reflect.DeepEqual(call.Args, expected) {
			t.Errorf("searchsploit args mismatch:\n got: %v\nwant: %v", call.Args, expected)
		}

		text := result.Content[0].Text
		for _, want := range []string{
			"**CVE**: CVE-2021-44228",
			"| 50542 |", // EDB-ID table row
			"/usr/share/exploitdb/exploits/linux/remote/50542.rb",
			"```json", // raw JSON fenced
			"searchsploit_edb",
			"cve_enrich",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("result text should contain %q, got: %s", want, text)
			}
		}
	})

	t.Run("no results", func(t *testing.T) {
		mock := executor.NewMock()
		mock.StdoutFn = func(_ string, _ []string) []byte {
			return []byte("{\n\t\"SEARCH\": \"CVE-1999-0001\",\n\t\"RESULTS_EXPLOIT\": [\"\"], \n\"RESULTS_EXPLOIT\": []}\n")
		}
		result := runTool(t, NewCve(mock), map[string]any{"cve": "CVE-1999-0001"})
		if result.IsError {
			t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
		}
		if !strings.Contains(result.Content[0].Text, "No EDB exploits reference this CVE") {
			t.Errorf("result should state that no exploits were found, got: %s", result.Content[0].Text)
		}
	})

	t.Run("non-JSON output falls back to raw", func(t *testing.T) {
		mock := executor.NewMock()
		mock.StdoutFn = func(_ string, _ []string) []byte {
			return []byte("some broken table output\n")
		}
		result := runTool(t, NewCve(mock), map[string]any{"cve": "CVE-2021-44228"})
		if result.IsError {
			t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
		}
		for _, want := range []string{"parsing failed", "some broken table output"} {
			if !strings.Contains(result.Content[0].Text, want) {
				t.Errorf("result text should contain %q, got: %s", want, result.Content[0].Text)
			}
		}
	})
}

// --- TestCveInvalid ---

func TestCveInvalid(t *testing.T) {
	tests := []struct {
		name    string
		cve     string
		wantSub string
	}{
		{"missing", "", "cve is required"},
		{"no prefix", "2021-44228", "cve must match"},
		{"two digit year", "CVE-21-44228", "cve must match"},
		{"three digit sequence", "CVE-2021-442", "cve must match"},
		{"trailing junk", "CVE-2021-44228 extra", "cve must match"},
		{"metachar", "CVE-2021-44228;id", "cve must match"},
		{"wrong separator", "CVE:2021-44228", "cve must match"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewCve(mock), map[string]any{"cve": tc.cve})
			expectError(t, result, tc.wantSub)
			if len(mock.Calls) != 0 {
				t.Errorf("no executor call expected on invalid input, got %v", mock.Calls)
			}
		})
	}
}

// --- TestEdb ---

func TestEdb(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return []byte(edbPathOut) }
	result := runTool(t, NewEdb(mock), map[string]any{"edb_id": "39446"})
	if result.IsError {
		t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
	}

	if len(mock.Calls) != 1 {
		t.Fatalf("expected exactly 1 executor call, got %d", len(mock.Calls))
	}
	call := mock.Calls[0]
	if call.Binary != "searchsploit" {
		t.Fatalf("expected binary searchsploit, got %q", call.Binary)
	}
	expected := []string{"--disable-colour", "--path", "39446"}
	if !reflect.DeepEqual(call.Args, expected) {
		t.Errorf("searchsploit args mismatch:\n got: %v\nwant: %v", call.Args, expected)
	}

	text := result.Content[0].Text
	for _, want := range []string{
		"**EDB-ID**: 39446",
		"**Exploit file**: /usr/share/exploitdb/exploits/windows/local/39446.py",
		"cp /usr/share/exploitdb/exploits/windows/local/39446.py .", // copy command hint
		"https://www.exploit-db.com/exploits/39446",
		"msf_module_run",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("result text should contain %q, got: %s", want, text)
		}
	}
}

// --- TestEdbInvalid ---

func TestEdbInvalid(t *testing.T) {
	tests := []struct {
		name    string
		edbID   string
		wantSub string
	}{
		{"missing", "", "edb_id is required"},
		{"prefixed", "EDB-39446", "edb_id must be 1-9 digits"},
		{"file name", "39446.rb", "edb_id must be 1-9 digits"},
		{"negative", "-1", "edb_id must be 1-9 digits"},
		{"letters", "abc", "edb_id must be 1-9 digits"},
		{"metachar", "12;45", "edb_id must be 1-9 digits"},
		{"too many digits", "1234567890", "edb_id must be 1-9 digits"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewEdb(mock), map[string]any{"edb_id": tc.edbID})
			expectError(t, result, tc.wantSub)
			if len(mock.Calls) != 0 {
				t.Errorf("no executor call expected on invalid input, got %v", mock.Calls)
			}
		})
	}
}

// --- TestEnrichDirectCVE ---

func TestEnrichDirectCVE(t *testing.T) {
	mock := executor.NewMock()
	mockCVEOutput(mock, map[string]string{"CVE-2021-44228": cveJSONOut})
	result := runTool(t, NewEnrich(mock), map[string]any{"cve": "CVE-2021-44228"})
	if result.IsError {
		t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
	}

	if len(mock.Calls) != 1 {
		t.Fatalf("expected exactly 1 executor call, got %d", len(mock.Calls))
	}
	call := mock.Calls[0]
	expected := []string{"--disable-colour", "--json", "--cve", "CVE-2021-44228"}
	if !reflect.DeepEqual(call.Args, expected) {
		t.Errorf("searchsploit args mismatch:\n got: %v\nwant: %v", call.Args, expected)
	}

	text := result.Content[0].Text
	// The .rb exploit maps to a Metasploit module, the .py one does not.
	if !strings.Contains(text, "- Metasploit: try msf_module_run with module exploit/linux/remote/50542\n") {
		t.Errorf("result must map the .rb exploit to an msf_module_run candidate, got: %s", text)
	}
	if strings.Contains(text, "exploit/multi/50543") {
		t.Errorf(".py exploits must not map to Metasploit modules, got: %s", text)
	}
	if !strings.Contains(text, "msf_module_info") {
		t.Errorf("result should point at msf_module_info for verification, got: %s", text)
	}
}

// --- TestEnrichFromText ---

func TestEnrichFromText(t *testing.T) {
	mock := executor.NewMock()
	mockCVEOutput(mock, map[string]string{
		"CVE-2021-44228": cveJSONOut,
		"CVE-2015-1701":  cve2021JSONOut,
	})
	// Text carries metachars and a duplicate lowercase mention: the text is
	// only scanned locally and never passed to a shell.
	text := "[nuclei] finding: Apache Log4j RCE (matched-id: log4j-rce) | references cve-2021-44228 and CVE-2021-44228 again; also CVE-2015-1701"
	result := runTool(t, NewEnrich(mock), map[string]any{"text": text})
	if result.IsError {
		t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
	}

	if len(mock.Calls) != 2 {
		t.Fatalf("expected exactly 2 executor calls (one per distinct CVE), got %d", len(mock.Calls))
	}
	for i, want := range []string{"CVE-2021-44228", "CVE-2015-1701"} {
		call := mock.Calls[i]
		if call.Binary != "searchsploit" {
			t.Fatalf("call %d: expected binary searchsploit, got %q", i, call.Binary)
		}
		if got := call.Args[len(call.Args)-1]; got != want {
			t.Errorf("call %d: expected --cve %s, got args %v", i, want, call.Args)
		}
	}

	out := result.Content[0].Text
	for _, want := range []string{
		"### CVE-2021-44228",
		"### CVE-2015-1701",
		"exploit/linux/remote/50542", // .rb maps
		"no module candidates",       // CVE-2015-1701 only has a .py exploit
	} {
		if !strings.Contains(out, want) {
			t.Errorf("result text should contain %q, got: %s", want, out)
		}
	}
}

// --- TestEnrichInvalid ---

func TestEnrichInvalid(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]any
		wantSub string
	}{
		{"neither param", map[string]any{}, "either cve or text is required"},
		{"bad cve format", map[string]any{"cve": "CVE-21-1"}, "cve must match"},
		{"cve metachar", map[string]any{"cve": "CVE-2021-44228;id"}, "cve must match"},
		{"text without cve", map[string]any{"text": "nothing to see here"}, "no CVE IDs found in text"},
		{"text with partial id", map[string]any{"text": "hit on CVE-2021-44"}, "no CVE IDs found in text"},
		{
			"too many cves",
			map[string]any{"text": "CVE-2020-1111 CVE-2020-2222 CVE-2020-3333 CVE-2020-4444 CVE-2020-5555 CVE-2020-6666"},
			"max 5 per call",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewEnrich(mock), tc.params)
			expectError(t, result, tc.wantSub)
			if len(mock.Calls) != 0 {
				t.Errorf("no executor call expected on invalid input, got %v", mock.Calls)
			}
		})
	}

	t.Run("text too long", func(t *testing.T) {
		mock := executor.NewMock()
		result := runTool(t, NewEnrich(mock), map[string]any{"text": strings.Repeat("A", 65537)})
		expectError(t, result, "text too long")
		if len(mock.Calls) != 0 {
			t.Errorf("no executor call expected on invalid input, got %v", mock.Calls)
		}
	})
}

// --- TestEnrichExecFailure ---

func TestEnrichExecFailure(t *testing.T) {
	t.Run("single failure surfaces as error", func(t *testing.T) {
		mock := executor.NewMock()
		mock.ErrFn = func(_ string, _ []string) error {
			return fmt.Errorf("execution failed (exit 1)")
		}
		result := runTool(t, NewEnrich(mock), map[string]any{"cve": "CVE-2021-44228"})
		if !result.IsError {
			t.Fatalf("expected IsError=true when every searchsploit call fails, got: %s", result.Content[0].Text)
		}
		if !strings.Contains(result.Content[0].Text, "apt install exploitdb") {
			t.Errorf("failure hint should mention the exploitdb install, got: %s", result.Content[0].Text)
		}
	})

	t.Run("mixed success continues", func(t *testing.T) {
		mock := executor.NewMock()
		mockCVEOutput(mock, map[string]string{"CVE-2021-44228": cveJSONOut})
		mock.ErrFn = func(_ string, args []string) error {
			for i, a := range args {
				if a == "--cve" && i+1 < len(args) && args[i+1] == "CVE-2015-1701" {
					return fmt.Errorf("execution failed (exit 1)")
				}
			}
			return nil
		}
		result := runTool(t, NewEnrich(mock), map[string]any{
			"text": "CVE-2021-44228 CVE-2015-1701",
		})
		if result.IsError {
			t.Fatalf("partial failure should not fail the whole result, got: %s", result.Content[0].Text)
		}
		text := result.Content[0].Text
		if !strings.Contains(text, "exploit/linux/remote/50542") {
			t.Errorf("successful CVE section should still render, got: %s", text)
		}
		if !strings.Contains(text, "searchsploit failed") {
			t.Errorf("failed CVE section should note the failure, got: %s", text)
		}
	})
}

// --- TestEnrichRawFallback ---

// When the JSON cannot be parsed, cve_enrich still extracts exploit paths
// from the raw output with a fallback scan.
func TestEnrichRawFallback(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte(`garbage { "Title":"broken json..." "Path":"/usr/share/exploitdb/exploits/linux/remote/50542.rb" } trailing`)
	}
	result := runTool(t, NewEnrich(mock), map[string]any{"cve": "CVE-2021-44228"})
	if result.IsError {
		t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "fallback scan") {
		t.Errorf("result should note the fallback path extraction, got: %s", text)
	}
	if !strings.Contains(text, "- Metasploit: try msf_module_run with module exploit/linux/remote/50542") {
		t.Errorf("fallback should still map the .rb path to an msf_module_run candidate, got: %s", text)
	}
}

// --- TestMSFModuleFromEDBPath ---

func TestMSFModuleFromEDBPath(t *testing.T) {
	tests := []struct {
		path       string
		wantModule string
		wantOK     bool
	}{
		// Ruby exploits under exploits/ map.
		{"exploits/linux/remote/12345.rb", "exploit/linux/remote/12345", true},
		{"/usr/share/exploitdb/exploits/linux/remote/12345.rb", "exploit/linux/remote/12345", true},
		{"/opt/exploitdb/exploits/windows/local/39446.rb", "exploit/windows/local/39446", true},
		{"exploits/multi/http/50542.rb", "exploit/multi/http/50542", true},
		{"exploits/12345.rb", "exploit/12345", true},
		{"/usr/share/exploitdb/exploits/a/b/12345.rb ", "exploit/a/b/12345", true}, // trailing space trimmed
		// Non-Ruby exploits never map.
		{"exploits/multi/50543.py", "", false},
		{"exploits/windows/local/39446.txt", "", false},
		{"exploits/linux/remote/12345.rb.txt", "", false},
		{"exploits/linux/remote/12345.rb/", "", false},
		// Shellcodes and papers never map.
		{"shellcodes/linux_x86/1337.rb", "", false},
		{"/usr/share/exploitdb/shellcodes/linux_x86/1337.rb", "", false},
		{"papers/windows/1234.rb", "", false},
		// Lookalike directories and traversal are rejected.
		{"myexploits/foo/123.rb", "", false},
		{"exploits/../45416.rb", "", false},
		{"exploits//45416.rb", "", false},
		{"exploits/./45416.rb", "", false},
		// Metasploit module names are lowercase only.
		{"exploits/Windows/Local/39446.rb", "", false},
		// No exploits/ component at all.
		{"", "", false},
		{"12345.rb", "", false},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%q", tc.path), func(t *testing.T) {
			module, ok := msfModuleFromEDBPath(tc.path)
			if ok != tc.wantOK {
				t.Fatalf("msfModuleFromEDBPath(%q) ok = %v, want %v (module %q)", tc.path, ok, tc.wantOK, module)
			}
			if ok && module != tc.wantModule {
				t.Errorf("msfModuleFromEDBPath(%q) = %q, want %q", tc.path, module, tc.wantModule)
			}
		})
	}
}

// --- TestExtractCVEs ---

func TestExtractCVEs(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []string
	}{
		{"single", "nuclei: CVE-2021-44228 detected", []string{"CVE-2021-44228"}},
		{"case insensitive and deduped", "cve-2021-44228 and CVE-2021-44228 again", []string{"CVE-2021-44228"}},
		{"multiple in order", "hits CVE-2021-44228 then CVE-2015-1701", []string{"CVE-2021-44228", "CVE-2015-1701"}},
		{"bracketed", "[CVE-2021-44228]", []string{"CVE-2021-44228"}},
		{"long sequence", "CVE-2023-1234567 matched", []string{"CVE-2023-1234567"}},
		{"none", "no identifiers here", nil},
		{"word boundary prefix", "XCVE-2021-44228 nope", nil},
		{"too few sequence digits", "CVE-2021-442 nope", nil},
		{"two digit year", "CVE-21-44228 nope", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractCVEs(tc.text)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("extractCVEs(%q) = %v, want %v", tc.text, got, tc.want)
			}
		})
	}
}

// --- TestParseSearchsploitJSON ---

// The parser must handle the real searchsploit -j shape, including the
// tab-padded empty array and multiple RESULTS_* databases.
func TestParseSearchsploitJSON(t *testing.T) {
	results, err := parseSearchsploitJSON([]byte(cveJSONOut))
	if err != nil {
		t.Fatalf("parseSearchsploitJSON() error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d: %+v", len(results), results)
	}
	first := results[0]
	if first.EDBID != "50542" || first.Title != "Apache Log4j 2.14 - JNDI RCE (CVE-2021-44228)" ||
		first.Path != "/usr/share/exploitdb/exploits/linux/remote/50542.rb" ||
		first.Verified != "1" || first.Codes != "CVE-2021-44228" || first.Type != "remote" {
		t.Errorf("first result fields mismatch: %+v", first)
	}

	if _, err := parseSearchsploitJSON([]byte("not json at all")); err == nil {
		t.Error("parseSearchsploitJSON() should fail on non-JSON input")
	}
}

// --- TestMetacharsRejected ---

// TestMetacharsRejected walks the executor's full forbidden-character set
// through the free-form string surfaces of the searchsploit tools.
func TestMetacharsRejected(t *testing.T) {
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "\n", "\r"}

	for _, mc := range forbidden {
		t.Run("query "+fmt.Sprintf("%q", mc), func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewSearch(mock), map[string]any{
				"query": "apache log4j" + mc + "id",
			})
			expectError(t, result, "forbidden character")
			if len(mock.Calls) != 0 {
				t.Errorf("no executor call expected, got %v", mock.Calls)
			}
		})
		t.Run("exclude "+fmt.Sprintf("%q", mc), func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewSearch(mock), map[string]any{
				"query":   "apache log4j",
				"exclude": "PoC" + mc + "dos",
			})
			expectError(t, result, "exclude")
			if len(mock.Calls) != 0 {
				t.Errorf("no executor call expected, got %v", mock.Calls)
			}
		})
		t.Run("cve "+fmt.Sprintf("%q", mc), func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewCve(mock), map[string]any{
				"cve": "CVE-2021-4422" + mc + "8",
			})
			expectError(t, result, "cve must match")
			if len(mock.Calls) != 0 {
				t.Errorf("no executor call expected, got %v", mock.Calls)
			}
		})
	}
}
