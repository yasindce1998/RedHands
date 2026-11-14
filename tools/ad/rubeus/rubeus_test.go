package rubeus

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

const validTicket = "doIFmjCCBZagAwIBBaEDAgEWooIErzCCBKthggSnMIIEo6ADAgEFoQ8bDVRFU1RMQUIuTE9DQUw="

// toolRunner executes one tool with the mock executor.
type toolRunner func(ctx context.Context, mock *executor.MockExecutor, params json.RawMessage) (*mcp.ToolResult, error)

func runners() map[string]toolRunner {
	return map[string]toolRunner{
		"kerberoast": func(ctx context.Context, m *executor.MockExecutor, p json.RawMessage) (*mcp.ToolResult, error) {
			return NewKerberoast(m).Execute(ctx, p)
		},
		"asktgt": func(ctx context.Context, m *executor.MockExecutor, p json.RawMessage) (*mcp.ToolResult, error) {
			return NewAskTgt(m).Execute(ctx, p)
		},
		"asreproast": func(ctx context.Context, m *executor.MockExecutor, p json.RawMessage) (*mcp.ToolResult, error) {
			return NewAsRepRoast(m).Execute(ctx, p)
		},
		"harvest": func(ctx context.Context, m *executor.MockExecutor, p json.RawMessage) (*mcp.ToolResult, error) {
			return NewHarvest(m).Execute(ctx, p)
		},
		"dump": func(ctx context.Context, m *executor.MockExecutor, p json.RawMessage) (*mcp.ToolResult, error) {
			return NewDump(m).Execute(ctx, p)
		},
		"describe": func(ctx context.Context, m *executor.MockExecutor, p json.RawMessage) (*mcp.ToolResult, error) {
			return NewDescribe(m).Execute(ctx, p)
		},
	}
}

func TestName(t *testing.T) {
	mock := executor.NewMock()
	expected := map[string]string{
		"Keroboast":  "rubeus_kerberoast",
		"AskTgt":     "rubeus_asktgt",
		"AsRepRoast": "rubeus_asreproast",
		"Harvest":    "rubeus_harvest",
		"Dump":       "rubeus_dump",
		"Describe":   "rubeus_describe",
	}
	tools := map[string]struct {
		name string
	}{
		"Keroboast":  {NewKerberoast(mock).Name()},
		"AskTgt":     {NewAskTgt(mock).Name()},
		"AsRepRoast": {NewAsRepRoast(mock).Name()},
		"Harvest":    {NewHarvest(mock).Name()},
		"Dump":       {NewDump(mock).Name()},
		"Describe":   {NewDescribe(mock).Name()},
	}
	for name, tool := range tools {
		if tool.name != expected[name] {
			t.Errorf("%s Name() = %q, want %q", name, tool.name, expected[name])
		}
	}
}

func TestDescription(t *testing.T) {
	mock := executor.NewMock()
	descs := map[string]string{
		"rubeus_kerberoast": NewKerberoast(mock).Description(),
		"rubeus_asktgt":     NewAskTgt(mock).Description(),
		"rubeus_asreproast": NewAsRepRoast(mock).Description(),
		"rubeus_harvest":    NewHarvest(mock).Description(),
		"rubeus_dump":       NewDump(mock).Description(),
		"rubeus_describe":   NewDescribe(mock).Description(),
	}
	for name, desc := range descs {
		if desc == "" {
			t.Errorf("%s Description() returned empty string", name)
			continue
		}
		// Every Rubeus tool is high impact: offensive Kerberos tooling.
		for _, want := range []string{"HIGH IMPACT", "authorized", "approval-gated"} {
			if !strings.Contains(desc, want) {
				t.Errorf("%s Description() must mention %q, got: %s", name, want, desc)
			}
		}
	}
}

func TestInputSchema(t *testing.T) {
	mock := executor.NewMock()
	schemas := map[string]json.RawMessage{
		"rubeus_kerberoast": NewKerberoast(mock).InputSchema(),
		"rubeus_asktgt":     NewAskTgt(mock).InputSchema(),
		"rubeus_asreproast": NewAsRepRoast(mock).InputSchema(),
		"rubeus_harvest":    NewHarvest(mock).InputSchema(),
		"rubeus_dump":       NewDump(mock).InputSchema(),
		"rubeus_describe":   NewDescribe(mock).InputSchema(),
	}
	for name, schema := range schemas {
		var parsed map[string]interface{}
		if err := json.Unmarshal(schema, &parsed); err != nil {
			t.Fatalf("%s InputSchema() is not valid JSON: %v", name, err)
		}
		if parsed["type"] != "object" {
			t.Errorf("%s InputSchema() type = %v, want \"object\"", name, parsed["type"])
		}
		if _, ok := parsed["properties"]; !ok {
			t.Errorf("%s InputSchema() missing \"properties\" key", name)
		}
	}

	// Enum-bearing and required properties.
	var kerb map[string]interface{}
	if err := json.Unmarshal(NewKerberoast(mock).InputSchema(), &kerb); err != nil {
		t.Fatal(err)
	}
	op := kerb["properties"].(map[string]interface{})["op"].(map[string]interface{})
	if enum, ok := op["enum"].([]interface{}); !ok || len(enum) != 3 {
		t.Errorf("kerberoast op property must carry a 3-value enum, got %v", op["enum"])
	}

	var asktgt map[string]interface{}
	if err := json.Unmarshal(NewAskTgt(mock).InputSchema(), &asktgt); err != nil {
		t.Fatal(err)
	}
	if req, ok := asktgt["required"].([]interface{}); !ok || len(req) != 1 || req[0] != "user" {
		t.Errorf("asktgt schema required must be [user], got %v", asktgt["required"])
	}
	var describe map[string]interface{}
	if err := json.Unmarshal(NewDescribe(mock).InputSchema(), &describe); err != nil {
		t.Fatal(err)
	}
	if req, ok := describe["required"].([]interface{}); !ok || len(req) != 1 || req[0] != "ticket" {
		t.Errorf("describe schema required must be [ticket], got %v", describe["required"])
	}
}

// TestExecuteExactArgs drives every tool through the MockExecutor and asserts
// the exact binary and argv produced.
func TestExecuteExactArgs(t *testing.T) {
	ctx := context.Background()
	r := runners()

	tests := []struct {
		name     string
		tool     string
		params   string
		expected []string
	}{
		{
			name:     "KeroboastDefaultRC4",
			tool:     "kerberoast",
			params:   `{"user": "sqlsvc"}`,
			expected: []string{"kerberoast", "/user:sqlsvc"},
		},
		{
			name:     "KeroboastAES",
			tool:     "kerberoast",
			params:   `{"op": "aes", "user": "sqlsvc", "nowrap": true}`,
			expected: []string{"kerberoast", "/aes", "/user:sqlsvc", "/nowrap"},
		},
		{
			name:   "KeroboastRC4OpsecFull",
			tool:   "kerberoast",
			params: `{"op": "rc4opsec", "user": "sqlsvc", "domain": "corp.local", "dc": "dc01.corp.local", "outfile": "C:\\temp\\hashes.txt", "nowrap": true}`,
			expected: []string{
				"kerberoast", "/rc4opsec", "/user:sqlsvc",
				"/domain:corp.local", "/dc:dc01.corp.local",
				"/outfile:C:\\temp\\hashes.txt", "/nowrap",
			},
		},
		{
			name:   "AskTgtPassword",
			tool:   "asktgt",
			params: `{"user": "dfm.a", "password": "Password1", "domain": "testlab.local", "nowrap": true}`,
			expected: []string{
				"asktgt", "/user:dfm.a", "/password:Password1",
				"/domain:testlab.local", "/nowrap",
			},
		},
		{
			name:   "AskTgtPasswordEnctype",
			tool:   "asktgt",
			params: `{"user": "dfm.a", "password": "Password1", "enctype": "aes256"}`,
			expected: []string{
				"asktgt", "/user:dfm.a", "/password:Password1", "/enctype:aes256",
			},
		},
		{
			name:   "AskTgtRC4",
			tool:   "asktgt",
			params: `{"user": "dfm.a", "rc4": "2b576acbe6bcfda7294d6bd18041b8fe"}`,
			expected: []string{
				"asktgt", "/user:dfm.a", "/rc4:2b576acbe6bcfda7294d6bd18041b8fe",
			},
		},
		{
			name:   "AskTgtAES256",
			tool:   "asktgt",
			params: `{"user": "dfm.a", "aes256": "e27b2e7b39f59c3738813a9ba8c20cd5864946f179c80f60067f5cda59c3bd27", "outfile": "C:\\temp\\tgt.kirbi"}`,
			expected: []string{
				"asktgt", "/user:dfm.a",
				"/aes256:e27b2e7b39f59c3738813a9ba8c20cd5864946f179c80f60067f5cda59c3bd27",
				"/outfile:C:\\temp\\tgt.kirbi",
			},
		},
		{
			name:     "AsRepRoastDefault",
			tool:     "asreproast",
			params:   `{}`,
			expected: []string{"asreproast"},
		},
		{
			name:   "AsRepRoastHashcat",
			tool:   "asreproast",
			params: `{"user": "jdoe", "ou": "OU=ServiceAccounts,DC=corp,DC=local", "domain": "corp.local", "dc": "dc01.corp.local", "format": "hashcat", "outfile": "C:\\temp\\asrep.txt", "ldaps": true, "nowrap": true}`,
			expected: []string{
				"asreproast", "/user:jdoe",
				"/ou:OU=ServiceAccounts,DC=corp,DC=local",
				"/domain:corp.local", "/dc:dc01.corp.local",
				"/format:hashcat", "/outfile:C:\\temp\\asrep.txt",
				"/ldaps", "/nowrap",
			},
		},
		{
			name:     "HarvestInterval",
			tool:     "harvest",
			params:   `{"interval": 30}`,
			expected: []string{"harvest", "/interval:30"},
		},
		{
			name:   "HarvestSeparateIntervals",
			tool:   "harvest",
			params: `{"monitor_interval": 60, "display_interval": 600, "targetuser": "admin", "runfor": 300, "nowrap": true}`,
			expected: []string{
				"harvest", "/monitorinterval:60", "/displayinterval:600",
				"/targetuser:admin", "/runfor:300", "/nowrap",
			},
		},
		{
			name:     "DumpDefault",
			tool:     "dump",
			params:   `{}`,
			expected: []string{"dump"},
		},
		{
			name:   "DumpFiltered",
			tool:   "dump",
			params: `{"luid": "0x3e7", "user": "admin", "service": "krbtgt", "server": "dc01.corp.local", "nowrap": true}`,
			expected: []string{
				"dump", "/luid:0x3e7", "/user:admin", "/service:krbtgt",
				"/server:dc01.corp.local", "/nowrap",
			},
		},
		{
			name:   "DescribeTicket",
			tool:   "describe",
			params: `{"ticket": "` + validTicket + `"}`,
			expected: []string{
				"describe", "/ticket:" + validTicket,
			},
		},
		{
			name:   "DescribeFull",
			tool:   "describe",
			params: `{"ticket": "` + validTicket + `", "serviceuser": "sqlsvc", "servicedomain": "corp.local", "nowrap": true}`,
			expected: []string{
				"describe", "/ticket:" + validTicket,
				"/serviceuser:sqlsvc", "/servicedomain:corp.local", "/nowrap",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("[*] Action: simulated rubeus output")
			}

			result, err := r[tt.tool](ctx, mock, json.RawMessage(tt.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if result.IsError {
				t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
			}
			if len(mock.Calls) != 1 {
				t.Fatalf("expected exactly 1 executor call, got %d", len(mock.Calls))
			}
			if mock.Calls[0].Binary != "rubeus" {
				t.Errorf("expected binary %q, got %q", "rubeus", mock.Calls[0].Binary)
			}
			if !reflect.DeepEqual(mock.Calls[0].Args, tt.expected) {
				t.Errorf("args mismatch:\n got:  %v\n want: %v", mock.Calls[0].Args, tt.expected)
			}
			if !strings.Contains(result.Content[0].Text, "simulated rubeus output") {
				t.Errorf("result does not contain expected stdout")
			}
		})
	}
}

func TestEnumValidation(t *testing.T) {
	ctx := context.Background()
	r := runners()

	tests := []struct {
		name      string
		tool      string
		params    string
		wantError string
	}{
		{
			name:      "KeroboastBadOp",
			tool:      "kerberoast",
			params:    `{"user": "x", "op": "des"}`,
			wantError: "op must be one of: rc4, aes, rc4opsec",
		},
		{
			name:      "AskTgtBadEnctype",
			tool:      "asktgt",
			params:    `{"user": "x", "password": "p", "enctype": "des"}`,
			wantError: "enctype must be one of: rc4, aes128, aes256",
		},
		{
			name:      "AsRepRoastBadFormat",
			tool:      "asreproast",
			params:    `{"format": "dcc2"}`,
			wantError: "format must be one of: john, hashcat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()

			result, err := r[tt.tool](ctx, mock, json.RawMessage(tt.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !result.IsError {
				t.Fatal("Execute() should return IsError=true")
			}
			if !strings.Contains(result.Content[0].Text, tt.wantError) {
				t.Errorf("error text %q does not contain %q", result.Content[0].Text, tt.wantError)
			}
			if len(mock.Calls) > 0 {
				t.Error("executor should not be called for invalid input")
			}
		})
	}
}

func TestAskTgtInputValidation(t *testing.T) {
	ctx := context.Background()
	r := runners()

	rc4OK := "2b576acbe6bcfda7294d6bd18041b8fe"

	tests := []struct {
		name      string
		params    string
		wantError string
	}{
		{
			name:      "MissingUser",
			params:    `{"password": "p"}`,
			wantError: "user is required",
		},
		{
			name:      "NoCredential",
			params:    `{"user": "dfm.a"}`,
			wantError: "exactly one of password, rc4, or aes256 is required",
		},
		{
			name:      "TwoCredentials",
			params:    `{"user": "dfm.a", "password": "p", "rc4": "` + rc4OK + `"}`,
			wantError: "mutually exclusive",
		},
		{
			name:      "ThreeCredentials",
			params:    `{"user": "dfm.a", "password": "p", "rc4": "` + rc4OK + `", "aes256": "e27b2e7b39f59c3738813a9ba8c20cd5864946f179c80f60067f5cda59c3bd27"}`,
			wantError: "mutually exclusive",
		},
		{
			name:      "RC4TooShort",
			params:    `{"user": "dfm.a", "rc4": "2b576acbe6bcfda7294d6bd18041b8"}`,
			wantError: "rc4 must be exactly 32 hex characters",
		},
		{
			name:      "RC4NotHex",
			params:    `{"user": "dfm.a", "rc4": "zz576acbe6bcfda7294d6bd18041b8fe"}`,
			wantError: "rc4 must contain only hex characters",
		},
		{
			name:      "AES256TooShort",
			params:    `{"user": "dfm.a", "aes256": "` + rc4OK + `"}`,
			wantError: "aes256 must be exactly 64 hex characters",
		},
		{
			name:      "EnctypeWithoutPassword",
			params:    `{"user": "dfm.a", "rc4": "` + rc4OK + `", "enctype": "rc4"}`,
			wantError: "enctype only applies when password is set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()

			result, err := r["asktgt"](ctx, mock, json.RawMessage(tt.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !result.IsError {
				t.Fatal("Execute() should return IsError=true")
			}
			if !strings.Contains(result.Content[0].Text, tt.wantError) {
				t.Errorf("error text %q does not contain %q", result.Content[0].Text, tt.wantError)
			}
			if len(mock.Calls) > 0 {
				t.Error("executor should not be called for invalid input")
			}
		})
	}
}

func TestHarvestInputValidation(t *testing.T) {
	ctx := context.Background()
	r := runners()

	tests := []struct {
		name      string
		params    string
		wantError string
	}{
		{
			name:      "IntervalCombined",
			params:    `{"interval": 30, "monitor_interval": 60}`,
			wantError: "interval cannot be combined with monitor_interval/display_interval",
		},
		{
			name:      "IntervalNegative",
			params:    `{"interval": -1}`,
			wantError: "interval must be between 1 and 86400 seconds",
		},
		{
			name:      "MonitorIntervalTooHigh",
			params:    `{"monitor_interval": 86401}`,
			wantError: "monitor_interval must be between 1 and 86400 seconds",
		},
		{
			name:      "RunForTooHigh",
			params:    `{"runfor": 100000}`,
			wantError: "runfor must be between 1 and 86400 seconds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()

			result, err := r["harvest"](ctx, mock, json.RawMessage(tt.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !result.IsError {
				t.Fatal("Execute() should return IsError=true")
			}
			if !strings.Contains(result.Content[0].Text, tt.wantError) {
				t.Errorf("error text %q does not contain %q", result.Content[0].Text, tt.wantError)
			}
			if len(mock.Calls) > 0 {
				t.Error("executor should not be called for invalid input")
			}
		})
	}
}

func TestDumpLUIDValidation(t *testing.T) {
	ctx := context.Background()
	r := runners()

	badLUIDs := []struct {
		name string
		luid string
	}{
		{"no-prefix", "3e7"},
		{"not-hex", "0xzz"},
		{"empty-hex", "0x"},
		{"decimal", "999"},
	}
	for _, tt := range badLUIDs {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()

			result, err := r["dump"](ctx, mock, json.RawMessage(`{"luid": "`+tt.luid+`"}`))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("luid %q should be rejected", tt.luid)
			}
			if !strings.Contains(result.Content[0].Text, "0x-prefixed hex logon session ID") {
				t.Errorf("error text should describe the LUID format, got: %s", result.Content[0].Text)
			}
			if len(mock.Calls) > 0 {
				t.Error("executor should not be called for invalid input")
			}
		})
	}

	// Valid LUIDs pass through.
	for _, luid := range []string{"0x3e7", "0x3c4c241", "0x0"} {
		t.Run("valid-"+luid, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("ok")
			}

			result, err := r["dump"](ctx, mock, json.RawMessage(`{"luid": "`+luid+`"}`))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if result.IsError {
				t.Fatalf("luid %q should be accepted: %s", luid, result.Content[0].Text)
			}
			if mock.LastCall().Args[1] != "/luid:"+luid {
				t.Errorf("expected /luid:%s, got %v", luid, mock.LastCall().Args)
			}
		})
	}
}

func TestTicketBase64Validation(t *testing.T) {
	ctx := context.Background()
	r := runners()

	tests := []struct {
		name      string
		ticket    string
		wantError string
	}{
		{"valid-with-padding", validTicket, ""},
		{"valid-no-padding", strings.TrimRight(validTicket, "="), ""},
		{"missing", "", "ticket is required"},
		{"too-short", "c2hvcnQ=", "too short to be a base64"},
		{"bad-charset", strings.Replace(validTicket, "doIF", "d!IF", 1), "must be standard base64"},
		{"space-in-ticket", "doIF mjCCBZagAwIBBaEDAgEWooIErzCCBKthggSnMIIEo6ADAgEFoQ8", "must be standard base64"},
		{"equals-in-middle", "doIF=mjCCBZagAwIBBaEDAgEWooIErzCCBKthggSnMIIEo6ADAgEFoQ8", "must be standard base64"},
		{"three-paddings", validTicket + "==", "must be standard base64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("UserName : dfm.a")
			}

			result, err := r["describe"](ctx, mock, json.RawMessage(`{"ticket": "`+tt.ticket+`"}`))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if tt.wantError == "" {
				if result.IsError {
					t.Fatalf("ticket should pass validation, got: %s", result.Content[0].Text)
				}
				if mock.LastCall().Args[1] != "/ticket:"+tt.ticket {
					t.Errorf("expected /ticket passthrough, got %v", mock.LastCall().Args)
				}
				return
			}
			if !result.IsError {
				t.Fatalf("ticket %q should be rejected", tt.ticket)
			}
			if !strings.Contains(result.Content[0].Text, tt.wantError) {
				t.Errorf("error text %q does not contain %q", result.Content[0].Text, tt.wantError)
			}
			if len(mock.Calls) > 0 {
				t.Error("executor should not be called for invalid ticket")
			}
		})
	}
}

func TestShellInjection(t *testing.T) {
	ctx := context.Background()
	r := runners()

	metachars := []struct {
		name string
		char string
	}{
		{"semicolon", ";"},
		{"pipe", "|"},
		{"ampersand", "&"},
		{"backtick", "`"},
		{"dollar", "$"},
		{"lparen", "("},
		{"rparen", ")"},
		{"lbrace", "{"},
		{"rbrace", "}"},
		{"langle", "<"},
		{"rangle", ">"},
		{"exclamation", "!"},
	}

	fields := []struct {
		name   string
		tool   string
		params func(char string) string
	}{
		{"kerberoast-user", "kerberoast", func(c string) string {
			return `{"user": "sqlsvc` + c + `x"}`
		}},
		{"asktgt-user", "asktgt", func(c string) string {
			return `{"user": "dfm.a` + c + `x", "password": "p"}`
		}},
		{"asktgt-password", "asktgt", func(c string) string {
			return `{"user": "dfm.a", "password": "p` + c + `q"}`
		}},
		{"asreproast-ou", "asreproast", func(c string) string {
			return `{"ou": "OU=SA` + c + `x,DC=corp"}`
		}},
		{"harvest-targetuser", "harvest", func(c string) string {
			return `{"targetuser": "admin` + c + `x"}`
		}},
		{"dump-server", "dump", func(c string) string {
			return `{"server": "dc01.corp.local` + c + `x"}`
		}},
		{"describe-serviceuser", "describe", func(c string) string {
			return `{"ticket": "` + validTicket + `", "serviceuser": "sqlsvc` + c + `x"}`
		}},
	}

	for _, field := range fields {
		for _, mc := range metachars {
			t.Run(field.name+"-"+mc.name, func(t *testing.T) {
				mock := executor.NewMock()
				mock.StdoutFn = func(_ string, _ []string) []byte {
					return []byte("should not run")
				}

				result, err := r[field.tool](ctx, mock, json.RawMessage(field.params(mc.char)))
				if err != nil {
					t.Fatalf("Execute() returned error: %v", err)
				}
				if !result.IsError {
					t.Fatal("Execute() should return IsError=true for shell metacharacter")
				}
				if !strings.Contains(result.Content[0].Text, "contains forbidden character") {
					t.Errorf("error text should contain \"contains forbidden character\", got: %s", result.Content[0].Text)
				}
				if len(mock.Calls) > 0 {
					t.Error("executor should not be called for invalid input")
				}
			})
		}
	}
}

// TestFlagValueAllowedCharacters verifies that characters Rubeus flag values
// legitimately need ('/' in SPNs, '=' in OUs, '\' in DOMAIN\user, spaces)
// pass validation; only executor-forbidden metacharacters are rejected.
func TestFlagValueAllowedCharacters(t *testing.T) {
	ctx := context.Background()
	r := runners()

	tests := []struct {
		name   string
		tool   string
		params string
		check  func(call executor.MockCall) bool
	}{
		{
			name:   "BackslashDomainUser",
			tool:   "asktgt",
			params: `{"user": "CORP\\sqlsvc", "password": "p"}`,
			check: func(call executor.MockCall) bool {
				return call.Args[1] == "/user:CORP\\sqlsvc"
			},
		},
		{
			name:   "SlashDotService",
			tool:   "dump",
			params: `{"service": "cifs/dc01.corp.local"}`,
			check: func(call executor.MockCall) bool {
				return call.Args[1] == "/service:cifs/dc01.corp.local"
			},
		},
		{
			name:   "EqualsAndSpaceInOU",
			tool:   "asreproast",
			params: `{"ou": "OU=Service Accounts,DC=corp,DC=local"}`,
			check: func(call executor.MockCall) bool {
				return call.Args[1] == "/ou:OU=Service Accounts,DC=corp,DC=local"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("ok")
			}

			result, err := r[tt.tool](ctx, mock, json.RawMessage(tt.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if result.IsError {
				t.Fatalf("value should pass validation, got: %s", result.Content[0].Text)
			}
			if len(mock.Calls) != 1 {
				t.Fatalf("expected 1 executor call, got %d", len(mock.Calls))
			}
			if !tt.check(mock.Calls[0]) {
				t.Errorf("unexpected args: %v", mock.Calls[0].Args)
			}
		})
	}
}

func TestExecuteRunError(t *testing.T) {
	ctx := context.Background()
	r := runners()

	for name := range r {
		t.Run(name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.ErrFn = func(_ string, _ []string) error {
				return errRubeusBoom
			}

			var params json.RawMessage
			switch name {
			case "asktgt":
				params = json.RawMessage(`{"user": "u", "password": "p"}`)
			case "describe":
				params = json.RawMessage(`{"ticket": "` + validTicket + `"}`)
			default:
				params = json.RawMessage(`{}`)
			}

			result, err := r[name](ctx, mock, params)
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("%s should surface executor failures as IsError", name)
			}
			if !strings.Contains(result.Content[0].Text, "failed") {
				t.Errorf("error text should mention failure, got: %s", result.Content[0].Text)
			}
		})
	}
}

var errRubeusBoom = &rubeusTestError{"simulated executor failure"}

type rubeusTestError struct{ msg string }

func (e *rubeusTestError) Error() string { return e.msg }
