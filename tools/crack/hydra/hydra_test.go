package hydra

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
)

func TestName(t *testing.T) {
	mock := executor.NewMock()
	if got := NewAttack(mock).Name(); got != "hydra_attack" {
		t.Errorf("Name() = %q, want %q", got, "hydra_attack")
	}
}

func TestDescription(t *testing.T) {
	mock := executor.NewMock()
	desc := NewAttack(mock).Description()
	if desc == "" {
		t.Fatal("Description() returned empty string")
	}
	for _, want := range []string{"HIGH IMPACT", "authorized", "approval-gated"} {
		if !strings.Contains(desc, want) {
			t.Errorf("Description() must mention %q, got: %s", want, desc)
		}
	}
}

func TestInputSchema(t *testing.T) {
	mock := executor.NewMock()
	schema := NewAttack(mock).InputSchema()

	var parsed map[string]interface{}
	if err := json.Unmarshal(schema, &parsed); err != nil {
		t.Fatalf("InputSchema() is not valid JSON: %v", err)
	}
	if parsed["type"] != "object" {
		t.Errorf("InputSchema() type = %v, want \"object\"", parsed["type"])
	}
	props, ok := parsed["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("InputSchema() missing \"properties\" key")
	}
	service, ok := props["service"].(map[string]interface{})
	if !ok {
		t.Fatal("InputSchema() missing service property")
	}
	enum, ok := service["enum"].([]interface{})
	if !ok || len(enum) != len(serviceList) {
		t.Fatalf("service property must carry an enum of %d services, got %v", len(serviceList), service["enum"])
	}
	required, ok := parsed["required"].([]interface{})
	if !ok || len(required) != 2 {
		t.Fatalf("InputSchema() must require target and service, got %v", parsed["required"])
	}
}

func TestExecuteExactArgs(t *testing.T) {
	ctx := context.Background()

	wordlist := filepath.Join(t.TempDir(), "passwords.txt")
	if err := os.WriteFile(wordlist, []byte("admin\npassword123\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		params   string
		expected []string
	}{
		{
			name:   "SingleLoginAndPassword",
			params: `{"target": "10.0.0.5", "service": "ssh", "username": "admin", "password": "password123"}`,
			expected: []string{
				"-l", "admin",
				"-p", "password123",
				"10.0.0.5", "ssh",
			},
		},
		{
			name:   "UserAndPasswordFiles",
			params: `{"target": "10.0.0.5", "service": "ftp", "user_file": "` + wordlist + `", "password_file": "` + wordlist + `"}`,
			expected: []string{
				"-L", wordlist,
				"-P", wordlist,
				"10.0.0.5", "ftp",
			},
		},
		{
			name:   "EmptyPasswordModes",
			params: `{"target": "10.0.0.5", "service": "ssh", "username": "admin", "empty_passwords": true, "try_same": true, "login_reverse": true}`,
			expected: []string{
				"-l", "admin",
				"-e", "nsr",
				"10.0.0.5", "ssh",
			},
		},
		{
			name:   "TrySameOnly",
			params: `{"target": "10.0.0.5", "service": "smb", "username": "admin", "try_same": true}`,
			expected: []string{
				"-l", "admin",
				"-e", "s",
				"10.0.0.5", "smb",
			},
		},
		{
			name:   "AllOptions",
			params: `{"target": "10.0.0.5", "service": "rdp", "username": "admin", "password": "P@ss", "tasks": 32, "port": 33890, "stop_on_success": true, "ssl": false, "wait_time": 5}`,
			expected: []string{
				"-l", "admin",
				"-p", "P@ss",
				"-t", "32",
				"-s", "33890",
				"-f",
				"-W", "5",
				"10.0.0.5", "rdp",
			},
		},
		{
			name:   "HttpPostFormOption",
			params: `{"target": "web.corp.local", "service": "http-post-form", "username": "admin", "password": "test", "service_option": "/login.php:user=^PASS:incorrect"}`,
			expected: []string{
				"-l", "admin",
				"-p", "test",
				"web.corp.local", "http-post-form", "/login.php:user=^PASS:incorrect",
			},
		},
		{
			name:   "SSL",
			params: `{"target": "10.0.0.5", "service": "https-get", "username": "admin", "password": "test", "ssl": true}`,
			expected: []string{
				"-l", "admin",
				"-p", "test",
				"-S",
				"10.0.0.5", "https-get",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("[data][ssh] host: 10.0.0.5   login: admin   password: password123")
			}
			tool := NewAttack(mock)

			result, err := tool.Execute(ctx, json.RawMessage(tt.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if result.IsError {
				t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
			}
			if len(mock.Calls) != 1 {
				t.Fatalf("expected exactly 1 executor call, got %d", len(mock.Calls))
			}
			if mock.Calls[0].Binary != "hydra" {
				t.Errorf("expected binary %q, got %q", "hydra", mock.Calls[0].Binary)
			}
			if !reflect.DeepEqual(mock.Calls[0].Args, tt.expected) {
				t.Errorf("args mismatch:\n got:  %v\n want: %v", mock.Calls[0].Args, tt.expected)
			}
			if !strings.Contains(result.Content[0].Text, "password123") {
				t.Errorf("result does not contain hydra stdout")
			}
		})
	}
}

func TestExecuteRequiresCredentials(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		params    string
		wantError string
	}{
		{
			name:      "NoLoginSource",
			params:    `{"target": "10.0.0.5", "service": "ssh", "password": "x"}`,
			wantError: "either username or user_file is required",
		},
		{
			name:      "LoginAndUserFile",
			params:    `{"target": "10.0.0.5", "service": "ssh", "username": "a", "user_file": "/tmp/users.txt", "password": "x"}`,
			wantError: "mutually exclusive",
		},
		{
			name:      "PasswordAndPasswordFile",
			params:    `{"target": "10.0.0.5", "service": "ssh", "username": "a", "password": "x", "password_file": "/tmp/pw.txt"}`,
			wantError: "mutually exclusive",
		},
		{
			name:      "NoPasswordSource",
			params:    `{"target": "10.0.0.5", "service": "ssh", "username": "a"}`,
			wantError: "no password source",
		},
		{
			name:      "MissingTarget",
			params:    `{"service": "ssh", "username": "a", "password": "x"}`,
			wantError: "target is required",
		},
		{
			name:      "MissingService",
			params:    `{"target": "10.0.0.5", "username": "a", "password": "x"}`,
			wantError: "service is required",
		},
		{
			name:      "TasksTooHigh",
			params:    `{"target": "10.0.0.5", "service": "ssh", "username": "a", "password": "x", "tasks": 65}`,
			wantError: "tasks must be between 1 and 64",
		},
		{
			name:      "TasksTooLow",
			params:    `{"target": "10.0.0.5", "service": "ssh", "username": "a", "password": "x", "tasks": 0}`,
			wantError: "",
		},
		{
			name:      "TasksNegative",
			params:    `{"target": "10.0.0.5", "service": "ssh", "username": "a", "password": "x", "tasks": -1}`,
			wantError: "tasks must be between 1 and 64",
		},
		{
			name:      "PortOutOfRange",
			params:    `{"target": "10.0.0.5", "service": "ssh", "username": "a", "password": "x", "port": 70000}`,
			wantError: "port must be between 1 and 65535",
		},
		{
			name:      "WaitTimeOutOfRange",
			params:    `{"target": "10.0.0.5", "service": "ssh", "username": "a", "password": "x", "wait_time": 0}`,
			wantError: "",
		},
		{
			name:      "WaitTimeTooHigh",
			params:    `{"target": "10.0.0.5", "service": "ssh", "username": "a", "password": "x", "wait_time": 3601}`,
			wantError: "wait_time must be between 1 and 3600",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewAttack(mock)

			result, err := tool.Execute(ctx, json.RawMessage(tt.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if tt.wantError == "" {
				// Zero values are treated as unset and must succeed.
				if result.IsError {
					t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
				}
				return
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

func TestServiceEnum(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		service string
		valid   bool
	}{
		{"ssh", "ssh", true},
		{"http-post-form", "http-post-form", true},
		{"snmp", "snmp", true},
		{"unknown", "http-head", false},
		{"empty", "", false},
		{"path-traversal", "../../etc", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewAttack(mock)
			params := `{"target": "10.0.0.5", "service": "` + tt.service + `", "username": "a", "password": "x"}`

			result, err := tool.Execute(ctx, json.RawMessage(params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if tt.valid {
				if result.IsError {
					t.Fatalf("service %q should be accepted: %s", tt.service, result.Content[0].Text)
				}
				return
			}
			if !result.IsError {
				t.Fatalf("service %q should be rejected", tt.service)
			}
			if tt.service == "" {
				// Empty service short-circuits to "service is required".
				if !strings.Contains(result.Content[0].Text, "service is required") {
					t.Errorf("error text should mention required service, got: %s", result.Content[0].Text)
				}
				return
			}
			// The error must enumerate every valid service so callers can self-correct.
			for _, svc := range serviceList {
				if !strings.Contains(result.Content[0].Text, svc) {
					t.Errorf("error text should list valid service %q, got: %s", svc, result.Content[0].Text)
				}
			}
			if len(mock.Calls) > 0 {
				t.Error("executor should not be called for invalid service")
			}
		})
	}
}

func TestWordlistFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	users := filepath.Join(dir, "users.txt")
	if err := os.WriteFile(users, []byte("admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		params    string
		wantError string
	}{
		{
			name:      "UserFileExists",
			params:    `{"target": "10.0.0.5", "service": "ssh", "user_file": "` + users + `", "password": "x"}`,
			wantError: "",
		},
		{
			name:      "PasswordFileMissing",
			params:    `{"target": "10.0.0.5", "service": "ssh", "username": "a", "password_file": "` + filepath.Join(dir, "missing.txt") + `"}`,
			wantError: "password_file does not exist",
		},
		{
			name:      "UserFileIsDirectory",
			params:    `{"target": "10.0.0.5", "service": "ssh", "user_file": "` + dir + `", "password": "x"}`,
			wantError: "user_file is a directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewAttack(mock)

			result, err := tool.Execute(ctx, json.RawMessage(tt.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if tt.wantError == "" {
				if result.IsError {
					t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
				}
				return
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

func TestShellInjection(t *testing.T) {
	ctx := context.Background()

	// The executor's full forbidden set. Every character must be rejected in
	// every free-form string field.
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
		params func(char string) string
	}{
		{"target", func(c string) string {
			return `{"target": "10.0.0.5` + c + `evil", "service": "ssh", "username": "a", "password": "x"}`
		}},
		{"username", func(c string) string {
			return `{"target": "10.0.0.5", "service": "ssh", "username": "a` + c + `b", "password": "x"}`
		}},
		{"password", func(c string) string {
			return `{"target": "10.0.0.5", "service": "ssh", "username": "a", "password": "x` + c + `y"}`
		}},
		{"user_file", func(c string) string {
			return `{"target": "10.0.0.5", "service": "ssh", "user_file": "/tmp/users` + c + `.txt", "password": "x"}`
		}},
		{"password_file", func(c string) string {
			return `{"target": "10.0.0.5", "service": "ssh", "username": "a", "password_file": "/tmp/pw` + c + `.txt"}`
		}},
		{"service_option", func(c string) string {
			return `{"target": "10.0.0.5", "service": "http-post-form", "username": "a", "password": "x", "service_option": "/l:u=^PASS:f` + c + `ail"}`
		}},
	}

	for _, field := range fields {
		for _, mc := range metachars {
			t.Run(field.name+"-"+mc.name, func(t *testing.T) {
				mock := executor.NewMock()
				mock.StdoutFn = func(_ string, _ []string) []byte {
					return []byte("should not run")
				}
				tool := NewAttack(mock)

				result, err := tool.Execute(ctx, json.RawMessage(field.params(mc.char)))
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

// TestServiceOptionAllowedCharacters verifies that the characters hydra's
// module OPTION strings legitimately need (^, :, /, =, spaces) pass
// validation even though they look exotic; only executor-forbidden
// metacharacters are rejected.
func TestServiceOptionAllowedCharacters(t *testing.T) {
	ctx := context.Background()

	options := []struct {
		name    string
		service string
		option  string
	}{
		{"http-post-form-caret-colon", "http-post-form", "/login/index.php:user=^PASS:incorrect"},
		{"http-get-form-caret-colon-slash", "http-get", "/desktop/login/:user=^PASS:failed"},
		{"snmp-option", "snmp", "/LM"},
	}

	for _, tt := range options {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("done")
			}
			tool := NewAttack(mock)
			params := `{"target": "10.0.0.5", "service": "` + tt.service + `", "username": "a", "password": "x", "service_option": "` + tt.option + `"}`

			result, err := tool.Execute(ctx, json.RawMessage(params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if result.IsError {
				t.Fatalf("service_option %q should pass validation, got: %s", tt.option, result.Content[0].Text)
			}
			call := mock.LastCall()
			if call.Args[len(call.Args)-1] != tt.option {
				t.Errorf("expected service option %q as final positional arg, got %v", tt.option, call.Args)
			}
		})
	}
}

func TestExecuteRunError(t *testing.T) {
	ctx := context.Background()
	mock := executor.NewMock()
	mock.ErrFn = func(_ string, _ []string) error {
		return errBoom
	}
	tool := NewAttack(mock)

	result, err := tool.Execute(ctx, json.RawMessage(`{"target": "10.0.0.5", "service": "ssh", "username": "a", "password": "x"}`))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Fatal("Execute() should return IsError=true when the executor fails")
	}
	if !strings.Contains(result.Content[0].Text, "hydra attack failed") {
		t.Errorf("error text should mention hydra attack failure, got: %s", result.Content[0].Text)
	}
}

var errBoom = &testError{"simulated executor failure"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
