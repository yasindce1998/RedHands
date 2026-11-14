// Package hydra wraps the THC-Hydra online password attack tool for use in
// authorized engagements only.
//
// Hydra's syntax is positional: options first, then the target, the service
// module, and optionally a module OPTION string after the service (some
// services such as http-post-form require it). The module OPTION may contain
// characters like ':', '^', '/', '=' and spaces (e.g. the http-form format
// "/login.php:user=^PASS:failed") which are all legal executor arguments;
// only the executor's forbidden metacharacter set is rejected.
package hydra

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// AttackInput models the hydra_attack parameters.
type AttackInput struct {
	Target         string `json:"target"`
	Service        string `json:"service"`
	Username       string `json:"username,omitempty"`
	UserFile       string `json:"user_file,omitempty"`
	Password       string `json:"password,omitempty"`
	PasswordFile   string `json:"password_file,omitempty"`
	EmptyPasswords bool   `json:"empty_passwords,omitempty"`
	TrySame        bool   `json:"try_same,omitempty"`
	LoginReverse   bool   `json:"login_reverse,omitempty"`
	Tasks          int    `json:"tasks,omitempty"`
	Port           int    `json:"port,omitempty"`
	StopOnSuccess  bool   `json:"stop_on_success,omitempty"`
	SSL            bool   `json:"ssl,omitempty"`
	WaitTime       int    `json:"wait_time,omitempty"`
	ServiceOption  string `json:"service_option,omitempty"`
}

// AttackTool wraps the hydra binary for online password attacks.
type AttackTool struct {
	exec executor.Executor
}

// NewAttack constructs a hydra_attack tool.
func NewAttack(exec executor.Executor) *AttackTool {
	return &AttackTool{exec: exec}
}

func (t *AttackTool) Name() string { return "hydra_attack" }

func (t *AttackTool) Description() string {
	return "Run a THC-Hydra online password attack (dictionary or login-derived) against a network service " +
		"login (ssh, ftp, smb, rdp, http-form, databases, and more). Supports username/password wordlists, " +
		"-e nsr login-derived guesses, parallel tasks, custom ports, and per-service module options such as " +
		"the http-post-form string \"/login.php:user=^PASS:failed\". HIGH IMPACT: online password guessing can " +
		"lock out accounts and is highly visible to defenders; use only against explicitly authorized targets " +
		"within an active engagement scope; approval-gated."
}

func (t *AttackTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target IP, hostname, or CIDR range to attack"
			},
			"service": {
				"type": "string",
				"description": "Hydra service module to attack",
				"enum": ["ssh", "ftp", "telnet", "smtp", "http-get", "http-post-form", "https-get", "https-post-form", "smb", "rdp", "mysql", "mssql", "postgresql", "ldap3", "vnc", "redis", "snmp"]
			},
			"username": {
				"type": "string",
				"description": "Single login to try (-l)"
			},
			"user_file": {
				"type": "string",
				"description": "Path to a local file with logins, one per line (-L)"
			},
			"password": {
				"type": "string",
				"description": "Single password to try (-p)"
			},
			"password_file": {
				"type": "string",
				"description": "Path to a local file with passwords, one per line (-P)"
			},
			"empty_passwords": {
				"type": "boolean",
				"description": "Also try an empty password (-e n)"
			},
			"try_same": {
				"type": "boolean",
				"description": "Also try the login as password (-e s)"
			},
			"login_reverse": {
				"type": "boolean",
				"description": "Also try the reversed login as password (-e r)"
			},
			"tasks": {
				"type": "integer",
				"description": "Parallel connections (1-64, default 16) (-t)"
			},
			"port": {
				"type": "integer",
				"description": "Override the service default port (-s)"
			},
			"stop_on_success": {
				"type": "boolean",
				"description": "Stop the attack when a valid pair is found (-f)"
			},
			"ssl": {
				"type": "boolean",
				"description": "Connect via SSL (-S)"
			},
			"wait_time": {
				"type": "integer",
				"description": "Seconds to wait between requests, 1-3600 (-W)"
			},
			"service_option": {
				"type": "string",
				"description": "Optional module OPTION passed positionally after the service. Formats: http-post-form/https-post-form use \"path:login^PASS:failstring\" (e.g. \"/login.php:user=^PASS:incorrect\"), http-get-form/https-get-form use \"path:login^PASS:failstring\", other services take simple option tokens (e.g. PLAIN for imap, /LM for snmp). Colons, carets, slashes, equals and spaces are allowed; shell metacharacters are rejected."
			}
		},
		"required": ["target", "service"]
	}`)
}

func (t *AttackTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input AttackInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Service == "" {
		return errorResult("service is required"), nil
	}
	if !validServices[input.Service] {
		return errorResult(fmt.Sprintf("service must be one of: %s", strings.Join(serviceList, ", "))), nil
	}
	if input.Username != "" && input.UserFile != "" {
		return errorResult("username and user_file are mutually exclusive (hydra accepts only one of -l/-L)"), nil
	}
	if input.Username == "" && input.UserFile == "" {
		return errorResult("either username or user_file is required"), nil
	}
	if input.Password != "" && input.PasswordFile != "" {
		return errorResult("password and password_file are mutually exclusive (hydra accepts only one of -p/-P)"), nil
	}
	hasPasswordSource := input.Password != "" || input.PasswordFile != "" ||
		input.EmptyPasswords || input.TrySame || input.LoginReverse
	if !hasPasswordSource {
		return errorResult("no password source: set password, password_file, or at least one of empty_passwords/try_same/login_reverse"), nil
	}

	if err := validateSafeString(input.Username, "username"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Password, "password"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.UserFile != "" {
		if err := validateExistingFile(input.UserFile, "user_file"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if input.PasswordFile != "" {
		if err := validateExistingFile(input.PasswordFile, "password_file"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if input.Tasks != 0 {
		if input.Tasks < 1 || input.Tasks > 64 {
			return errorResult("tasks must be between 1 and 64"), nil
		}
	}
	if input.Port != 0 {
		if input.Port < 1 || input.Port > 65535 {
			return errorResult("port must be between 1 and 65535"), nil
		}
	}
	if input.WaitTime != 0 {
		if input.WaitTime < 1 || input.WaitTime > 3600 {
			return errorResult("wait_time must be between 1 and 3600 seconds"), nil
		}
	}
	if err := validateSafeString(input.ServiceOption, "service_option"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{}
	if input.Username != "" {
		args = append(args, "-l", input.Username)
	}
	if input.UserFile != "" {
		args = append(args, "-L", input.UserFile)
	}
	if input.Password != "" {
		args = append(args, "-p", input.Password)
	}
	if input.PasswordFile != "" {
		args = append(args, "-P", input.PasswordFile)
	}
	// -e takes the combined letter string in canonical nsr order.
	var eModes string
	if input.EmptyPasswords {
		eModes += "n"
	}
	if input.TrySame {
		eModes += "s"
	}
	if input.LoginReverse {
		eModes += "r"
	}
	if eModes != "" {
		args = append(args, "-e", eModes)
	}
	if input.Tasks != 0 {
		args = append(args, "-t", strconv.Itoa(input.Tasks))
	}
	if input.Port != 0 {
		args = append(args, "-s", strconv.Itoa(input.Port))
	}
	if input.StopOnSuccess {
		args = append(args, "-f")
	}
	if input.SSL {
		args = append(args, "-S")
	}
	if input.WaitTime != 0 {
		args = append(args, "-W", strconv.Itoa(input.WaitTime))
	}
	// Positional tail: target, service, then the optional module OPTION.
	args = append(args, input.Target, input.Service)
	if input.ServiceOption != "" {
		args = append(args, input.ServiceOption)
	}

	result, err := t.exec.Run(ctx, "hydra", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("hydra attack failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Hydra Password Attack\n\n")
	fmt.Fprintf(&sb, "**Target**: %s\n", input.Target)
	fmt.Fprintf(&sb, "**Service**: %s\n\n", input.Service)
	if output == "" {
		sb.WriteString("Attack completed with no output.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}
