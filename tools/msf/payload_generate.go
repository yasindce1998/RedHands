package msf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// payloadFormats are the msfvenom output formats (msfvenom --list formats).
var payloadFormats = []string{
	"raw", "c", "csharp", "dw", "dword", "elf", "elfso", "exe", "exe-only",
	"exe-service", "exe-small", "exe-x64", "exe-x86", "hex", "java", "js_be",
	"js_le", "macho", "masm", "num", "perl", "pl", "powershell", "ps1", "py",
	"python", "ruby", "rb", "sh", "vbapplication", "vbscript", "war",
}

// payloadArchs are the msfvenom target architectures (msfvenom --list archs).
var payloadArchs = []string{
	"x86", "x64", "armle", "armbe", "aarch64", "mipsle", "mipsbe",
	"ppc", "ppc64", "sparc", "sparc64",
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// PayloadGenerateTool generates Metasploit payloads with msfvenom.
type PayloadGenerateTool struct {
	exec executor.Executor
}

// NewPayloadGenerate creates the msfvenom payload generation tool.
func NewPayloadGenerate(exec executor.Executor) *PayloadGenerateTool {
	return &PayloadGenerateTool{exec: exec}
}

func (t *PayloadGenerateTool) Name() string { return "msf_payload_generate" }

func (t *PayloadGenerateTool) Description() string {
	return "Generate a Metasploit payload with msfvenom (payload, KEY=VALUE options such as LHOST/LPORT, " +
		"output format, architecture, platform, encoder with iteration count, badchars, nopsled) and write it to " +
		"the required output file, reporting the generated file's path, size and SHA-256. " +
		"HIGH IMPACT: this produces offensive artifacts (stagers, implants, shellcode) that EDR/AV may flag; " +
		"use only in authorized engagements and handle generated binaries per engagement rules; approval-gated."
}

func (t *PayloadGenerateTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"payload": {
				"type": "string",
				"pattern": "^[a-z0-9][a-z0-9/_.+-]*$",
				"description": "Metasploit payload name, e.g. linux/x64/meterpreter/reverse_tcp, windows/x64/shell_reverse_tcp or cmd/unix/reverse_bash (discover with msf_payload_list)"
			},
			"options": {
				"type": "object",
				"additionalProperties": {"type": "string"},
				"description": "Payload options as KEY=VALUE datastore pairs (LHOST, LPORT, RHOSTS, ...); keys must match ^[A-Za-z][A-Za-z0-9_]*$"
			},
			"format": {
				"type": "string",
				"enum": ["raw", "c", "csharp", "dw", "dword", "elf", "elfso", "exe", "exe-only", "exe-service", "exe-small", "exe-x64", "exe-x86", "hex", "java", "js_be", "js_le", "macho", "masm", "num", "perl", "pl", "powershell", "ps1", "py", "python", "ruby", "rb", "sh", "vbapplication", "vbscript", "war"],
				"description": "Output format (default: raw)"
			},
			"arch": {
				"type": "string",
				"enum": ["x86", "x64", "armle", "armbe", "aarch64", "mipsle", "mipsbe", "ppc", "ppc64", "sparc", "sparc64"],
				"description": "Target architecture"
			},
			"platform": {
				"type": "string",
				"description": "Target platform, e.g. linux, windows, osx, nodejs"
			},
			"encoder": {
				"type": "string",
				"description": "Encoder module, e.g. x86/shikata_ga_nai (discover with msf_payload_list kind=encoders)"
			},
			"iterations": {
				"type": "integer",
				"minimum": 0,
				"maximum": 20,
				"description": "Number of encoding iterations (0 = do not encode)"
			},
			"badchars": {
				"type": "string",
				"pattern": "^(\\\\x[0-9a-fA-F]{2})*$",
				"description": "Bad characters to avoid, as concatenated hex escapes, e.g. \\x00\\xff"
			},
			"nopsled": {
				"type": "integer",
				"minimum": 0,
				"maximum": 256,
				"description": "Prepend this many bytes of nopsled to the payload (0 = none)"
			},
			"smallest": {
				"type": "boolean",
				"description": "Generate the smallest possible payload"
			},
			"output": {
				"type": "string",
				"description": "Required output file path (parent directory must exist); the payload is written here and its SHA-256 reported"
			},
			"keep": {
				"type": "boolean",
				"description": "Preserve the output file when generating exe formats (do not treat it as a temporary template)"
			}
		},
		"required": ["payload", "output"]
	}`)
}

type payloadGenerateInput struct {
	Payload    string            `json:"payload"`
	Options    map[string]string `json:"options"`
	Format     string            `json:"format"`
	Arch       string            `json:"arch"`
	Platform   string            `json:"platform"`
	Encoder    string            `json:"encoder"`
	Iterations int               `json:"iterations"`
	Badchars   string            `json:"badchars"`
	Nopsled    int               `json:"nopsled"`
	Smallest   bool              `json:"smallest"`
	Output     string            `json:"output"`
	Keep       bool              `json:"keep"`
}

func (t *PayloadGenerateTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input payloadGenerateInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid parameters: " + err.Error()), nil
	}

	if err := validatePayloadName(input.Payload, "payload"); err != nil {
		return errorResult(err.Error()), nil
	}
	optionKeys, err := validateOptionMap(input.Options, "options")
	if err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Format != "" && !containsString(payloadFormats, input.Format) {
		return errorResult(fmt.Sprintf("invalid format %q: must be one of %s", input.Format, strings.Join(payloadFormats, ", "))), nil
	}
	if input.Arch != "" && !containsString(payloadArchs, input.Arch) {
		return errorResult(fmt.Sprintf("invalid arch %q: must be one of %s", input.Arch, strings.Join(payloadArchs, ", "))), nil
	}
	if input.Platform != "" && !platformRegex.MatchString(input.Platform) {
		return errorResult(fmt.Sprintf("invalid platform %q: must match ^[A-Za-z0-9][A-Za-z0-9_.+-]*$ (e.g. linux, windows)", input.Platform)), nil
	}
	if input.Encoder != "" {
		if err := validatePayloadName(input.Encoder, "encoder"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if input.Iterations < 0 || input.Iterations > 20 {
		return errorResult("iterations must be between 0 and 20"), nil
	}
	if input.Badchars != "" && !badcharsRegex.MatchString(input.Badchars) {
		return errorResult(`invalid badchars: must be concatenated hex escapes such as \x00\xff`), nil
	}
	if input.Nopsled < 0 || input.Nopsled > 256 {
		return errorResult("nopsled must be between 0 and 256 bytes"), nil
	}
	if err := validateOutputPath(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}

	// Canonical msfvenom argument order:
	// -p PAYLOAD [OPTION=VALUE ...] [-f FORMAT] [-o outfile] [-a ARCH]
	// [--platform PLATFORM] [-e ENCODER] [-i N] [-b BADCHARS] [-n NOPSLED]
	// [--smallest] [--keep]
	args := []string{"-p", input.Payload}
	for _, k := range optionKeys {
		args = append(args, k+"="+input.Options[k])
	}
	if input.Format != "" {
		args = append(args, "-f", input.Format)
	}
	args = append(args, "-o", input.Output)
	if input.Arch != "" {
		args = append(args, "-a", input.Arch)
	}
	if input.Platform != "" {
		args = append(args, "--platform", input.Platform)
	}
	if input.Encoder != "" {
		args = append(args, "-e", input.Encoder)
	}
	if input.Iterations > 0 {
		args = append(args, "-i", strconv.Itoa(input.Iterations))
	}
	if input.Badchars != "" {
		args = append(args, "-b", input.Badchars)
	}
	if input.Nopsled > 0 {
		args = append(args, "-n", strconv.Itoa(input.Nopsled))
	}
	if input.Smallest {
		args = append(args, "--smallest")
	}
	if input.Keep {
		args = append(args, "--keep")
	}

	result, err := t.exec.Run(ctx, "msfvenom", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("msfvenom failed: %v\n%s", err, stderr)), nil
	}

	payload, err := os.ReadFile(input.Output)
	if err != nil {
		return errorResult(fmt.Sprintf("msfvenom reported success but the output file is unreadable: %v", err)), nil
	}
	sum := sha256.Sum256(payload)

	var sb strings.Builder
	sb.WriteString("## Metasploit Payload Generated\n\n")
	fmt.Fprintf(&sb, "**Payload**: %s\n", input.Payload)
	if input.Format != "" {
		fmt.Fprintf(&sb, "**Format**: %s\n", input.Format)
	}
	fmt.Fprintf(&sb, "**Output**: %s\n", input.Output)
	fmt.Fprintf(&sb, "**Size**: %d bytes\n", len(payload))
	fmt.Fprintf(&sb, "**SHA-256**: %s\n", hex.EncodeToString(sum[:]))
	if out := strings.TrimSpace(string(result.Stdout)); out != "" {
		sb.WriteString("\n```\n" + out + "\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
