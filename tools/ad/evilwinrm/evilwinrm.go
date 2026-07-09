package evilwinrm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// --- ShellTool ---

type ShellInput struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Command  string `json:"command"`
	SSL      bool   `json:"ssl,omitempty"`
}

type ShellTool struct {
	exec executor.Executor
}

func NewShell(exec executor.Executor) *ShellTool {
	return &ShellTool{exec: exec}
}

func (t *ShellTool) Name() string { return "evilwinrm_shell" }

func (t *ShellTool) Description() string {
	return "Execute a command on a remote Windows host via WinRM using Evil-WinRM. Supports password and pass-the-hash authentication."
}

func (t *ShellTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"host": {
				"type": "string",
				"description": "Target host IP or hostname"
			},
			"username": {
				"type": "string",
				"description": "Username for authentication"
			},
			"password": {
				"type": "string",
				"description": "Password for authentication"
			},
			"hash": {
				"type": "string",
				"description": "NTLM hash for pass-the-hash authentication"
			},
			"domain": {
				"type": "string",
				"description": "Active Directory domain"
			},
			"command": {
				"type": "string",
				"description": "Command to execute on the remote host"
			},
			"ssl": {
				"type": "boolean",
				"description": "Use SSL for the WinRM connection"
			}
		},
		"required": ["host", "username", "command"]
	}`)
}

func (t *ShellTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ShellInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Host); err != nil {
		return errorResult(fmt.Sprintf("host: %s", err.Error())), nil
	}
	if err := validateInput(input.Username); err != nil {
		return errorResult(fmt.Sprintf("username: %s", err.Error())), nil
	}
	if err := validateInput(input.Command); err != nil {
		return errorResult(fmt.Sprintf("command: %s", err.Error())), nil
	}

	args := []string{"-i", input.Host, "-u", input.Username}
	if input.Password != "" {
		if err := validateInput(input.Password); err != nil {
			return errorResult(fmt.Sprintf("password: %s", err.Error())), nil
		}
		args = append(args, "-p", input.Password)
	}
	if input.Hash != "" {
		if err := validateInput(input.Hash); err != nil {
			return errorResult(fmt.Sprintf("hash: %s", err.Error())), nil
		}
		args = append(args, "-H", input.Hash)
	}
	if input.Domain != "" {
		if err := validateInput(input.Domain); err != nil {
			return errorResult(fmt.Sprintf("domain: %s", err.Error())), nil
		}
		args = append(args, "-d", input.Domain)
	}
	if input.SSL {
		args = append(args, "-S")
	}
	args = append(args, "-c", input.Command)

	result, err := t.exec.Run(ctx, "evil-winrm", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("evil-winrm shell failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Evil-WinRM Shell\n\n")
	if output == "" {
		sb.WriteString("Command executed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- UploadTool ---

type UploadInput struct {
	Host       string `json:"host"`
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Domain     string `json:"domain,omitempty"`
	LocalPath  string `json:"local_path"`
	RemotePath string `json:"remote_path"`
	SSL        bool   `json:"ssl,omitempty"`
}

type UploadTool struct {
	exec executor.Executor
}

func NewUpload(exec executor.Executor) *UploadTool {
	return &UploadTool{exec: exec}
}

func (t *UploadTool) Name() string { return "evilwinrm_upload" }

func (t *UploadTool) Description() string {
	return "Upload a file to a remote Windows host via WinRM using Evil-WinRM."
}

func (t *UploadTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"host": {
				"type": "string",
				"description": "Target host IP or hostname"
			},
			"username": {
				"type": "string",
				"description": "Username for authentication"
			},
			"password": {
				"type": "string",
				"description": "Password for authentication"
			},
			"hash": {
				"type": "string",
				"description": "NTLM hash for pass-the-hash authentication"
			},
			"domain": {
				"type": "string",
				"description": "Active Directory domain"
			},
			"local_path": {
				"type": "string",
				"description": "Local file path to upload"
			},
			"remote_path": {
				"type": "string",
				"description": "Remote destination path"
			},
			"ssl": {
				"type": "boolean",
				"description": "Use SSL for the WinRM connection"
			}
		},
		"required": ["host", "username", "local_path", "remote_path"]
	}`)
}

func (t *UploadTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input UploadInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Host); err != nil {
		return errorResult(fmt.Sprintf("host: %s", err.Error())), nil
	}
	if err := validateInput(input.Username); err != nil {
		return errorResult(fmt.Sprintf("username: %s", err.Error())), nil
	}
	if err := validateInput(input.LocalPath); err != nil {
		return errorResult(fmt.Sprintf("local_path: %s", err.Error())), nil
	}
	if err := validateInput(input.RemotePath); err != nil {
		return errorResult(fmt.Sprintf("remote_path: %s", err.Error())), nil
	}

	args := []string{"-i", input.Host, "-u", input.Username}
	if input.Password != "" {
		if err := validateInput(input.Password); err != nil {
			return errorResult(fmt.Sprintf("password: %s", err.Error())), nil
		}
		args = append(args, "-p", input.Password)
	}
	if input.Hash != "" {
		if err := validateInput(input.Hash); err != nil {
			return errorResult(fmt.Sprintf("hash: %s", err.Error())), nil
		}
		args = append(args, "-H", input.Hash)
	}
	if input.Domain != "" {
		if err := validateInput(input.Domain); err != nil {
			return errorResult(fmt.Sprintf("domain: %s", err.Error())), nil
		}
		args = append(args, "-d", input.Domain)
	}
	if input.SSL {
		args = append(args, "-S")
	}
	uploadCmd := fmt.Sprintf("upload %s %s", input.LocalPath, input.RemotePath)
	args = append(args, "-e", uploadCmd)

	result, err := t.exec.Run(ctx, "evil-winrm", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("evil-winrm upload failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Evil-WinRM Upload\n\n")
	sb.WriteString(fmt.Sprintf("Uploaded `%s` -> `%s`\n\n", input.LocalPath, input.RemotePath))
	if output != "" {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- DownloadTool ---

type DownloadInput struct {
	Host       string `json:"host"`
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Domain     string `json:"domain,omitempty"`
	RemotePath string `json:"remote_path"`
	LocalPath  string `json:"local_path"`
	SSL        bool   `json:"ssl,omitempty"`
}

type DownloadTool struct {
	exec executor.Executor
}

func NewDownload(exec executor.Executor) *DownloadTool {
	return &DownloadTool{exec: exec}
}

func (t *DownloadTool) Name() string { return "evilwinrm_download" }

func (t *DownloadTool) Description() string {
	return "Download a file from a remote Windows host via WinRM using Evil-WinRM."
}

func (t *DownloadTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"host": {
				"type": "string",
				"description": "Target host IP or hostname"
			},
			"username": {
				"type": "string",
				"description": "Username for authentication"
			},
			"password": {
				"type": "string",
				"description": "Password for authentication"
			},
			"hash": {
				"type": "string",
				"description": "NTLM hash for pass-the-hash authentication"
			},
			"domain": {
				"type": "string",
				"description": "Active Directory domain"
			},
			"remote_path": {
				"type": "string",
				"description": "Remote file path to download"
			},
			"local_path": {
				"type": "string",
				"description": "Local destination path"
			},
			"ssl": {
				"type": "boolean",
				"description": "Use SSL for the WinRM connection"
			}
		},
		"required": ["host", "username", "remote_path", "local_path"]
	}`)
}

func (t *DownloadTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DownloadInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Host); err != nil {
		return errorResult(fmt.Sprintf("host: %s", err.Error())), nil
	}
	if err := validateInput(input.Username); err != nil {
		return errorResult(fmt.Sprintf("username: %s", err.Error())), nil
	}
	if err := validateInput(input.RemotePath); err != nil {
		return errorResult(fmt.Sprintf("remote_path: %s", err.Error())), nil
	}
	if err := validateInput(input.LocalPath); err != nil {
		return errorResult(fmt.Sprintf("local_path: %s", err.Error())), nil
	}

	args := []string{"-i", input.Host, "-u", input.Username}
	if input.Password != "" {
		if err := validateInput(input.Password); err != nil {
			return errorResult(fmt.Sprintf("password: %s", err.Error())), nil
		}
		args = append(args, "-p", input.Password)
	}
	if input.Hash != "" {
		if err := validateInput(input.Hash); err != nil {
			return errorResult(fmt.Sprintf("hash: %s", err.Error())), nil
		}
		args = append(args, "-H", input.Hash)
	}
	if input.Domain != "" {
		if err := validateInput(input.Domain); err != nil {
			return errorResult(fmt.Sprintf("domain: %s", err.Error())), nil
		}
		args = append(args, "-d", input.Domain)
	}
	if input.SSL {
		args = append(args, "-S")
	}
	downloadCmd := fmt.Sprintf("download %s %s", input.RemotePath, input.LocalPath)
	args = append(args, "-e", downloadCmd)

	result, err := t.exec.Run(ctx, "evil-winrm", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("evil-winrm download failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Evil-WinRM Download\n\n")
	sb.WriteString(fmt.Sprintf("Downloaded `%s` -> `%s`\n\n", input.RemotePath, input.LocalPath))
	if output != "" {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- DllInjectTool ---

type DllInjectInput struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Domain   string `json:"domain,omitempty"`
	DllPath  string `json:"dll_path"`
	SSL      bool   `json:"ssl,omitempty"`
}

type DllInjectTool struct {
	exec executor.Executor
}

func NewDllInject(exec executor.Executor) *DllInjectTool {
	return &DllInjectTool{exec: exec}
}

func (t *DllInjectTool) Name() string { return "evilwinrm_dll_inject" }

func (t *DllInjectTool) Description() string {
	return "Inject a DLL into the remote host via WinRM using Evil-WinRM. Loads the specified DLL path on the target."
}

func (t *DllInjectTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"host": {
				"type": "string",
				"description": "Target host IP or hostname"
			},
			"username": {
				"type": "string",
				"description": "Username for authentication"
			},
			"password": {
				"type": "string",
				"description": "Password for authentication"
			},
			"hash": {
				"type": "string",
				"description": "NTLM hash for pass-the-hash authentication"
			},
			"domain": {
				"type": "string",
				"description": "Active Directory domain"
			},
			"dll_path": {
				"type": "string",
				"description": "Path to the DLL to inject"
			},
			"ssl": {
				"type": "boolean",
				"description": "Use SSL for the WinRM connection"
			}
		},
		"required": ["host", "username", "dll_path"]
	}`)
}

func (t *DllInjectTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DllInjectInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Host); err != nil {
		return errorResult(fmt.Sprintf("host: %s", err.Error())), nil
	}
	if err := validateInput(input.Username); err != nil {
		return errorResult(fmt.Sprintf("username: %s", err.Error())), nil
	}
	if err := validateInput(input.DllPath); err != nil {
		return errorResult(fmt.Sprintf("dll_path: %s", err.Error())), nil
	}

	args := []string{"-i", input.Host, "-u", input.Username}
	if input.Password != "" {
		if err := validateInput(input.Password); err != nil {
			return errorResult(fmt.Sprintf("password: %s", err.Error())), nil
		}
		args = append(args, "-p", input.Password)
	}
	if input.Hash != "" {
		if err := validateInput(input.Hash); err != nil {
			return errorResult(fmt.Sprintf("hash: %s", err.Error())), nil
		}
		args = append(args, "-H", input.Hash)
	}
	if input.Domain != "" {
		if err := validateInput(input.Domain); err != nil {
			return errorResult(fmt.Sprintf("domain: %s", err.Error())), nil
		}
		args = append(args, "-d", input.Domain)
	}
	if input.SSL {
		args = append(args, "-S")
	}
	args = append(args, "-s", input.DllPath)

	result, err := t.exec.Run(ctx, "evil-winrm", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("evil-winrm dll inject failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Evil-WinRM DLL Inject\n\n")
	sb.WriteString(fmt.Sprintf("Injected DLL: `%s`\n\n", input.DllPath))
	if output != "" {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- PsExecTool ---

type PsExecInput struct {
	Host       string `json:"host"`
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Domain     string `json:"domain,omitempty"`
	ScriptPath string `json:"script_path"`
	SSL        bool   `json:"ssl,omitempty"`
}

type PsExecTool struct {
	exec executor.Executor
}

func NewPsExec(exec executor.Executor) *PsExecTool {
	return &PsExecTool{exec: exec}
}

func (t *PsExecTool) Name() string { return "evilwinrm_ps_exec" }

func (t *PsExecTool) Description() string {
	return "Execute a PowerShell script on a remote Windows host via WinRM using Evil-WinRM. Loads scripts from the specified path."
}

func (t *PsExecTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"host": {
				"type": "string",
				"description": "Target host IP or hostname"
			},
			"username": {
				"type": "string",
				"description": "Username for authentication"
			},
			"password": {
				"type": "string",
				"description": "Password for authentication"
			},
			"hash": {
				"type": "string",
				"description": "NTLM hash for pass-the-hash authentication"
			},
			"domain": {
				"type": "string",
				"description": "Active Directory domain"
			},
			"script_path": {
				"type": "string",
				"description": "Path to the PowerShell script to execute"
			},
			"ssl": {
				"type": "boolean",
				"description": "Use SSL for the WinRM connection"
			}
		},
		"required": ["host", "username", "script_path"]
	}`)
}

func (t *PsExecTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PsExecInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Host); err != nil {
		return errorResult(fmt.Sprintf("host: %s", err.Error())), nil
	}
	if err := validateInput(input.Username); err != nil {
		return errorResult(fmt.Sprintf("username: %s", err.Error())), nil
	}
	if err := validateInput(input.ScriptPath); err != nil {
		return errorResult(fmt.Sprintf("script_path: %s", err.Error())), nil
	}

	args := []string{"-i", input.Host, "-u", input.Username}
	if input.Password != "" {
		if err := validateInput(input.Password); err != nil {
			return errorResult(fmt.Sprintf("password: %s", err.Error())), nil
		}
		args = append(args, "-p", input.Password)
	}
	if input.Hash != "" {
		if err := validateInput(input.Hash); err != nil {
			return errorResult(fmt.Sprintf("hash: %s", err.Error())), nil
		}
		args = append(args, "-H", input.Hash)
	}
	if input.Domain != "" {
		if err := validateInput(input.Domain); err != nil {
			return errorResult(fmt.Sprintf("domain: %s", err.Error())), nil
		}
		args = append(args, "-d", input.Domain)
	}
	if input.SSL {
		args = append(args, "-S")
	}
	args = append(args, "-s", input.ScriptPath)

	result, err := t.exec.Run(ctx, "evil-winrm", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("evil-winrm ps exec failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Evil-WinRM PowerShell Exec\n\n")
	sb.WriteString(fmt.Sprintf("Script: `%s`\n\n", input.ScriptPath))
	if output == "" {
		sb.WriteString("Script executed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}
