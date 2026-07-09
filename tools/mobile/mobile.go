package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// --- FridaAttachTool ---

type FridaAttachInput struct {
	Target  string `json:"target"`
	Device  string `json:"device,omitempty"`
	Script  string `json:"script,omitempty"`
	Runtime string `json:"runtime,omitempty"`
}

type FridaAttachTool struct {
	exec executor.Executor
}

func NewFridaAttach(exec executor.Executor) *FridaAttachTool {
	return &FridaAttachTool{exec: exec}
}

func (t *FridaAttachTool) Name() string { return "mobile_frida_attach" }

func (t *FridaAttachTool) Description() string {
	return "Attach Frida to a running process for dynamic instrumentation. Supports specifying target device, loading JS scripts, and selecting the JavaScript runtime engine."
}

func (t *FridaAttachTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "PID or process name to attach to"
			},
			"device": {
				"type": "string",
				"description": "Device ID to target (optional)"
			},
			"script": {
				"type": "string",
				"description": "Path to JavaScript instrumentation script (optional)"
			},
			"runtime": {
				"type": "string",
				"enum": ["qjs", "v8"],
				"description": "JavaScript runtime to use (qjs or v8)"
			}
		},
		"required": ["target"]
	}`)
}

func (t *FridaAttachTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FridaAttachInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Target); err != nil {
		return errorResult("target: " + err.Error()), nil
	}
	if input.Device != "" {
		if err := validateInput(input.Device); err != nil {
			return errorResult("device: " + err.Error()), nil
		}
	}
	if input.Script != "" {
		if err := validateInput(input.Script); err != nil {
			return errorResult("script: " + err.Error()), nil
		}
	}
	if input.Runtime != "" && input.Runtime != "qjs" && input.Runtime != "v8" {
		return errorResult("runtime must be 'qjs' or 'v8'"), nil
	}

	var args []string
	if input.Device != "" {
		args = append(args, "-D", input.Device)
	}
	if input.Script != "" {
		args = append(args, "-l", input.Script)
	}
	if input.Runtime != "" {
		args = append(args, "--runtime", input.Runtime)
	}
	args = append(args, input.Target)

	result, err := t.exec.Run(ctx, "frida", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("frida attach failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	return textResult(fmt.Sprintf("## Frida Attach: %s\n\n%s", input.Target, output)), nil
}

// --- FridaSpawnTool ---

type FridaSpawnInput struct {
	PackageName string `json:"package_name"`
	Device      string `json:"device,omitempty"`
	Script      string `json:"script,omitempty"`
	Pause       bool   `json:"pause,omitempty"`
}

type FridaSpawnTool struct {
	exec executor.Executor
}

func NewFridaSpawn(exec executor.Executor) *FridaSpawnTool {
	return &FridaSpawnTool{exec: exec}
}

func (t *FridaSpawnTool) Name() string { return "mobile_frida_spawn" }

func (t *FridaSpawnTool) Description() string {
	return "Spawn a new process with Frida instrumentation. Launches the target application under Frida control, allowing early-stage hooking before the app initializes."
}

func (t *FridaSpawnTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"package_name": {
				"type": "string",
				"description": "Application package name to spawn (e.g., com.example.app)"
			},
			"device": {
				"type": "string",
				"description": "Device ID to target (optional)"
			},
			"script": {
				"type": "string",
				"description": "Path to JavaScript instrumentation script (optional)"
			},
			"pause": {
				"type": "boolean",
				"description": "Pause the process after spawning (allows attaching before execution)"
			}
		},
		"required": ["package_name"]
	}`)
}

func (t *FridaSpawnTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FridaSpawnInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.PackageName); err != nil {
		return errorResult("package_name: " + err.Error()), nil
	}
	if input.Device != "" {
		if err := validateInput(input.Device); err != nil {
			return errorResult("device: " + err.Error()), nil
		}
	}
	if input.Script != "" {
		if err := validateInput(input.Script); err != nil {
			return errorResult("script: " + err.Error()), nil
		}
	}

	var args []string
	if input.Device != "" {
		args = append(args, "-D", input.Device)
	}
	if input.Script != "" {
		args = append(args, "-l", input.Script)
	}
	args = append(args, "-f", input.PackageName)
	if input.Pause {
		args = append(args, "--pause")
	}

	result, err := t.exec.Run(ctx, "frida", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("frida spawn failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	return textResult(fmt.Sprintf("## Frida Spawn: %s\n\n%s", input.PackageName, output)), nil
}

// --- ObjectionTool ---

type ObjectionInput struct {
	Gadget  string `json:"gadget"`
	Command string `json:"command"`
}

type ObjectionTool struct {
	exec executor.Executor
}

func NewObjection(exec executor.Executor) *ObjectionTool {
	return &ObjectionTool{exec: exec}
}

func (t *ObjectionTool) Name() string { return "mobile_objection" }

func (t *ObjectionTool) Description() string {
	return "Run objection commands for runtime mobile application analysis. Objection provides a REPL-powered interface for exploring iOS and Android applications at runtime without requiring a jailbreak or root."
}

func (t *ObjectionTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"gadget": {
				"type": "string",
				"description": "Application package/bundle to attach to (e.g., com.example.app)"
			},
			"command": {
				"type": "string",
				"description": "Objection command to execute (e.g., 'ios keychain dump', 'android sslpinning disable')"
			}
		},
		"required": ["gadget", "command"]
	}`)
}

func (t *ObjectionTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ObjectionInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Gadget); err != nil {
		return errorResult("gadget: " + err.Error()), nil
	}
	if input.Command == "" {
		return errorResult("command is required"), nil
	}
	if len(input.Command) > 500 {
		return errorResult("command too long"), nil
	}

	args := []string{"-g", input.Gadget, "explore", "-c", input.Command}

	result, err := t.exec.Run(ctx, "objection", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("objection failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	return textResult(fmt.Sprintf("## Objection [%s]: %s\n\n%s", input.Gadget, input.Command, output)), nil
}

// --- ApkDecompileTool ---

type ApkDecompileInput struct {
	ApkPath   string `json:"apk_path"`
	OutputDir string `json:"output_dir,omitempty"`
	Force     bool   `json:"force,omitempty"`
}

type ApkDecompileTool struct {
	exec executor.Executor
}

func NewApkDecompile(exec executor.Executor) *ApkDecompileTool {
	return &ApkDecompileTool{exec: exec}
}

func (t *ApkDecompileTool) Name() string { return "mobile_apk_decompile" }

func (t *ApkDecompileTool) Description() string {
	return "Decompile an Android APK file using apktool. Extracts resources, smali code, and the AndroidManifest.xml for static analysis and modification."
}

func (t *ApkDecompileTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"apk_path": {
				"type": "string",
				"description": "Path to the APK file to decompile"
			},
			"output_dir": {
				"type": "string",
				"description": "Output directory for decompiled files (optional)"
			},
			"force": {
				"type": "boolean",
				"description": "Force overwrite if output directory already exists"
			}
		},
		"required": ["apk_path"]
	}`)
}

func (t *ApkDecompileTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ApkDecompileInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.ApkPath); err != nil {
		return errorResult("apk_path: " + err.Error()), nil
	}
	if input.OutputDir != "" {
		if err := validateInput(input.OutputDir); err != nil {
			return errorResult("output_dir: " + err.Error()), nil
		}
	}

	args := []string{"d"}
	if input.Force {
		args = append(args, "-f")
	}
	if input.OutputDir != "" {
		args = append(args, "-o", input.OutputDir)
	}
	args = append(args, input.ApkPath)

	result, err := t.exec.Run(ctx, "apktool", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("apktool decompile failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	return textResult(fmt.Sprintf("## APK Decompile: %s\n\n%s", input.ApkPath, output)), nil
}

// --- ApkRepackageTool ---

type ApkRepackageInput struct {
	SourceDir string `json:"source_dir"`
	OutputApk string `json:"output_apk,omitempty"`
}

type ApkRepackageTool struct {
	exec executor.Executor
}

func NewApkRepackage(exec executor.Executor) *ApkRepackageTool {
	return &ApkRepackageTool{exec: exec}
}

func (t *ApkRepackageTool) Name() string { return "mobile_apk_repackage" }

func (t *ApkRepackageTool) Description() string {
	return "Repackage a decompiled APK directory back into an APK file using apktool. Used after modifying smali code or resources to rebuild the application."
}

func (t *ApkRepackageTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"source_dir": {
				"type": "string",
				"description": "Path to the decompiled APK source directory"
			},
			"output_apk": {
				"type": "string",
				"description": "Output path for the repackaged APK file (optional)"
			}
		},
		"required": ["source_dir"]
	}`)
}

func (t *ApkRepackageTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ApkRepackageInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.SourceDir); err != nil {
		return errorResult("source_dir: " + err.Error()), nil
	}
	if input.OutputApk != "" {
		if err := validateInput(input.OutputApk); err != nil {
			return errorResult("output_apk: " + err.Error()), nil
		}
	}

	args := []string{"b"}
	if input.OutputApk != "" {
		args = append(args, "-o", input.OutputApk)
	}
	args = append(args, input.SourceDir)

	result, err := t.exec.Run(ctx, "apktool", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("apktool repackage failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	return textResult(fmt.Sprintf("## APK Repackage: %s\n\n%s", input.SourceDir, output)), nil
}

// --- AdbShellTool ---

type AdbShellInput struct {
	Command string `json:"command"`
	Device  string `json:"device,omitempty"`
}

type AdbShellTool struct {
	exec executor.Executor
}

func NewAdbShell(exec executor.Executor) *AdbShellTool {
	return &AdbShellTool{exec: exec}
}

func (t *AdbShellTool) Name() string { return "mobile_adb_shell" }

func (t *AdbShellTool) Description() string {
	return "Run an ADB shell command on a connected Android device or emulator. Supports targeting a specific device by serial number when multiple devices are connected."
}

func (t *AdbShellTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"command": {
				"type": "string",
				"description": "Shell command to execute on the device"
			},
			"device": {
				"type": "string",
				"description": "Device serial number to target (optional, use when multiple devices connected)"
			}
		},
		"required": ["command"]
	}`)
}

func (t *AdbShellTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input AdbShellInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Command == "" {
		return errorResult("command is required"), nil
	}
	if len(input.Command) > 500 {
		return errorResult("command too long"), nil
	}
	if input.Device != "" {
		if err := validateInput(input.Device); err != nil {
			return errorResult("device: " + err.Error()), nil
		}
	}

	var args []string
	if input.Device != "" {
		args = append(args, "-s", input.Device)
	}
	args = append(args, "shell", input.Command)

	result, err := t.exec.Run(ctx, "adb", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("adb shell failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	return textResult(fmt.Sprintf("## ADB Shell\n\n```\n%s\n```", output)), nil
}
