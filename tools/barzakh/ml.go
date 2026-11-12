package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

var mlActions = []string{"train", "evaluate"}

// MlTool wraps `barzakh-scanner ml train|evaluate` (verified against
// scanner main.rs):
//
//	ml train --corpus <dir> [--output <model.json>]
//	ml evaluate --corpus <dir> --model <model.json>
//
// The corpus directory uses malicious_*/clean_* filename labeling. train
// writes the combined isolation-forest + logistic-regression model; evaluate
// reports TPR/FPR and a confusion matrix. The scanner main() exits 2 on
// error, so no detection-exit handling is needed.
type MlInput struct {
	Action string `json:"action"`
	Corpus string `json:"corpus"`
	Output string `json:"output,omitempty"`
	Model  string `json:"model,omitempty"`
}

type MlTool struct {
	exec executor.Executor
}

func NewMl(exec executor.Executor) *MlTool {
	return &MlTool{exec: exec}
}

func (t *MlTool) Name() string { return "barzakh_ml" }

func (t *MlTool) Description() string {
	return "Train and evaluate ML bootkit-detection models on labeled corpora (malicious_*/clean_* files, e.g. from barzakh_corpus): train fits the combined isolation-forest + logistic-regression model and writes model JSON; evaluate loads a trained model and reports TPR/FPR and a confusion matrix against a corpus."
}

func (t *MlTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["train", "evaluate"],
				"description": "train a model on a labeled corpus, or evaluate a trained model"
			},
			"corpus": {
				"type": "string",
				"description": "Corpus directory with malicious_*/clean_* files (must exist)"
			},
			"output": {
				"type": "string",
				"description": "Output path for the trained model JSON (train only; default: model.json)"
			},
			"model": {
				"type": "string",
				"description": "Trained model JSON (required for evaluate; must exist)"
			}
		},
		"required": ["action", "corpus"]
	}`)
}

func (t *MlTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input MlInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if !isValidAction(mlActions, input.Action) {
		return errorResult("invalid action: must be one of " + strings.Join(mlActions, ", ")), nil
	}
	if input.Corpus == "" {
		return errorResult("corpus path is required"), nil
	}
	if err := validatePath(input.Corpus, "corpus"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateExistingDir(input.Corpus, "corpus"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Model, "model"); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "train":
		args = []string{"ml", "train", "--corpus", input.Corpus}
		if input.Output != "" {
			args = append(args, "--output", input.Output)
		}
	case "evaluate":
		if input.Model == "" {
			return errorResult("model path is required for evaluate"), nil
		}
		if err := validateExistingFile(input.Model, "model"); err != nil {
			return errorResult(err.Error()), nil
		}
		args = []string{"ml", "evaluate", "--corpus", input.Corpus, "--model", input.Model}
	}

	result, err := t.exec.Run(ctx, "barzakh-scanner", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner ml %s failed: %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## ML %s\n\n", strings.ToUpper(input.Action[:1])+input.Action[1:])
	fmt.Fprintf(&sb, "- **Corpus:** %s\n", input.Corpus)
	if input.Action == "train" && input.Output != "" {
		fmt.Fprintf(&sb, "- **Output:** %s\n", input.Output)
	}
	if input.Action == "evaluate" {
		fmt.Fprintf(&sb, "- **Model:** %s\n", input.Model)
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("ML command completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
