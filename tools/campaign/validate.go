package campaign

import (
	"encoding/json"
	"fmt"
)

// requireWorkflowID validates that params is a JSON object carrying a
// required workflow_id that matches the engine's identifier rules. The
// params are passed through to the engine unchanged.
func requireWorkflowID(params json.RawMessage) (string, error) {
	if err := requireObject(params); err != nil {
		return "", err
	}
	workflowID := resultField(params, "workflow_id")
	if workflowID == "" {
		return "", fmt.Errorf("workflow_id is required")
	}
	if !validID(workflowID) {
		return "", fmt.Errorf("workflow_id %q invalid: %s", workflowID, idRule)
	}
	return workflowID, nil
}

// requireName validates that params is a JSON object carrying a required
// template name that matches the template manager's identifier rules.
func requireName(params json.RawMessage) (string, error) {
	if err := requireObject(params); err != nil {
		return "", err
	}
	name := resultField(params, "name")
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if !validID(name) {
		return "", fmt.Errorf("name %q invalid: %s", name, idRule)
	}
	return name, nil
}
