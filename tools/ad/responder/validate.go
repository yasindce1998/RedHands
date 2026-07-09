package responder

import (
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}

func textResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
	}
}

func validateInput(val string) error {
	if val == "" {
		return fmt.Errorf("value is required")
	}
	if len(val) > 253 {
		return fmt.Errorf("value too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(val, c) {
			return fmt.Errorf("value contains forbidden character: %q", c)
		}
	}
	return nil
}
