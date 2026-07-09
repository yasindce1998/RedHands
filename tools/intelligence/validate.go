package intelligence

import (
	"encoding/json"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

func errorResult(msg string) (*mcp.ToolResult, error) {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}, nil
}

func textResult(text string) (*mcp.ToolResult, error) {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: text}},
	}, nil
}

func jsonResult(v interface{}) (*mcp.ToolResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errorResult("failed to marshal result: " + err.Error())
	}
	return textResult(string(data))
}
