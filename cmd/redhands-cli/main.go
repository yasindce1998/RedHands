package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	serverURL := os.Getenv("REDHANDS_URL")
	if serverURL == "" {
		serverURL = "http://localhost:3000"
	}

	cmd := os.Args[1]
	switch cmd {
	case "call":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: redhands-cli call <tool_name> [json_params]\n")
			os.Exit(1)
		}
		toolName := os.Args[2]
		var params json.RawMessage
		if len(os.Args) > 3 {
			params = json.RawMessage(os.Args[3])
		} else {
			params = json.RawMessage("{}")
		}
		callTool(serverURL, toolName, params)

	case "tools":
		listTools(serverURL)

	case "targets":
		if len(os.Args) > 2 && os.Args[2] == "add" {
			if len(os.Args) < 4 {
				fmt.Fprintf(os.Stderr, "Usage: redhands-cli targets add <ip> [hostname]\n")
				os.Exit(1)
			}
			p := map[string]string{"ip": os.Args[3]}
			if len(os.Args) > 4 {
				p["hostname"] = os.Args[4]
			}
			data, _ := json.Marshal(p)
			callTool(serverURL, "targetdb_add_host", data)
		} else {
			callTool(serverURL, "targetdb_list_hosts", json.RawMessage("{}"))
		}

	case "findings":
		params := map[string]string{}
		if len(os.Args) > 2 {
			params["severity"] = os.Args[2]
		}
		data, _ := json.Marshal(params)
		callTool(serverURL, "targetdb_query_findings", data)

	case "status":
		resp, err := http.Get(serverURL + "/api/status")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		var out bytes.Buffer
		_ = json.Indent(&out, body, "", "  ")
		fmt.Println(out.String())

	case "version":
		fmt.Println("redhands-cli v1.0.0")

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `RedHands CLI - Offensive Security Platform

Usage: redhands-cli <command> [args...]

Commands:
  call <tool> [params]    Call an MCP tool with JSON parameters
  tools                   List available tools
  targets [add <ip>]      List or add targets
  findings [severity]     Query findings
  status                  Show server status
  version                 Show version

Environment:
  REDHANDS_URL            Server URL (default: http://localhost:3000)
`)
}

func callTool(serverURL, toolName string, params json.RawMessage) {
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  mustMarshal(map[string]interface{}{
			"name":      toolName,
			"arguments": json.RawMessage(params),
		}),
	}

	result := rpcCall(serverURL, req)
	fmt.Println(prettyJSON(result))
}

func listTools(serverURL string) {
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}

	result := rpcCall(serverURL, req)

	var toolsList struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
	}
	_ = json.Unmarshal(result, &toolsList)

	if len(toolsList.Tools) > 0 {
		maxName := 0
		for _, t := range toolsList.Tools {
			if len(t.Name) > maxName {
				maxName = len(t.Name)
			}
		}
		for _, t := range toolsList.Tools {
			fmt.Printf("  %-*s  %s\n", maxName, t.Name, t.Description)
		}
	} else {
		fmt.Println(prettyJSON(result))
	}
}

func rpcCall(serverURL string, req jsonRPCRequest) json.RawMessage {
	body, _ := json.Marshal(req)
	client := &http.Client{Timeout: 60 * time.Second}

	resp, err := client.Post(serverURL+"/rpc", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to %s: %v\n", serverURL, err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid response: %s\n", string(respBody))
		os.Exit(1)
	}

	if rpcResp.Error != nil {
		fmt.Fprintf(os.Stderr, "RPC Error [%d]: %s\n", rpcResp.Error.Code, rpcResp.Error.Message)
		os.Exit(1)
	}

	return rpcResp.Result
}

func prettyJSON(data json.RawMessage) string {
	var out bytes.Buffer
	if json.Indent(&out, data, "", "  ") != nil {
		return string(data)
	}
	return strings.TrimSpace(out.String())
}

func mustMarshal(v interface{}) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}
