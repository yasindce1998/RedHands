package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/mcpclient"
	"github.com/yasindce1998/redhands/pkg/version"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer, getenv func(string) string) error {
	if len(args) == 0 {
		usage(out)
		return fmt.Errorf("a command is required")
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		usage(out)
		return nil
	}
	if args[0] == "version" {
		_, err := fmt.Fprintln(out, "redhands-cli v"+version.Version)
		return err
	}
	method := mcp.MethodToolsCall
	var params any
	tool := ""
	arguments := json.RawMessage(`{}`)
	switch args[0] {
	case "call":
		if len(args) < 2 || len(args) > 3 {
			return fmt.Errorf("usage: redhands-cli call <tool> [json_params]")
		}
		tool = args[1]
		if len(args) == 3 {
			arguments = json.RawMessage(args[2])
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(arguments, &object); err != nil || object == nil {
			return fmt.Errorf("tool parameters must be a JSON object")
		}
	case "tools":
		if len(args) != 1 {
			return fmt.Errorf("usage: redhands-cli tools")
		}
		method = mcp.MethodToolsList
	case "targets":
		tool = "targetdb_list_hosts"
		if len(args) > 1 {
			if args[1] != "add" || len(args) < 3 || len(args) > 4 {
				return fmt.Errorf("usage: redhands-cli targets [add <ip> [hostname]]")
			}
			tool = "targetdb_add_host"
			p := map[string]string{"ip": args[2]}
			if len(args) == 4 {
				p["hostname"] = args[3]
			}
			arguments, _ = json.Marshal(p)
		}
	case "findings":
		if len(args) > 2 {
			return fmt.Errorf("usage: redhands-cli findings [severity]")
		}
		tool = "targetdb_query_findings"
		if len(args) == 2 {
			arguments, _ = json.Marshal(map[string]string{"severity": args[1]})
		}
	case "status":
		if len(args) != 1 {
			return fmt.Errorf("usage: redhands-cli status")
		}
		tool = "redhands_health"
	default:
		return fmt.Errorf("unknown command %q; use redhands-cli help", args[0])
	}
	if tool != "" {
		params = mcp.ToolsCallParams{Name: tool, Arguments: arguments}
	} else {
		params = struct{}{}
	}
	timeout := 6 * time.Minute
	if value := getenv("REDHANDS_CLIENT_TIMEOUT"); value != "" {
		var err error
		timeout, err = time.ParseDuration(value)
		if err != nil || timeout <= 0 {
			return fmt.Errorf("REDHANDS_CLIENT_TIMEOUT must be a positive duration")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	serverURL := getenv("REDHANDS_URL")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8080"
	}
	client, err := mcpclient.Dial(ctx, mcpclient.Config{URL: serverURL, APIKey: getenv("REDHANDS_API_KEY"), CAFile: getenv("REDHANDS_CLIENT_CA"), CertFile: getenv("REDHANDS_CLIENT_CERT"), KeyFile: getenv("REDHANDS_CLIENT_KEY")})
	if err != nil {
		return err
	}
	defer client.Close()
	result, err := client.Call(ctx, method, params)
	if err != nil {
		return err
	}
	if method == mcp.MethodToolsList {
		var list mcp.ToolsListResult
		if err := json.Unmarshal(result, &list); err != nil {
			return fmt.Errorf("invalid tools list: %w", err)
		}
		for _, tool := range list.Tools {
			if _, err := fmt.Fprintf(out, "%-36s %s\n", tool.Name, tool.Description); err != nil {
				return err
			}
		}
		return nil
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, result, "", "  "); err != nil {
		return fmt.Errorf("invalid result: %w", err)
	}
	if _, err := fmt.Fprintln(out, formatted.String()); err != nil {
		return err
	}
	var toolResult mcp.ToolResult
	if err := json.Unmarshal(result, &toolResult); err != nil {
		return err
	}
	if toolResult.IsError {
		return fmt.Errorf("tool reported failure")
	}
	return nil
}

func usage(out io.Writer) {
	_, _ = fmt.Fprint(out, `RedHands CLI

Usage: redhands-cli <command> [args]
  call <tool> [json]        Call a tool (JSON object parameters)
  tools                     List available tools
  targets [add <ip> [name]] List or add hosts
  findings [severity]       Query findings
  status                    Call redhands_health on the MCP server
  version                   Show version

Environment:
  REDHANDS_URL              SSE server base URL (default http://127.0.0.1:8080)
  REDHANDS_API_KEY          X-API-Key credential
  REDHANDS_CLIENT_CA        Trusted server CA PEM file
  REDHANDS_CLIENT_CERT      mTLS client certificate PEM file
  REDHANDS_CLIENT_KEY       mTLS client private key PEM file
  REDHANDS_CLIENT_TIMEOUT   Total command deadline (default 6m)

Start the server with REDHANDS_TRANSPORT=sse. Commands are never retried automatically.
`)
}
