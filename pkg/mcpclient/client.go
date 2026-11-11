// Package mcpclient implements the server's legacy HTTP/SSE transport. Requests
// are never automatically retried: a lost response may follow a successful mutation.
package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/version"
)

const maxResponseBytes = 32 * 1024 * 1024

type Config struct {
	URL      string
	APIKey   string
	CAFile   string
	CertFile string
	KeyFile  string
}

type Client struct {
	http       *http.Client
	endpoint   *url.URL
	key        string
	body       io.ReadCloser
	cancel     context.CancelFunc
	events     chan event
	streamDone chan struct{}
	gate       chan struct{}
	nextID     uint64
}

type event struct {
	kind, data string
	err        error
}

func NewHTTPClient(cfg Config) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file contains no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, fmt.Errorf("client certificate and key must be provided together")
	}
	if cfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("redirects are disabled to protect credentials and prevent request replay")
	}}, nil
}

func Dial(ctx context.Context, cfg Config) (*Client, error) {
	base, err := url.Parse(cfg.URL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("server URL must be an http(s) URL without credentials, query or fragment")
	}
	if base.Scheme == "http" {
		ip := net.ParseIP(base.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("non-loopback server connections require HTTPS")
		}
	}
	hc, err := NewHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &Client{http: hc, key: cfg.APIKey, cancel: cancel, events: make(chan event, 16), streamDone: make(chan struct{}), gate: make(chan struct{}, 1)}
	streamURL := *base
	streamURL.Path = strings.TrimRight(base.Path, "/") + "/sse"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, streamURL.String(), nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("X-API-Key", cfg.APIKey)
	response, err := hc.Do(request)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("open SSE stream: %w", err)
	}
	c.body = response.Body
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		c.Close()
		return nil, fmt.Errorf("SSE endpoint returned HTTP %d or invalid content type", response.StatusCode)
	}
	go c.readEvents(ctx)
	select {
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	case first, ok := <-c.events:
		if !ok || first.err != nil || first.kind != "endpoint" {
			c.Close()
			return nil, fmt.Errorf("SSE stream did not provide a message endpoint")
		}
		endpoint, err := url.Parse(first.data)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("invalid SSE endpoint")
		}
		endpoint = streamURL.ResolveReference(endpoint)
		if endpoint.Scheme != base.Scheme || !strings.EqualFold(endpoint.Host, base.Host) || endpoint.User != nil || endpoint.Fragment != "" {
			c.Close()
			return nil, fmt.Errorf("SSE endpoint must have the same origin as the server")
		}
		c.endpoint = endpoint
	}
	_, err = c.Call(ctx, mcp.MethodInitialize, mcp.InitializeParams{ProtocolVersion: "2024-11-05", ClientInfo: mcp.ClientInfo{Name: "redhands-cli", Version: version.Version}})
	if err == nil {
		err = c.notify(ctx, mcp.MethodInitialized)
	}
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("initialize MCP session: %w", err)
	}
	return c, nil
}

func (c *Client) Close() {
	c.cancel()
	if c.body != nil {
		_ = c.body.Close()
	}
	c.http.CloseIdleConnections()
}

func (c *Client) readEvents(ctx context.Context) {
	defer close(c.events)
	if c.streamDone != nil {
		defer close(c.streamDone)
	}
	scanner := bufio.NewScanner(c.body)
	scanner.Buffer(make([]byte, 4096), maxResponseBytes)
	var kind string
	var data strings.Builder
	send := func(e event) bool {
		select {
		case c.events <- e:
			return true
		case <-ctx.Done():
			return false
		}
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if data.Len() > 0 && !send(event{kind: kind, data: strings.TrimSuffix(data.String(), "\n")}) {
				return
			}
			kind = ""
			data.Reset()
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			kind = value
		case "data":
			if data.Len()+len(value)+1 > maxResponseBytes {
				send(event{err: fmt.Errorf("SSE event exceeds response limit")})
				return
			}
			data.WriteString(value)
			data.WriteByte('\n')
		}
	}
	if err := scanner.Err(); err != nil {
		send(event{err: fmt.Errorf("read SSE response: %w", err)})
	}
}

func (c *Client) post(ctx context.Context, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(data) > mcp.MaxRequestBytes {
		return fmt.Errorf("request exceeds server size limit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.key)
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("send MCP request (execution may have occurred; not retried): %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("message endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (c *Client) notify(ctx context.Context, method string) error {
	return c.post(ctx, mcp.JSONRPCRequest{JSONRPC: mcp.JSONRPCVersion, Method: method})
}

// Call serializes requests within this session, correlates responses by ID and
// uses the caller's deadline for both the HTTP request and SSE response wait.
func (c *Client) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-c.streamDone:
		return nil, fmt.Errorf("SSE stream is closed; request was not sent")
	default:
	}
	c.nextID++
	id := json.RawMessage(fmt.Sprintf("%d", c.nextID))
	rawParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	if err := c.post(ctx, mcp.JSONRPCRequest{JSONRPC: mcp.JSONRPCVersion, ID: id, Method: method, Params: rawParams}); err != nil {
		return nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for MCP response (not retried): %w", ctx.Err())
		case e, ok := <-c.events:
			if !ok {
				return nil, fmt.Errorf("SSE stream closed before response; execution may have occurred")
			}
			if e.err != nil {
				return nil, e.err
			}
			if e.kind != "message" {
				continue
			}
			var response struct {
				JSONRPC string            `json:"jsonrpc"`
				ID      json.RawMessage   `json:"id"`
				Result  json.RawMessage   `json:"result"`
				Error   *mcp.JSONRPCError `json:"error"`
			}
			if err := json.Unmarshal([]byte(e.data), &response); err != nil {
				return nil, fmt.Errorf("invalid MCP response: %w", err)
			}
			if len(response.ID) == 0 {
				continue
			} // Server notification.
			if response.JSONRPC != mcp.JSONRPCVersion {
				return nil, fmt.Errorf("invalid JSON-RPC response version")
			}
			if !bytes.Equal(response.ID, id) {
				continue
			}
			if response.Error != nil {
				return nil, fmt.Errorf("RPC error [%d]: %s", response.Error.Code, response.Error.Message)
			}
			if len(response.Result) == 0 {
				return nil, fmt.Errorf("MCP response has neither result nor error")
			}
			return response.Result, nil
		}
	}
}
