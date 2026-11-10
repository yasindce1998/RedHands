package mcp

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const MaxRequestBytes = 10 * 1024 * 1024

type HTTPOptions struct {
	TLSConfig *tls.Config
	AuthCheck func(*http.Request) (context.Context, error)
	Identity  func(context.Context) string
}

func checkHTTPRequest(w http.ResponseWriter, r *http.Request, opts HTTPOptions) (context.Context, bool) {
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, r.Host) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return nil, false
		}
	}
	if opts.AuthCheck != nil {
		ctx, err := opts.AuthCheck(r)
		if err != nil {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return nil, false
		}
		return ctx, true
	}
	return r.Context(), true
}

func serveHTTP(ctx context.Context, addr string, handler http.Handler, opts HTTPOptions) error {
	server := &http.Server{
		Addr: addr, Handler: handler, TLSConfig: opts.TLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second, IdleTimeout: 120 * time.Second,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
			return
		case <-ctx.Done():
		}
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutCtx)
	}()
	var err error
	if opts.TLSConfig != nil {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
