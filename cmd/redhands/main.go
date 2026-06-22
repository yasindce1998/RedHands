package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/redhands-sec/redhands/pkg/audit"
	"github.com/redhands-sec/redhands/pkg/executor"
	"github.com/redhands-sec/redhands/pkg/mcp"
	nmaptools "github.com/redhands-sec/redhands/tools/nmap"
)

func main() {
	log.SetOutput(os.Stderr)

	nmapPath, err := findNmap()
	if err != nil {
		log.Fatalf("nmap not found: %v", err)
	}

	exec := executor.New(executor.Config{
		Timeout:         int64((5 * time.Minute).Seconds()),
		AllowedBinaries: map[string]string{"nmap": nmapPath},
		MaxOutputBytes:  10 * 1024 * 1024,
	})

	auditLogger, err := audit.NewFileLogger("audit.jsonl")
	if err != nil {
		log.Fatalf("failed to initialize audit logger: %v", err)
	}
	defer auditLogger.Close()

	srv := mcp.NewServer("redhands", "0.1.0")
	srv.Use(audit.Middleware(auditLogger))
	srv.RegisterTool(nmaptools.NewPortScan(exec))
	srv.RegisterTool(nmaptools.NewServiceDetect(exec))
	srv.RegisterTool(nmaptools.NewOSDetect(exec))
	srv.RegisterTool(nmaptools.NewVulnScan(exec))

	if err := srv.ServeStdio(context.Background()); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func findNmap() (string, error) {
	path, err := exec.LookPath("nmap")
	if err != nil {
		return "", err
	}
	return path, nil
}
