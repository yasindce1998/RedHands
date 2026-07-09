package report

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type PDFOptions struct {
	Title      string
	OutputPath string
	PageSize   string
	Findings   []*targetdb.Finding
	Hosts      []*targetdb.Host
}

func GeneratePDF(ctx context.Context, opts PDFOptions) (string, error) {
	if opts.OutputPath == "" {
		opts.OutputPath = fmt.Sprintf("report_%s.pdf", time.Now().Format("20060102_150405"))
	}
	if opts.PageSize == "" {
		opts.PageSize = "A4"
	}

	htmlContent := buildPDFHTML(opts)

	tmpDir := os.TempDir()
	htmlPath := filepath.Join(tmpDir, fmt.Sprintf("redhands_report_%d.html", time.Now().UnixNano()))

	if err := os.WriteFile(htmlPath, []byte(htmlContent), 0600); err != nil {
		return "", fmt.Errorf("write temp HTML: %w", err)
	}
	defer os.Remove(htmlPath)

	cmd := exec.CommandContext(ctx, "wkhtmltopdf",
		"--page-size", opts.PageSize,
		"--margin-top", "20mm",
		"--margin-bottom", "20mm",
		"--margin-left", "15mm",
		"--margin-right", "15mm",
		"--encoding", "UTF-8",
		"--enable-local-file-access",
		htmlPath, opts.OutputPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("wkhtmltopdf: %s: %w", string(output), err)
	}

	return opts.OutputPath, nil
}

func buildPDFHTML(opts PDFOptions) string {
	title := opts.Title
	if title == "" {
		title = "Security Assessment Report"
	}

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html><head><meta charset="UTF-8">`)
	fmt.Fprintf(&sb, `<title>%s</title>`, htmlEscape(title))
	sb.WriteString(`<style>
body { font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 11pt; color: #222; line-height: 1.5; }
h1 { color: #c0392b; font-size: 22pt; border-bottom: 2px solid #c0392b; padding-bottom: 8px; }
h2 { color: #2c3e50; font-size: 16pt; margin-top: 24px; }
h3 { color: #34495e; font-size: 13pt; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; }
th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; font-size: 10pt; }
th { background: #f5f5f5; }
.severity-critical { color: #fff; background: #c0392b; padding: 2px 8px; border-radius: 3px; }
.severity-high { color: #fff; background: #e67e22; padding: 2px 8px; border-radius: 3px; }
.severity-medium { color: #000; background: #f1c40f; padding: 2px 8px; border-radius: 3px; }
.severity-low { color: #fff; background: #27ae60; padding: 2px 8px; border-radius: 3px; }
.severity-info { color: #fff; background: #3498db; padding: 2px 8px; border-radius: 3px; }
.meta { color: #7f8c8d; font-size: 10pt; }
.page-break { page-break-before: always; }
</style></head><body>`)

	fmt.Fprintf(&sb, `<h1>%s</h1>`, htmlEscape(title))
	fmt.Fprintf(&sb, `<p class="meta">Generated: %s</p>`, time.Now().Format("2006-01-02 15:04:05 UTC"))

	// Summary section
	sb.WriteString(`<h2>Summary</h2>`)
	fmt.Fprintf(&sb, `<p>Total findings: <strong>%d</strong> | Hosts assessed: <strong>%d</strong></p>`, len(opts.Findings), len(opts.Hosts))

	sevCounts := make(map[string]int)
	for _, f := range opts.Findings {
		sevCounts[f.Severity]++
	}
	sb.WriteString(`<table><tr><th>Severity</th><th>Count</th></tr>`)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c := sevCounts[sev]; c > 0 {
			fmt.Fprintf(&sb, `<tr><td><span class="severity-%s">%s</span></td><td>%d</td></tr>`, sev, strings.ToUpper(sev), c)
		}
	}
	sb.WriteString(`</table>`)

	// Findings detail
	if len(opts.Findings) > 0 {
		sb.WriteString(`<h2 class="page-break">Findings</h2>`)
		sb.WriteString(`<table><tr><th>#</th><th>Title</th><th>Host</th><th>Severity</th><th>Score</th><th>Tool</th></tr>`)
		for i, f := range opts.Findings {
			fmt.Fprintf(&sb, `<tr><td>%d</td><td>%s</td><td>%s</td><td><span class="severity-%s">%s</span></td><td>%.1f</td><td>%s</td></tr>`,
				i+1, htmlEscape(f.Title), htmlEscape(f.Host), f.Severity, strings.ToUpper(f.Severity), f.RiskScore, htmlEscape(f.Tool))
		}
		sb.WriteString(`</table>`)

		for _, f := range opts.Findings {
			fmt.Fprintf(&sb, `<h3>%s</h3>`, htmlEscape(f.Title))
			fmt.Fprintf(&sb, `<p><strong>Host:</strong> %s | <strong>Severity:</strong> <span class="severity-%s">%s</span> | <strong>Score:</strong> %.1f</p>`,
				htmlEscape(f.Host), f.Severity, strings.ToUpper(f.Severity), f.RiskScore)
			fmt.Fprintf(&sb, `<p>%s</p>`, htmlEscape(f.Description))
			if f.Evidence != "" {
				fmt.Fprintf(&sb, `<pre>%s</pre>`, htmlEscape(f.Evidence))
			}
		}
	}

	sb.WriteString(`</body></html>`)
	return sb.String()
}
