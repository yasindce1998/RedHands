package firmware

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
)

// scanCSVFixture mirrors real `binwalk --csv -f <log>` output from v2.3.1,
// verified against src/binwalk/core/display.py: the header row is written
// first, then one csv.writerow([offset, offset, description]) row per
// result. The column under the HEXADECIMAL header repeats the decimal offset
// (binwalk's CSV quirk), and descriptions containing commas are quoted by
// Python's csv writer.
const scanCSVFixture = `DECIMAL,HEXADECIMAL,DESCRIPTION
0,0,"gzip compressed data, from Unix, last modified: 2023-04-05 06:07:08, original size: 4567"
4096,4096,"Squashfs filesystem, little endian, version 4.0, compression:gzip, size: 1234567 bytes, 512 inodes, blocksize: 131072 bytes, created: 2023-04-05 06:07:09"
1245695,1245695,"certificate, type: X.509, entity: firmware-signing"
`

// extractJSONBlock pulls the first fenced json block out of a tool result.
func extractJSONBlock(t *testing.T, text string) string {
	t.Helper()
	const open = "```json\n"
	start := strings.Index(text, open)
	if start < 0 {
		t.Fatalf("no json block in result:\n%s", text)
	}
	rest := text[start+len(open):]
	end := strings.Index(rest, "\n```")
	if end < 0 {
		t.Fatalf("unterminated json block in result:\n%s", text)
	}
	return rest[:end]
}

func TestFirmwareScan_Execute_Default(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := executor.NewMock()
	mock.StdoutFn = writeLogFromArgs(t, scanCSVFixture, "")
	tool := NewFirmwareScan(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"image": image,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	for _, want := range []string{"## Firmware Signature Scan", "Signatures found:** 3", "Signature summary", "Raw CSV log"} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in result, got:\n%s", want, text)
		}
	}

	// The JSON summary must carry the parsed CSV rows so record rules can
	// map signatures.N.description and signatures.N.offset.
	var summary struct {
		Image          string `json:"image"`
		SignatureCount int    `json:"signature_count"`
		Signatures     []struct {
			Offset      int64  `json:"offset"`
			OffsetHex   string `json:"offset_hex"`
			Description string `json:"description"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal([]byte(extractJSONBlock(t, text)), &summary); err != nil {
		t.Fatalf("summary is not valid JSON: %v\n%s", err, text)
	}
	if summary.Image != image || summary.SignatureCount != 3 || len(summary.Signatures) != 3 {
		t.Errorf("unexpected summary header: %+v", summary)
	}
	if summary.Signatures[0].Offset != 0 || summary.Signatures[0].OffsetHex != "0x0" {
		t.Errorf("unexpected first signature offset: %+v", summary.Signatures[0])
	}
	if !strings.HasPrefix(summary.Signatures[0].Description, "gzip compressed data, from Unix") {
		t.Errorf("comma-quoted description not parsed as one field: %q", summary.Signatures[0].Description)
	}
	if summary.Signatures[1].Offset != 4096 || summary.Signatures[1].OffsetHex != "0x1000" {
		t.Errorf("unexpected second signature offset: %+v", summary.Signatures[1])
	}

	call := mock.LastCall()
	if call.Binary != "binwalk" {
		t.Errorf("expected binary binwalk, got %q", call.Binary)
	}
	assertFlag(t, call.Args, "-B")
	assertFlag(t, call.Args, "--csv")
	assertFlag(t, call.Args, "-f")
	assertFlag(t, call.Args, "-q")
	assertNoFlag(t, call.Args, "-A")
	assertNoFlag(t, call.Args, "-E")
	assertNoFlag(t, call.Args, "-N")
	assertLastArg(t, call.Args, image)
}

func TestFirmwareScan_AllFlags(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := executor.NewMock()
	mock.StdoutFn = writeLogFromArgs(t, scanCSVFixture, "")
	tool := NewFirmwareScan(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"image":   image,
		"entropy": true,
		"opcodes": true,
		"include": "squashfs",
		"exclude": "certificate",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Modules:** signature, opcodes, entropy") {
		t.Errorf("expected module list in result, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertFlag(t, call.Args, "-A")
	// -E must always be paired with -N: the entropy module would otherwise
	// call matplotlib plt.show() and hang a headless run.
	assertFlag(t, call.Args, "-E")
	assertFlag(t, call.Args, "-N")
	assertArgs(t, call.Args, "-y", "squashfs")
	assertArgs(t, call.Args, "-x", "certificate")
	assertLastArg(t, call.Args, image)
}

func TestFirmwareScan_PlainOutput(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("DECIMAL       HEX         DESCRIPTION\n0            0x0         gzip compressed data\n")
	}
	tool := NewFirmwareScan(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"image": image,
		"csv":   false,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "0x0         gzip compressed data") {
		t.Errorf("expected plain stdout table in result, got: %s", text)
	}
	if strings.Contains(text, "```json") {
		t.Errorf("csv=false must not emit a JSON summary, got: %s", text)
	}

	call := mock.LastCall()
	assertNoFlag(t, call.Args, "--csv")
	assertNoFlag(t, call.Args, "-f")
	assertNoFlag(t, call.Args, "-q")
	assertLastArg(t, call.Args, image)
}

func TestFirmwareScan_ZeroSignatures(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := executor.NewMock()
	mock.StdoutFn = writeLogFromArgs(t, "DECIMAL,HEXADECIMAL,DESCRIPTION\n", "")
	tool := NewFirmwareScan(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"image": image}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "Signatures found:** 0") {
		t.Errorf("expected zero signature count, got: %s", text)
	}

	// signatures must serialize as [] (never null) so record-rule paths
	// remain valid on empty scans.
	var summary struct {
		Signatures []json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal([]byte(extractJSONBlock(t, text)), &summary); err != nil {
		t.Fatalf("summary is not valid JSON: %v", err)
	}
	if summary.Signatures == nil {
		t.Errorf("signatures must be an empty array, not null")
	}
}

func TestFirmwareScan_NoCSVLogFallsBackToStdout(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := executor.NewMock()
	// binwalk ran but wrote no CSV log (e.g. nothing was logged).
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("scan produced nothing")
	}
	tool := NewFirmwareScan(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"image": image}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "no CSV log") || !strings.Contains(text, "scan produced nothing") {
		t.Errorf("expected stdout fallback, got: %s", text)
	}
}

func TestFirmwareScan_InvalidInput(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name   string
		params json.RawMessage
		want   string
	}{
		{"bad json", json.RawMessage(`{invalid`), "invalid input"},
		{"image missing", mustJSON(map[string]any{}), "image is required"},
		{"image nonexistent", mustJSON(map[string]any{"image": "/nonexistent/fw.bin"}), "not accessible"},
		{"image is directory", mustJSON(map[string]any{"image": dir}), "must be a file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := NewFirmwareScan(executor.NewMock()).Execute(context.Background(), tc.params)
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected error, got success:\n%s", result.Content[0].Text)
			}
			if !strings.Contains(result.Content[0].Text, tc.want) {
				t.Errorf("expected %q in error, got: %s", tc.want, result.Content[0].Text)
			}
		})
	}
}

func TestFirmwareScan_ExecutorError(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := executor.NewMock()
	mock.StderrFn = func(_ string, _ []string) []byte {
		return []byte("General Error: Cannot open file /nonexistent")
	}
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"execution failed (exit 3): exit status 3"}
	}

	result, err := NewFirmwareScan(mock).Execute(context.Background(), mustJSON(map[string]any{"image": image}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true when executor fails")
	}
	if !strings.Contains(result.Content[0].Text, "binwalk failed") {
		t.Errorf("expected failure message, got: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Cannot open file") {
		t.Errorf("expected stderr in error, got: %s", result.Content[0].Text)
	}
}

// ---------------------------------------------------------------------------
// CSV parser unit tests (formats verified against binwalk v2.3.1's
// display.py csv writer; see the package comment for the column quirk).
// ---------------------------------------------------------------------------

func TestParseBinwalkCSV(t *testing.T) {
	cases := []struct {
		name string
		csv  string
		want []signatureRow
	}{
		{
			name: "quoted descriptions with commas",
			csv:  "DECIMAL,HEXADECIMAL,DESCRIPTION\n0,0,\"gzip compressed data, from Unix\"\n",
			want: []signatureRow{{Offset: 0, OffsetHex: "0x0", Description: "gzip compressed data, from Unix"}},
		},
		{
			name: "verbose matryoshka rows are skipped",
			csv: "DECIMAL,HEXADECIMAL,DESCRIPTION\n" +
				"FILE,MD5SUM,TIMESTAMP\n" +
				"/tmp/fw.bin,d41d8cd98f00b204e9800998ecf8427e,2023-04-05 06:07:08\n" +
				"DECIMAL,HEXADECIMAL,DESCRIPTION\n" +
				"4096,4096,Squashfs filesystem\n",
			want: []signatureRow{{Offset: 4096, OffsetHex: "0x1000", Description: "Squashfs filesystem"}},
		},
		{
			name: "empty log",
			csv:  "DECIMAL,HEXADECIMAL,DESCRIPTION\n",
			want: nil,
		},
		{
			name: "malformed lines are skipped",
			csv:  "DECIMAL,HEXADECIMAL,DESCRIPTION\nnot,a\n7,7,ELF\n",
			want: []signatureRow{{Offset: 7, OffsetHex: "0x7", Description: "ELF"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseBinwalkCSV([]byte(tc.csv))
			if len(got) != len(tc.want) {
				t.Fatalf("expected %d rows, got %d (%v)", len(tc.want), len(got), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("row %d: expected %+v, got %+v", i, tc.want[i], got[i])
				}
			}
		})
	}
}
