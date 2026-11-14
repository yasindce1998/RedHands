package firmware

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
)

// entropyCSVFixture mirrors real `binwalk -E -N --csv -f <log>` output from
// v2.3.1: the entropy module overrides the last header column with ENTROPY
// and, in non-verbose mode, only rising/falling edge rows are displayed.
// Offsets are chosen against the 39-byte temp image: the final rising edge
// has no matching falling edge, so its region extends to the file size.
const entropyCSVFixture = `DECIMAL,HEXADECIMAL,ENTROPY
0,0,Rising entropy edge (0.998375)
32,32,Falling entropy edge (0.038757)
36,36,Rising entropy edge (0.991254)
`

const entropyImageSize = 39 // len("\x1f\x8b\x08 fake firmware image with gzip magic")

func TestFirmwareEntropy_Execute(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := executor.NewMock()
	mock.StdoutFn = writeLogFromArgs(t, entropyCSVFixture, "")
	tool := NewFirmwareEntropy(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"image": image}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	for _, want := range []string{"## Firmware Entropy Analysis", "Entropy edges:** 3", "High-entropy regions", "0x0-0x20"} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in result, got:\n%s", want, text)
		}
	}

	var summary struct {
		Image     string `json:"image"`
		EdgeCount int    `json:"edge_count"`
		Edges     []struct {
			Offset    int64   `json:"offset"`
			OffsetHex string  `json:"offset_hex"`
			Type      string  `json:"type"`
			Entropy   float64 `json:"entropy"`
		} `json:"edges"`
		Regions []struct {
			StartOffset    int64  `json:"start_offset"`
			StartOffsetHex string `json:"start_offset_hex"`
			EndOffset      int64  `json:"end_offset"`
			EndOffsetHex   string `json:"end_offset_hex"`
		} `json:"regions"`
	}
	if err := json.Unmarshal([]byte(extractJSONBlock(t, text)), &summary); err != nil {
		t.Fatalf("summary is not valid JSON: %v\n%s", err, text)
	}
	if summary.EdgeCount != 3 || len(summary.Edges) != 3 {
		t.Fatalf("unexpected edge count: %+v", summary)
	}
	if summary.Edges[0].Type != "rising" || summary.Edges[0].Entropy != 0.998375 {
		t.Errorf("unexpected first edge: %+v", summary.Edges[0])
	}
	if summary.Edges[1].Type != "falling" || summary.Edges[1].OffsetHex != "0x20" {
		t.Errorf("unexpected second edge: %+v", summary.Edges[1])
	}
	if len(summary.Regions) != 2 {
		t.Fatalf("expected 2 regions (rising->falling, rising->EOF), got %+v", summary.Regions)
	}
	if summary.Regions[0].StartOffset != 0 || summary.Regions[0].EndOffset != 32 {
		t.Errorf("unexpected first region: %+v", summary.Regions[0])
	}
	// The trailing rising edge extends to the end of the file.
	if summary.Regions[1].StartOffset != 36 || summary.Regions[1].EndOffset != entropyImageSize {
		t.Errorf("unexpected second region: %+v", summary.Regions[1])
	}

	call := mock.LastCall()
	if call.Binary != "binwalk" {
		t.Errorf("expected binary binwalk, got %q", call.Binary)
	}
	assertFlag(t, call.Args, "-E")
	// -N must always accompany -E: plt.show() would hang a headless run.
	assertFlag(t, call.Args, "-N")
	assertFlag(t, call.Args, "--csv")
	assertFlag(t, call.Args, "-q")
	assertNoFlag(t, call.Args, "-K")
	assertNoFlag(t, call.Args, "-B")
	assertLastArg(t, call.Args, image)
}

func TestFirmwareEntropy_Block(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := executor.NewMock()
	mock.StdoutFn = writeLogFromArgs(t, entropyCSVFixture, "")
	tool := NewFirmwareEntropy(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"image": image,
		"block": 4096,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Block size:** 4096 bytes") {
		t.Errorf("expected block size in result, got: %s", result.Content[0].Text)
	}
	call := mock.LastCall()
	assertArgs(t, call.Args, "-K", "4096")
}

func TestFirmwareEntropy_InvalidBlock(t *testing.T) {
	image := tempImageFile(t, "fw.bin")

	for _, block := range []int{0, -1, 20000000} {
		t.Run("block", func(t *testing.T) {
			result, err := NewFirmwareEntropy(executor.NewMock()).Execute(context.Background(), mustJSON(map[string]any{
				"image": image,
				"block": block,
			}))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected error for block %d, got success", block)
			}
			if !strings.Contains(result.Content[0].Text, "block must be between 1 and 16777216") {
				t.Errorf("expected block bounds error, got: %s", result.Content[0].Text)
			}
		})
	}
}

func TestFirmwareEntropy_NoEdges(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := executor.NewMock()
	mock.StdoutFn = writeLogFromArgs(t, "DECIMAL,HEXADECIMAL,ENTROPY\n", "")
	tool := NewFirmwareEntropy(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"image": image}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "No entropy edges") {
		t.Errorf("expected no-edges note, got: %s", text)
	}
	if strings.Contains(text, "High-entropy regions") {
		t.Errorf("no regions expected without edges, got: %s", text)
	}

	var summary struct {
		Edges   []json.RawMessage `json:"edges"`
		Regions []json.RawMessage `json:"regions"`
	}
	if err := json.Unmarshal([]byte(extractJSONBlock(t, text)), &summary); err != nil {
		t.Fatalf("summary is not valid JSON: %v", err)
	}
	if summary.Edges == nil || summary.Regions == nil {
		t.Errorf("edges and regions must be empty arrays, not null")
	}
}

func TestFirmwareEntropy_InvalidInput(t *testing.T) {
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
			result, err := NewFirmwareEntropy(executor.NewMock()).Execute(context.Background(), tc.params)
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

func TestFirmwareEntropy_ExecutorError(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := executor.NewMock()
	mock.StderrFn = func(_ string, _ []string) []byte {
		return []byte("General Error: Cannot open file")
	}
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"execution failed (exit 3): exit status 3"}
	}

	result, err := NewFirmwareEntropy(mock).Execute(context.Background(), mustJSON(map[string]any{"image": image}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true when executor fails")
	}
	if !strings.Contains(result.Content[0].Text, "binwalk failed") {
		t.Errorf("expected failure message, got: %s", result.Content[0].Text)
	}
}

// ---------------------------------------------------------------------------
// Region builder unit tests
// ---------------------------------------------------------------------------

func TestEntropyRegions(t *testing.T) {
	edges := []entropyEdge{
		{Offset: 0, OffsetHex: "0x0", Type: "rising", Entropy: 0.99},
		{Offset: 1024, OffsetHex: "0x400", Type: "falling", Entropy: 0.04},
		{Offset: 2048, OffsetHex: "0x800", Type: "rising", Entropy: 0.97},
		{Offset: 4096, OffsetHex: "0x1000", Type: "falling", Entropy: 0.03},
	}
	regions := entropyRegions(edges, 8192)
	if len(regions) != 2 {
		t.Fatalf("expected 2 regions, got %d: %+v", len(regions), regions)
	}
	if regions[0].StartOffset != 0 || regions[0].EndOffset != 1024 {
		t.Errorf("unexpected first region: %+v", regions[0])
	}
	if regions[1].StartOffset != 2048 || regions[1].EndOffset != 4096 {
		t.Errorf("unexpected second region: %+v", regions[1])
	}

	// A lone falling edge closes nothing.
	if regions := entropyRegions([]entropyEdge{{Offset: 512, Type: "falling"}}, 8192); len(regions) != 0 {
		t.Errorf("expected no regions from a lone falling edge, got %+v", regions)
	}

	// A trailing rising edge extends to the file size, clamped so the region
	// never has a negative length.
	regions = entropyRegions([]entropyEdge{{Offset: 5000, OffsetHex: "0x1388", Type: "rising", Entropy: 0.99}}, 4096)
	if len(regions) != 1 || regions[0].StartOffset != 5000 || regions[0].EndOffset != 5000 {
		t.Errorf("expected clamped region, got %+v", regions)
	}
}
