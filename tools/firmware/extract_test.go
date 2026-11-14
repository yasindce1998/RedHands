package firmware

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
)

// extractCSVFixture mirrors a recursive (matryoshka) extraction run: binwalk
// forces verbose mode when -d is given, which interleaves FILE/MD5SUM/
// TIMESTAMP rows and repeated header rows into the CSV log. The parser must
// skip all of them.
const extractCSVFixture = `DECIMAL,HEXADECIMAL,DESCRIPTION
FILE,MD5SUM,TIMESTAMP
/tmp/firmware/fw.bin,d41d8cd98f00b204e9800998ecf8427e,2023-04-05 06:07:08
DECIMAL,HEXADECIMAL,DESCRIPTION
0,0,"gzip compressed data, from Unix, last modified: 2023-04-05 06:07:08, original size: 4567"
4096,4096,"Squashfs filesystem, little endian, version 4.0, compression:gzip, size: 1234567 bytes, 512 inodes, blocksize: 131072 bytes, created: 2023-04-05 06:07:09"
`

// extractionMock simulates a successful binwalk -e run: it writes the CSV to
// the -f log path and lays down extracted files under the -C output
// directory, in <outdir>/_<image basename>.extracted/, the way the real
// extractor does.
func extractionMock(t *testing.T, image string) *executor.MockExecutor {
	t.Helper()
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, args []string) []byte {
		outDir := ""
		logPath := ""
		for i, a := range args {
			if a == "-C" && i+1 < len(args) {
				outDir = args[i+1]
			}
			if a == "-f" && i+1 < len(args) {
				logPath = args[i+1]
			}
		}
		if logPath != "" {
			if err := os.WriteFile(logPath, []byte(extractCSVFixture), 0o600); err != nil {
				t.Errorf("mock failed to write CSV log: %v", err)
			}
		}
		if outDir != "" {
			extracted := filepath.Join(outDir, "_"+filepath.Base(image)+".extracted", "squashfs-root")
			for _, name := range []string{"etc/passwd", "bin/busybox"} {
				path := filepath.Join(extracted, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Errorf("mock failed to create extracted dir: %v", err)
					continue
				}
				if err := os.WriteFile(path, []byte("fake extracted bytes"), 0o600); err != nil {
					t.Errorf("mock failed to write extracted file: %v", err)
				}
			}
		}
		return []byte("")
	}
	return mock
}

func TestFirmwareExtract_Execute(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	outDir := filepath.Join(t.TempDir(), "extracted")
	mock := extractionMock(t, image)
	tool := NewFirmwareExtract(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"image":      image,
		"output_dir": outDir,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	for _, want := range []string{"HIGH IMPACT", "Extraction directory", "Mode:** auto-extraction", "Extracted files:** 2", "untrusted"} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in result, got:\n%s", want, text)
		}
	}

	var summary struct {
		Image               string `json:"image"`
		OutputDir           string `json:"output_dir"`
		ExtractionDirectory string `json:"extraction_directory"`
		SignatureCount      int    `json:"signature_count"`
		ExtractedFileCount  int    `json:"extracted_file_count"`
		ExtractedFiles      []struct {
			Path  string `json:"path"`
			Bytes int64  `json:"bytes"`
		} `json:"extracted_files"`
		Signatures []struct {
			Offset    int64  `json:"offset"`
			OffsetHex string `json:"offset_hex"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal([]byte(extractJSONBlock(t, text)), &summary); err != nil {
		t.Fatalf("summary is not valid JSON: %v\n%s", err, text)
	}
	if summary.ExtractedFileCount != 2 || len(summary.ExtractedFiles) != 2 {
		t.Errorf("unexpected extracted file counts: %+v", summary)
	}
	wantDir := filepath.Join(outDir, "_fw.bin.extracted")
	if summary.ExtractionDirectory != wantDir {
		t.Errorf("expected extraction directory %q, got %q", wantDir, summary.ExtractionDirectory)
	}
	if len(summary.ExtractedFiles) > 0 && !strings.HasPrefix(summary.ExtractedFiles[0].Path, "_fw.bin.extracted") {
		t.Errorf("extracted file paths should be relative to the output dir, got %q", summary.ExtractedFiles[0].Path)
	}
	if len(summary.ExtractedFiles) > 0 && summary.ExtractedFiles[0].Bytes != int64(len("fake extracted bytes")) {
		t.Errorf("unexpected extracted file size: %+v", summary.ExtractedFiles[0])
	}
	// The FILE/MD5SUM/TIMESTAMP verbose rows must not be counted as
	// signatures.
	if summary.SignatureCount != 2 || len(summary.Signatures) != 2 {
		t.Errorf("unexpected signature count: %+v", summary)
	}
	if summary.Signatures[1].Offset != 4096 || summary.Signatures[1].OffsetHex != "0x1000" {
		t.Errorf("unexpected second signature: %+v", summary.Signatures[1])
	}

	call := mock.LastCall()
	if call.Binary != "binwalk" {
		t.Errorf("expected binary binwalk, got %q", call.Binary)
	}
	assertFlag(t, call.Args, "-e")
	assertNoFlag(t, call.Args, "-D")
	assertArgs(t, call.Args, "-C", outDir)
	assertFlag(t, call.Args, "--csv")
	assertFlag(t, call.Args, "-q")
	assertLastArg(t, call.Args, image)
}

func TestFirmwareExtract_Depth(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := extractionMock(t, image)
	tool := NewFirmwareExtract(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"image":      image,
		"output_dir": t.TempDir(),
		"depth":      3,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Recursion depth:** 3") {
		t.Errorf("expected recursion depth in result, got: %s", result.Content[0].Text)
	}
	call := mock.LastCall()
	assertArgs(t, call.Args, "-d", "3")
}

func TestFirmwareExtract_DDCarveRule(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := extractionMock(t, image)
	tool := NewFirmwareExtract(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"image":      image,
		"output_dir": t.TempDir(),
		"dd":         "squashfs:*.sqfs",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Carve rule (--dd):** squashfs:*.sqfs") {
		t.Errorf("expected carve rule in result, got: %s", result.Content[0].Text)
	}
	call := mock.LastCall()
	assertArgs(t, call.Args, "-D", "squashfs:*.sqfs")
	// A --dd rule replaces full auto-extraction; -e must not be passed.
	assertNoFlag(t, call.Args, "-e")
}

func TestFirmwareExtract_InvalidDD(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	outDir := t.TempDir()

	cases := []struct {
		name string
		dd   string
		want string
	}{
		// The third component of binwalk's --dd rule format is an external
		// command binwalk would execute; it must be rejected.
		{"command component", "squashfs:*.sqfs:unsquashfs -d out %e", "not exposed"},
		{"missing extension", "squashfs", "invalid dd rule"},
		{"empty type", ":sqfs", "invalid dd rule"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := NewFirmwareExtract(executor.NewMock()).Execute(context.Background(), mustJSON(map[string]any{
				"image":      image,
				"output_dir": outDir,
				"dd":         tc.dd,
			}))
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

func TestFirmwareExtract_InvalidDepth(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	outDir := t.TempDir()

	for _, depth := range []int{0, -1, 65} {
		t.Run("depth", func(t *testing.T) {
			result, err := NewFirmwareExtract(executor.NewMock()).Execute(context.Background(), mustJSON(map[string]any{
				"image":      image,
				"output_dir": outDir,
				"depth":      depth,
			}))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected error for depth %d, got success", depth)
			}
			if !strings.Contains(result.Content[0].Text, "depth must be between 1 and 64") {
				t.Errorf("expected depth bounds error, got: %s", result.Content[0].Text)
			}
		})
	}
}

func TestFirmwareExtract_OutputDirCreated(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	nested := filepath.Join(t.TempDir(), "loot", "fw-extracted")

	result, err := NewFirmwareExtract(extractionMock(t, image)).Execute(context.Background(), mustJSON(map[string]any{
		"image":      image,
		"output_dir": nested,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if info, err := os.Stat(nested); err != nil || !info.IsDir() {
		t.Errorf("expected output dir to be created, got err=%v", err)
	}
}

func TestFirmwareExtract_OutputDirIsFile(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	notADir := filepath.Join(t.TempDir(), "plain-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	result, err := NewFirmwareExtract(executor.NewMock()).Execute(context.Background(), mustJSON(map[string]any{
		"image":      image,
		"output_dir": notADir,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when output_dir is a file")
	}
	if !strings.Contains(result.Content[0].Text, "is a file, not a directory") {
		t.Errorf("expected not-a-directory error, got: %s", result.Content[0].Text)
	}
}

func TestFirmwareExtract_InvalidInput(t *testing.T) {
	image := tempImageFile(t, "fw.bin")

	cases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"image missing", map[string]any{"output_dir": t.TempDir()}, "image is required"},
		{"image nonexistent", map[string]any{"image": "/nonexistent/fw.bin", "output_dir": t.TempDir()}, "not accessible"},
		{"output_dir missing", map[string]any{"image": image}, "output_dir is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := NewFirmwareExtract(executor.NewMock()).Execute(context.Background(), mustJSON(tc.params))
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

func TestFirmwareExtract_ExecutorError(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	mock := executor.NewMock()
	mock.StderrFn = func(_ string, _ []string) []byte {
		return []byte("Extractor Exception: no extraction rules")
	}
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"execution failed (exit 3): exit status 3"}
	}

	result, err := NewFirmwareExtract(mock).Execute(context.Background(), mustJSON(map[string]any{
		"image":      image,
		"output_dir": t.TempDir(),
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true when executor fails")
	}
	if !strings.Contains(result.Content[0].Text, "no extraction rules") {
		t.Errorf("expected stderr in error, got: %s", result.Content[0].Text)
	}
}
