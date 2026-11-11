package evidence

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/storage"
)

const (
	MaxArtifactBytes = 32 * 1024 * 1024
	maxIndexBytes    = 16 * 1024 * 1024
	maxItems         = 10000
	indexFile        = "index.json"
)

var extensionPattern = regexp.MustCompile(`^\.[a-zA-Z0-9]{1,10}$`)
var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Item struct {
	ID        string    `json:"id"`
	Tool      string    `json:"tool"`
	Host      string    `json:"host"`
	Type      string    `json:"type"`
	Path      string    `json:"path"`
	Timestamp time.Time `json:"timestamp"`
	Notes     string    `json:"notes,omitempty"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
}

// Paths in the on-disk index are direct-child filenames, not deployment-specific
// absolute paths. Public Item values retain absolute paths for existing callers.
type diskIndex struct {
	Version int     `json:"version"`
	Items   []*Item `json:"items"`
}

type Store struct {
	mu        sync.RWMutex
	dir       string
	items     []*Item
	writeFile func(*os.Root, string, []byte) error
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create evidence dir: %w", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: abs, items: make([]*Item, 0), writeFile: storage.WriteFileInRoot}
	if err := s.load(); err != nil {
		return nil, fmt.Errorf("load evidence index: %w", err)
	}
	return s, nil
}

func (s *Store) load() error {
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	data, err := storage.ReadRegularFile(root, indexFile, maxIndexBytes)
	if os.IsNotExist(err) {
		return nil
	} // Legacy unindexed files remain untouched.
	if err != nil {
		return err
	}
	var index diskIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return err
	}
	if index.Version != 1 || index.Items == nil || len(index.Items) > maxItems {
		return fmt.Errorf("invalid evidence index version or items")
	}
	seen := make(map[string]bool, len(index.Items))
	for _, item := range index.Items {
		if item == nil || !idPattern.MatchString(item.ID) || item.Tool == "" || item.Timestamp.IsZero() || !hashPattern.MatchString(item.SHA256) || item.Size < 0 || item.Size > MaxArtifactBytes {
			return fmt.Errorf("invalid evidence record")
		}
		if item.Type != "output" && item.Type != "file" && item.Type != "screenshot" {
			return fmt.Errorf("invalid evidence type")
		}
		if seen[item.ID] {
			return fmt.Errorf("duplicate evidence ID")
		}
		seen[item.ID] = true
		ext := filepath.Ext(item.Path)
		if !extensionPattern.MatchString(ext) || item.Path != item.ID+ext {
			return fmt.Errorf("invalid evidence artifact path")
		}
		artifact, err := storage.ReadRegularFile(root, item.Path, MaxArtifactBytes)
		if err != nil {
			return fmt.Errorf("evidence %s: %w", item.ID, err)
		}
		digest := sha256.Sum256(artifact)
		if int64(len(artifact)) != item.Size || hex.EncodeToString(digest[:]) != item.SHA256 {
			return fmt.Errorf("evidence %s failed size/checksum verification", item.ID)
		}
		item.Path = filepath.Join(s.dir, item.Path)
	}
	s.items = index.Items
	return nil
}

func (s *Store) SaveOutput(tool, host, output string) (*Item, error) {
	if len(output) > MaxArtifactBytes {
		return nil, fmt.Errorf("evidence exceeds 32 MiB limit")
	}
	return s.save(tool, host, []byte(output), ".txt", "output")
}

func (s *Store) SaveFile(tool, host string, data []byte, ext string) (*Item, error) {
	return s.save(tool, host, data, ext, "file")
}

func (s *Store) save(tool, host string, data []byte, ext, kind string) (*Item, error) {
	if tool == "" {
		return nil, fmt.Errorf("tool is required")
	}
	if !extensionPattern.MatchString(ext) {
		return nil, fmt.Errorf("extension must be a dot followed by 1-10 ASCII letters/digits")
	}
	if len(data) > MaxArtifactBytes {
		return nil, fmt.Errorf("evidence exceeds 32 MiB limit")
	}
	// Snapshot caller-owned bytes so metadata and the published file describe
	// the same content even while this operation waits for another store write.
	data = bytes.Clone(data)
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(token[:])
	filename := id + ext
	digest := sha256.Sum256(data)
	item := &Item{ID: id, Tool: tool, Host: host, Type: kind, Path: filepath.Join(s.dir, filename), Timestamp: time.Now().UTC(), SHA256: hex.EncodeToString(digest[:]), Size: int64(len(data))}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.items) >= maxItems {
		return nil, fmt.Errorf("evidence index is full")
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	if _, err := root.Lstat(filename); !os.IsNotExist(err) {
		return nil, fmt.Errorf("evidence artifact path already exists or is unreadable")
	}
	candidate := append(append([]*Item(nil), s.items...), item)
	index := diskIndex{Version: 1, Items: make([]*Item, 0, len(candidate))}
	for _, record := range candidate {
		copyItem := *record
		copyItem.Path = filepath.Base(record.Path)
		index.Items = append(index.Items, &copyItem)
	}
	encoded, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxIndexBytes {
		return nil, fmt.Errorf("evidence index exceeds size limit")
	}
	artifactErr := s.writeFile(root, filename, data)
	if artifactErr != nil && !storage.Committed(artifactErr) {
		return nil, fmt.Errorf("write evidence: %w", artifactErr)
	}
	indexErr := s.writeFile(root, indexFile, encoded)
	if indexErr != nil && !storage.Committed(indexErr) {
		// Never remove an artifact after its index entry has committed. Before
		// that point this new, randomly named file belongs only to this operation.
		cleanupErr := root.Remove(filename)
		return nil, errors.Join(fmt.Errorf("write evidence index: %w", indexErr), cleanupErr)
	}
	s.items = candidate
	copyItem := *item
	return &copyItem, errors.Join(artifactErr, indexErr)
}

// Screenshot never looks up or starts binaries itself. The caller supplies the
// same allowlisted, bounded executor used by other tools. Staging is private;
// only a verified PNG is copied into the artifact store and indexed.
func (s *Store) Screenshot(ctx context.Context, target string, exec executor.Executor) (*Item, error) {
	if err := ValidateScreenshotURL(target); err != nil {
		return nil, err
	}
	if exec == nil {
		return nil, fmt.Errorf("screenshot executor is not configured")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(s.dir, ".screenshot-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	_, err = exec.Run(ctx, "cutycapt", "--url="+target, "--out="+filepath.Join(stage, "capture.png"), "--min-width=1280", "--delay=2000")
	if err != nil {
		return nil, fmt.Errorf("cutycapt: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(stage)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	data, err := storage.ReadRegularFile(root, "capture.png", MaxArtifactBytes)
	if err != nil {
		return nil, fmt.Errorf("read screenshot: %w", err)
	}
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("invalid PNG screenshot: %w", err)
	}
	if config.Width <= 0 || config.Height <= 0 || int64(config.Width)*int64(config.Height) > 16*1024*1024 {
		return nil, fmt.Errorf("screenshot exceeds 16 megapixel limit")
	}
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("invalid PNG screenshot: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.save("cutycapt", target, data, ".png", "screenshot")
}

func (s *Store) List() []*Item                  { return s.Query("", "") }
func (s *Store) ListByTool(tool string) []*Item { return s.Query(tool, "") }
func (s *Store) ListByHost(host string) []*Item { return s.Query("", host) }

func (s *Store) Query(tool, host string) []*Item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Item, 0)
	for _, item := range s.items {
		if (tool != "" && item.Tool != tool) || (host != "" && item.Host != host) {
			continue
		}
		copyItem := *item
		result = append(result, &copyItem)
	}
	return result
}

func (s *Store) Dir() string { return s.dir }
