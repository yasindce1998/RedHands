package plugin

import (
	"crypto/sha256"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type PluginInfo struct {
	Path    string
	ModTime time.Time
}

type ReloadCallback func(path string) error

type Watcher struct {
	mu        sync.Mutex
	dir       string
	interval  time.Duration
	tracked   map[string]time.Time
	hashes    map[string][32]byte
	onReload  ReloadCallback
	stop      chan struct{}
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

func NewWatcher(dir string, interval time.Duration, onReload ReloadCallback) *Watcher {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Watcher{
		dir:      dir,
		interval: interval,
		tracked:  make(map[string]time.Time),
		hashes:   make(map[string][32]byte),
		onReload: onReload,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (w *Watcher) Start() {
	w.startOnce.Do(func() { go w.pollLoop() })
}

func (w *Watcher) Stop() {
	w.Start()
	w.stopOnce.Do(func() { close(w.stop) })
	<-w.done
}

func (w *Watcher) pollLoop() {
	defer close(w.done)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	w.scan()

	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			w.scan()
		}
	}
}

func (w *Watcher) scan() {
	w.mu.Lock()
	defer w.mu.Unlock()

	entries, err := os.ReadDir(w.dir)
	if err != nil && !os.IsNotExist(err) {
		return
	}
	seen := make(map[string]bool)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := filepath.Ext(entry.Name())
		if ext != ".json" {
			continue
		}

		path := filepath.Join(w.dir, entry.Name())
		seen[path] = true
		info, err := entry.Info()
		if err != nil {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		hash := sha256.Sum256(data)
		modTime := info.ModTime()
		prev, exists := w.hashes[path]

		if !exists || hash != prev {
			w.tracked[path] = modTime
			w.hashes[path] = hash
			if exists {
				if w.onReload != nil {
					if err := w.onReload(path); err != nil {
						log.Printf("[plugin] reload failed for %s: %v", path, err)
					} else {
						log.Printf("[plugin] reloaded: %s", path)
					}
				}
			} else {
				log.Printf("[plugin] discovered: %s", path)
				if w.onReload != nil {
					if err := w.onReload(path); err != nil {
						log.Printf("[plugin] initial load failed for %s: %v", path, err)
					}
				}
			}
		}
	}
	for path := range w.tracked {
		if !seen[path] {
			delete(w.tracked, path)
			delete(w.hashes, path)
			if w.onReload != nil {
				if err := w.onReload(path); err != nil {
					log.Printf("plugin removal reload: %v", err)
				}
			}
		}
	}
}

func (w *Watcher) Tracked() []PluginInfo {
	w.mu.Lock()
	defer w.mu.Unlock()

	var plugins []PluginInfo
	for path, modTime := range w.tracked {
		plugins = append(plugins, PluginInfo{Path: path, ModTime: modTime})
	}
	return plugins
}
