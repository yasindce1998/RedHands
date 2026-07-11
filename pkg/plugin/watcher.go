package plugin

import (
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
	mu       sync.Mutex
	dir      string
	interval time.Duration
	tracked  map[string]time.Time
	onReload ReloadCallback
	stop     chan struct{}
}

func NewWatcher(dir string, interval time.Duration, onReload ReloadCallback) *Watcher {
	if interval == 0 {
		interval = 5 * time.Second
	}
	return &Watcher{
		dir:      dir,
		interval: interval,
		tracked:  make(map[string]time.Time),
		onReload: onReload,
		stop:     make(chan struct{}),
	}
}

func (w *Watcher) Start() {
	go w.pollLoop()
}

func (w *Watcher) Stop() {
	close(w.stop)
}

func (w *Watcher) pollLoop() {
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
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := filepath.Ext(entry.Name())
		if ext != ".so" && ext != ".plugin" {
			continue
		}

		path := filepath.Join(w.dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		modTime := info.ModTime()
		prev, exists := w.tracked[path]

		if !exists || modTime.After(prev) {
			w.tracked[path] = modTime
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
