package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

type Logger interface {
	Log(ctx context.Context, event AuditEvent) error
	Close() error
}

type FileLogger struct {
	file   *os.File
	mu     sync.Mutex
	events chan AuditEvent
	done   chan struct{}
}

func NewFileLogger(path string) (*FileLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}

	fl := &FileLogger{
		file:   f,
		events: make(chan AuditEvent, 256),
		done:   make(chan struct{}),
	}

	go fl.writer()
	return fl, nil
}

func (l *FileLogger) Log(_ context.Context, event AuditEvent) error {
	event.Params = SanitizeParams(event.Params)

	select {
	case l.events <- event:
		return nil
	default:
		return fmt.Errorf("audit log buffer full")
	}
}

func (l *FileLogger) Close() error {
	close(l.events)
	<-l.done
	return l.file.Close()
}

func (l *FileLogger) writer() {
	defer close(l.done)
	enc := json.NewEncoder(l.file)
	for event := range l.events {
		l.mu.Lock()
		_ = enc.Encode(event)
		l.mu.Unlock()
	}
}
