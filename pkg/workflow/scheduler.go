package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scheduler runs workflows on cron-like schedules.
type Scheduler struct {
	mu       sync.RWMutex
	entries  map[string]*ScheduleEntry
	engine   *EnhancedEngine
	file     string
	stopCh   chan struct{}
	running  bool
}

// NewScheduler creates a new workflow scheduler.
func NewScheduler(engine *EnhancedEngine, file string) *Scheduler {
	s := &Scheduler{
		entries: make(map[string]*ScheduleEntry),
		engine:  engine,
		file:    file,
		stopCh:  make(chan struct{}),
	}
	s.load()
	return s
}

// Add registers a new scheduled workflow.
func (s *Scheduler) Add(entry *ScheduleEntry) error {
	if entry.ID == "" {
		entry.ID = GenerateID()
	}
	if _, err := parseCron(entry.Cron); err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}

	s.mu.Lock()
	entry.Enabled = true
	entry.NextRun = nextCronTime(entry.Cron, time.Now()).Unix()
	s.entries[entry.ID] = entry
	s.mu.Unlock()

	return s.save()
}

// Remove deletes a scheduled workflow.
func (s *Scheduler) Remove(id string) error {
	s.mu.Lock()
	delete(s.entries, id)
	s.mu.Unlock()
	return s.save()
}

// List returns all schedule entries.
func (s *Scheduler) List() []*ScheduleEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*ScheduleEntry, 0, len(s.entries))
	for _, e := range s.entries {
		result = append(result, e)
	}
	return result
}

// Start begins the scheduler loop.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	go s.loop(ctx)
}

// Stop halts the scheduler.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		close(s.stopCh)
		s.running = false
	}
}

func (s *Scheduler) loop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case now := <-ticker.C:
			s.checkAndRun(ctx, now)
		}
	}
}

func (s *Scheduler) checkAndRun(ctx context.Context, now time.Time) {
	s.mu.RLock()
	var toRun []*ScheduleEntry
	for _, e := range s.entries {
		if e.Enabled && now.Unix() >= e.NextRun {
			toRun = append(toRun, e)
		}
	}
	s.mu.RUnlock()

	for _, e := range toRun {
		go func(entry *ScheduleEntry) {
			_, _ = s.engine.RunEnhanced(ctx, &entry.Workflow)

			s.mu.Lock()
			entry.LastRun = time.Now().Unix()
			entry.NextRun = nextCronTime(entry.Cron, time.Now()).Unix()
			s.mu.Unlock()

			_ = s.save()
		}(e)
	}
}

func (s *Scheduler) load() {
	if s.file == "" {
		return
	}
	data, err := os.ReadFile(s.file)
	if err != nil {
		return
	}
	var entries []*ScheduleEntry
	if json.Unmarshal(data, &entries) == nil {
		for _, e := range entries {
			s.entries[e.ID] = e
		}
	}
}

func (s *Scheduler) save() error {
	if s.file == "" {
		return nil
	}

	s.mu.RLock()
	entries := make([]*ScheduleEntry, 0, len(s.entries))
	for _, e := range s.entries {
		entries = append(entries, e)
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.file)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(s.file, data, 0600)
}

// cronSpec holds parsed cron fields.
type cronSpec struct {
	minute, hour, dom, month, dow []int
}

// parseCron parses a 5-field cron expression (minute hour dom month dow).
func parseCron(expr string) (*cronSpec, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("expected 5 fields, got %d", len(fields))
	}

	minute, err := parseCronField(fields[0], 0, 59)
	if err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	hour, err := parseCronField(fields[1], 0, 23)
	if err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	dom, err := parseCronField(fields[2], 1, 31)
	if err != nil {
		return nil, fmt.Errorf("day of month: %w", err)
	}
	month, err := parseCronField(fields[3], 1, 12)
	if err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	dow, err := parseCronField(fields[4], 0, 6)
	if err != nil {
		return nil, fmt.Errorf("day of week: %w", err)
	}

	return &cronSpec{minute: minute, hour: hour, dom: dom, month: month, dow: dow}, nil
}

func parseCronField(field string, min, max int) ([]int, error) {
	if field == "*" {
		return nil, nil // nil means "all"
	}

	// Handle */N
	if strings.HasPrefix(field, "*/") {
		step, err := strconv.Atoi(field[2:])
		if err != nil || step <= 0 {
			return nil, fmt.Errorf("invalid step: %s", field)
		}
		var vals []int
		for i := min; i <= max; i += step {
			vals = append(vals, i)
		}
		return vals, nil
	}

	// Handle comma-separated values and ranges
	var vals []int
	for _, part := range strings.Split(field, ",") {
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid range start: %s", part)
			}
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid range end: %s", part)
			}
			for i := start; i <= end; i++ {
				vals = append(vals, i)
			}
		} else {
			v, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid value: %s", part)
			}
			vals = append(vals, v)
		}
	}
	return vals, nil
}

func nextCronTime(expr string, after time.Time) time.Time {
	spec, err := parseCron(expr)
	if err != nil {
		return after.Add(time.Hour)
	}

	t := after.Add(time.Minute).Truncate(time.Minute)

	for i := 0; i < 525600; i++ { // max 1 year of minutes
		if matchesCron(spec, t) {
			return t
		}
		t = t.Add(time.Minute)
	}

	return after.Add(time.Hour)
}

func matchesCron(spec *cronSpec, t time.Time) bool {
	if spec.minute != nil && !containsInt(spec.minute, t.Minute()) {
		return false
	}
	if spec.hour != nil && !containsInt(spec.hour, t.Hour()) {
		return false
	}
	if spec.dom != nil && !containsInt(spec.dom, t.Day()) {
		return false
	}
	if spec.month != nil && !containsInt(spec.month, int(t.Month())) {
		return false
	}
	if spec.dow != nil && !containsInt(spec.dow, int(t.Weekday())) {
		return false
	}
	return true
}

func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}
