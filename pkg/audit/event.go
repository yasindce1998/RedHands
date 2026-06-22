package audit

import (
	"encoding/json"
	"time"
)

type AuditEvent struct {
	ID        string          `json:"id"`
	Timestamp time.Time       `json:"timestamp"`
	Actor     string          `json:"actor"`
	Action    string          `json:"action"`
	Tool      string          `json:"tool"`
	Params    json.RawMessage `json:"params"`
	Result    string          `json:"result"`
	Duration  int64           `json:"duration_ms"`
	Error     string          `json:"error,omitempty"`
}
