package audit

import (
	"encoding/json"
	"strings"
)

var sensitiveKeys = []string{"password", "token", "key", "secret", "credential", "auth"}

const redactedValue = "[REDACTED]"

func SanitizeParams(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}

	var params map[string]any
	if err := json.Unmarshal(raw, &params); err != nil {
		return raw
	}

	sanitized := sanitizeMap(params)
	result, err := json.Marshal(sanitized)
	if err != nil {
		return raw
	}
	return result
}

func sanitizeMap(m map[string]any) map[string]any {
	result := make(map[string]any, len(m))
	for k, v := range m {
		if isSensitiveKey(k) {
			result[k] = redactedValue
			continue
		}
		result[k] = sanitizeValue(v)
	}
	return result
}

func sanitizeValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return sanitizeMap(val)
	case []any:
		result := make([]any, len(val))
		for i, item := range val {
			result[i] = sanitizeValue(item)
		}
		return result
	default:
		return v
	}
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
