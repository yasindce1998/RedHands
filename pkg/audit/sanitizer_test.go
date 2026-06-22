package audit

import (
	"encoding/json"
	"testing"
)

func TestSanitizeParams(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]any
	}{
		{
			name:  "redacts password",
			input: `{"target": "192.168.1.1", "password": "secret123"}`,
			expected: map[string]any{
				"target":   "192.168.1.1",
				"password": "[REDACTED]",
			},
		},
		{
			name:  "redacts api_token",
			input: `{"host": "example.com", "api_token": "tok_abc123"}`,
			expected: map[string]any{
				"host":      "example.com",
				"api_token": "[REDACTED]",
			},
		},
		{
			name:  "redacts nested secret",
			input: `{"config": {"secret_key": "mysecret", "port": 8080}}`,
			expected: map[string]any{
				"config": map[string]any{
					"secret_key": "[REDACTED]",
					"port":       float64(8080),
				},
			},
		},
		{
			name:  "no sensitive keys",
			input: `{"target": "10.0.0.1", "ports": "80,443"}`,
			expected: map[string]any{
				"target": "10.0.0.1",
				"ports":  "80,443",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeParams(json.RawMessage(tt.input))

			var got map[string]any
			if err := json.Unmarshal(result, &got); err != nil {
				t.Fatalf("unmarshaling result: %v", err)
			}

			assertMapsEqual(t, tt.expected, got)
		})
	}
}

func assertMapsEqual(t *testing.T, expected, got map[string]any) {
	t.Helper()
	for k, v := range expected {
		gv, ok := got[k]
		if !ok {
			t.Errorf("missing key %q", k)
			continue
		}
		switch ev := v.(type) {
		case map[string]any:
			gm, ok := gv.(map[string]any)
			if !ok {
				t.Errorf("key %q: expected map, got %T", k, gv)
				continue
			}
			assertMapsEqual(t, ev, gm)
		default:
			if gv != v {
				t.Errorf("key %q: expected %v, got %v", k, v, gv)
			}
		}
	}
}
