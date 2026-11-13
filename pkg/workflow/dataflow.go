package workflow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// maxSubstitutionBytes bounds substituted campaign parameters, mirroring the
// sequential engine.
const maxSubstitutionBytes = 10 * 1024 * 1024

// placeholderRe matches campaign variable references:
//
//	${step_id.text}              ${step_id.json.path.to.value}
//	$prev.text                   $prev.json.path
//	$step[2].text                $step[2].json.path
//
// JSON paths are dot-separated keys and array indices (e.g. "hosts.0.ip").
var placeholderRe = regexp.MustCompile(
	`\$\{(?P<nid>[A-Za-z0-9_-]+)\.(?P<nfield>text|json)(?:\.(?P<npath>[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*))?\}` +
		`|\$prev\.(?P<pfield>text|json)(?:\.(?P<ppath>[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*))?` +
		`|\$step\[(?P<sid>\d+)\]\.(?P<sfield>text|json)(?:\.(?P<spath>[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*))?`)

// substituteCampaignVars replaces campaign placeholders inside params.
//
// Placeholders that make up an entire string value are substituted natively:
// the extracted value keeps its JSON type (string, number, bool, object, or
// array). Placeholders embedded inside a larger string are substituted as
// text. Unresolvable placeholders are left untouched so downstream tool
// validation surfaces the mistake.
func substituteCampaignVars(params json.RawMessage, named map[string]StepResult, indexed []StepResult) (json.RawMessage, error) {
	if len(params) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(params))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("invalid step params: %w", err)
	}

	budget := maxSubstitutionBytes
	replaced, err := replacePlaceholders(value, &budget, named, indexed)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(replaced)
	if err != nil {
		return nil, fmt.Errorf("marshal substituted params: %w", err)
	}
	if len(data) > maxSubstitutionBytes {
		return nil, fmt.Errorf("substituted campaign parameters exceed 10 MiB")
	}
	return data, nil
}

func replacePlaceholders(v any, budget *int, named map[string]StepResult, indexed []StepResult) (any, error) {
	switch typed := v.(type) {
	case string:
		return substituteString(typed, budget, named, indexed)
	case []any:
		for i, item := range typed {
			replaced, err := replacePlaceholders(item, budget, named, indexed)
			if err != nil {
				return nil, err
			}
			typed[i] = replaced
		}
	case map[string]any:
		for key, item := range typed {
			replaced, err := replacePlaceholders(item, budget, named, indexed)
			if err != nil {
				return nil, err
			}
			typed[key] = replaced
		}
	}
	return v, nil
}

func substituteString(s string, budget *int, named map[string]StepResult, indexed []StepResult) (any, error) {
	matches := placeholderRe.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s, nil
	}

	// A string that is exactly one placeholder substitutes natively,
	// preserving the extracted value's JSON type.
	if len(matches) == 1 {
		m := matches[0]
		if m[0] == 0 && m[1] == len(s) {
			if val, ok := resolvePlaceholder(placeholderGroups(s, m), named, indexed); ok {
				return val, nil
			}
			return s, nil
		}
	}

	var b strings.Builder
	last := 0
	for _, m := range matches {
		val, ok := resolvePlaceholder(placeholderGroups(s, m), named, indexed)
		if !ok {
			continue
		}
		b.WriteString(s[last:m[0]])
		text := ValueToString(val)
		if *budget < len(text) {
			return nil, fmt.Errorf("substituted campaign parameters exceed 10 MiB")
		}
		*budget -= len(text)
		b.WriteString(text)
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String(), nil
}

// placeholderGroups extracts the named capture groups for one match.
func placeholderGroups(s string, m []int) map[string]string {
	groups := make(map[string]string)
	for _, name := range []string{"nid", "nfield", "npath", "pfield", "ppath", "sid", "sfield", "spath"} {
		idx := placeholderRe.SubexpIndex(name)
		if idx >= 0 && m[2*idx] >= 0 {
			groups[name] = s[m[2*idx]:m[2*idx+1]]
		}
	}
	return groups
}

// resolvePlaceholder resolves one matched placeholder to a value.
func resolvePlaceholder(groups map[string]string, named map[string]StepResult, indexed []StepResult) (any, bool) {
	switch {
	case groups["nid"] != "":
		r, ok := named[groups["nid"]]
		if !ok {
			return nil, false
		}
		return resultField(r, groups["nfield"], groups["npath"])
	case groups["pfield"] != "":
		if len(indexed) == 0 {
			return nil, false
		}
		return resultField(indexed[len(indexed)-1], groups["pfield"], groups["ppath"])
	case groups["sid"] != "":
		idx, err := strconv.Atoi(groups["sid"])
		if err != nil || idx < 0 || idx >= len(indexed) {
			return nil, false
		}
		return resultField(indexed[idx], groups["sfield"], groups["spath"])
	}
	return nil, false
}

// resultField extracts "text" or "json[.path]" from a step result.
func resultField(r StepResult, field, path string) (any, bool) {
	if field == "text" {
		return r.Text, true
	}
	raw, ok := extractStructured(r)
	if !ok {
		return nil, false
	}
	if path == "" {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
		return value, true
	}
	return lookupPath(raw, path)
}

// StructuredFromText extracts machine-readable JSON from an arbitrary
// string. It accepts pure JSON as well as JSON fenced in a markdown code
// block, the format RedHands tools emit. It is exported so the application
// layer can reuse the same extraction when migrating step results to
// structured content channels.
func StructuredFromText(text string) (json.RawMessage, bool) {
	s := strings.TrimSpace(text)
	if s == "" {
		return nil, false
	}
	if json.Valid([]byte(s)) {
		return json.RawMessage(s), true
	}
	// First ```json fenced block.
	if i := strings.Index(s, "```json"); i >= 0 {
		rest := s[i+len("```json"):]
		if j := strings.Index(rest, "```"); j >= 0 {
			inner := strings.TrimSpace(rest[:j])
			if json.Valid([]byte(inner)) {
				return json.RawMessage(inner), true
			}
		}
	}
	return nil, false
}

// extractStructured returns machine-readable JSON from a step result.
func extractStructured(r StepResult) (json.RawMessage, bool) {
	return StructuredFromText(r.Text)
}

// lookupPath resolves a dot-separated path ("hosts.0.ip") against raw JSON.
// Numeric segments index into arrays.
func lookupPath(raw json.RawMessage, path string) (any, bool) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	return LookupPathValue(value, path)
}

// LookupPathValue resolves a dot-separated path against an already-decoded
// JSON value (maps, slices, json.Number scalars). Numeric segments index into
// arrays. It is exported for step recorders that inspect step output.
func LookupPathValue(value any, path string) (any, bool) {
	current := value
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			continue
		}
		switch typed := current.(type) {
		case map[string]any:
			next, ok := typed[seg]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(typed) {
				return nil, false
			}
			current = typed[idx]
		default:
			return nil, false
		}
	}
	return current, true
}

// ValueToString renders a resolved value for embedding inside a larger string.
// Exported for step recorders that map JSON values onto database fields.
func ValueToString(v any) string {
	switch typed := v.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case bool:
		return strconv.FormatBool(typed)
	case nil:
		return ""
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(data)
	}
}
