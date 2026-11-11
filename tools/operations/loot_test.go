package operations

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/yasindce1998/redhands/pkg/loot"
)

func TestLootToolsValidateAndPersist(t *testing.T) {
	dir := t.TempDir()
	store, err := loot.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	add := NewLootAddTool(store)
	for _, params := range []string{`{}`, `{"type":"file"}`, `{"type":123,"description":"bad"}`} {
		result, err := add.Execute(context.Background(), json.RawMessage(params))
		if err != nil || !result.IsError {
			t.Fatalf("invalid add accepted: %+v %v", result, err)
		}
	}
	result, err := add.Execute(context.Background(), json.RawMessage(`{"type":"file","description":"artifact","host":"192.0.2.1"}`))
	if err != nil || result.IsError {
		t.Fatalf("add failed: %+v %v", result, err)
	}
	reopened, err := loot.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	list := NewLootListTool(reopened)
	result, err = list.Execute(context.Background(), json.RawMessage(`{"type":"file","host":"192.0.2.1"}`))
	if err != nil || result.IsError {
		t.Fatalf("list failed: %+v %v", result, err)
	}
	var items []*loot.Item
	if err := json.Unmarshal([]byte(result.Content[0].Text), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatal("saved loot missing")
	}
	result, err = list.Execute(context.Background(), json.RawMessage(`{"type":123}`))
	if err != nil || !result.IsError {
		t.Fatal("bad filter accepted")
	}
}
