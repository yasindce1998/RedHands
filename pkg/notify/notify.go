package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Event struct {
	Type    string `json:"type"`
	Tool    string `json:"tool,omitempty"`
	Target  string `json:"target,omitempty"`
	Message string `json:"message"`
	Time    string `json:"time"`
}

type Notifier struct {
	webhooks []string
	events   []string
	client   *http.Client
}

func NewNotifier(webhooks []string, events []string) *Notifier {
	return &Notifier{
		webhooks: webhooks,
		events:   events,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *Notifier) Notify(ctx context.Context, evt Event) {
	if !n.shouldNotify(evt.Type) {
		return
	}

	evt.Time = time.Now().Format(time.RFC3339)

	for _, url := range n.webhooks {
		go n.send(ctx, url, evt)
	}
}

func (n *Notifier) shouldNotify(eventType string) bool {
	if len(n.events) == 0 {
		return true
	}
	for _, e := range n.events {
		if e == eventType || e == "all" {
			return true
		}
	}
	return false
}

func (n *Notifier) send(_ context.Context, url string, evt Event) {
	payload := map[string]interface{}{
		"text":    fmt.Sprintf("[RedHands] %s: %s", evt.Type, evt.Message),
		"content": fmt.Sprintf("[RedHands] %s: %s", evt.Type, evt.Message),
		"event":   evt,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

func (n *Notifier) WebhookCount() int {
	return len(n.webhooks)
}
