package mcp

import (
	"encoding/json"
	"testing"
)

// TestTaskResultFromStateMapping unit-tests the campaign-state → task
// status mapping used by tasks/get.
func TestTaskResultFromStateMapping(t *testing.T) {
	cases := []struct {
		name  string
		state taskState
		check func(*testing.T, GetTaskResult)
	}{
		{
			name:  "running is working",
			state: taskState{Status: "running"},
			check: func(t *testing.T, r GetTaskResult) {
				if r.Status != TaskStatusWorking || r.StatusMessage != "" {
					t.Fatalf("running mapping = %+v", r)
				}
			},
		},
		{
			name:  "paused is working and resumable",
			state: taskState{Status: "paused", NextIndex: 3},
			check: func(t *testing.T, r GetTaskResult) {
				if r.Status != TaskStatusWorking || r.StatusMessage != "paused at step 3; resumable" {
					t.Fatalf("paused mapping = %+v", r)
				}
			},
		},
		{
			name: "paused with pending approval is input_required",
			state: taskState{Status: "paused", PendingApproval: &taskPendingApproval{
				Tool: "dangerous_tool", StepID: "gate", RequestID: "req_1", Message: "approve me",
			}},
			check: func(t *testing.T, r GetTaskResult) {
				if r.Status != TaskStatusInputRequired {
					t.Fatalf("approval mapping = %+v", r)
				}
				req, ok := r.InputRequests[ApprovalInputKey]
				if !ok || req.RequestID != "req_1" || req.Type != InputRequestTypeElicitation {
					t.Fatalf("inputRequests = %+v", r.InputRequests)
				}
				if req.Message == "" || req.Message != approvalPromptMessage("dangerous_tool") {
					t.Fatalf("message = %q", req.Message)
				}
			},
		},
		{
			name: "answered approval stays input_required until resumed",
			state: taskState{Status: "paused", PendingApproval: &taskPendingApproval{
				Tool: "dangerous_tool", StepID: "gate", RequestID: "req_1", Resolved: "approved",
			}},
			check: func(t *testing.T, r GetTaskResult) {
				if r.Status != TaskStatusInputRequired {
					t.Fatalf("answered mapping = %+v", r)
				}
				if r.StatusMessage == "" {
					t.Fatal("answered approval should explain the recorded response")
				}
			},
		},
		{
			name:  "failed carries an error object",
			state: taskState{Status: "failed", Error: "boom"},
			check: func(t *testing.T, r GetTaskResult) {
				if r.Status != TaskStatusFailed || r.Error == nil ||
					r.Error.Code != ErrCodeTaskFailed || r.Error.Message != "boom" {
					t.Fatalf("failed mapping = %+v", r)
				}
			},
		},
		{
			name:  "failed without message still has an error object",
			state: taskState{Status: "failed"},
			check: func(t *testing.T, r GetTaskResult) {
				if r.Error == nil || r.Error.Message != "campaign failed" {
					t.Fatalf("failed mapping = %+v", r)
				}
			},
		},
		{
			name:  "cancelled",
			state: taskState{Status: "cancelled"},
			check: func(t *testing.T, r GetTaskResult) {
				if r.Status != TaskStatusCancelled {
					t.Fatalf("cancelled mapping = %+v", r)
				}
			},
		},
		{
			name:  "completed serves the persisted final result",
			state: taskState{Status: "completed", FinalResult: json.RawMessage(`{"workflow_id":"x","success":true}`)},
			check: func(t *testing.T, r GetTaskResult) {
				if r.Status != TaskStatusCompleted || string(r.Result) != `{"workflow_id":"x","success":true}` {
					t.Fatalf("completed mapping = %+v", r)
				}
			},
		},
		{
			name:  "completed without FinalResult synthesizes one",
			state: taskState{Status: "completed", WorkflowID: "x", Steps: []json.RawMessage{json.RawMessage(`{"tool":"a"}`)}},
			check: func(t *testing.T, r GetTaskResult) {
				var synthesized struct {
					Status  string            `json:"status"`
					Success bool              `json:"success"`
					Steps   []json.RawMessage `json:"steps"`
				}
				if err := json.Unmarshal(r.Result, &synthesized); err != nil {
					t.Fatal(err)
				}
				if synthesized.Status != "completed" || !synthesized.Success || len(synthesized.Steps) != 1 {
					t.Fatalf("synthesized result = %s", r.Result)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, taskResultFromState(&tc.state))
		})
	}
}

func TestIsAffirmativeApproval(t *testing.T) {
	affirmative := []string{
		`{"approved":true}`,
		`{"approved":true,"requestId":"req_1"}`,
		`{"approved":true,"comment":"go"}`,
	}
	denial := []string{
		``,
		`{"approved":false}`,
		`{"approved":"true"}`,
		`{}`,
		`"yes"`,
		`null`,
		`{"other":true}`,
	}
	for _, resp := range affirmative {
		if !IsAffirmativeApproval(json.RawMessage(resp)) {
			t.Errorf("%s should be affirmative", resp)
		}
	}
	for _, resp := range denial {
		if IsAffirmativeApproval(json.RawMessage(resp)) {
			t.Errorf("%s must not be affirmative", resp)
		}
	}
}
