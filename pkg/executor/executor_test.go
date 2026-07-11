package executor

import (
	"bytes"
	"context"
	"testing"
)

func TestValidateArgs_Clean(t *testing.T) {
	cases := [][]string{
		{"--version"},
		{"-sV", "-p", "80,443", "192.168.1.1"},
		{"--output", "/tmp/results.txt"},
		{"hello world"},
		{},
	}
	for _, args := range cases {
		if err := validateArgs(args); err != nil {
			t.Errorf("validateArgs(%v) = %v, want nil", args, err)
		}
	}
}

func TestValidateArgs_Malicious(t *testing.T) {
	cases := []struct {
		args []string
		char string
	}{
		{[]string{"; rm -rf /"}, ";"},
		{[]string{"foo | bar"}, "|"},
		{[]string{"$(whoami)"}, "$"},
		{[]string{"a && b"}, "&"},
		{[]string{"`id`"}, "`"},
		{[]string{"foo\nbar"}, "\n"},
		{[]string{"a > /etc/passwd"}, ">"},
		{[]string{"a < /dev/null"}, "<"},
		{[]string{"!(x)"}, "!"},
		{[]string{"a{b,c}"}, "{"},
	}
	for _, tc := range cases {
		err := validateArgs(tc.args)
		if err == nil {
			t.Errorf("validateArgs(%v) = nil, want error for %q", tc.args, tc.char)
		}
	}
}

func TestLimitWriter_UnderLimit(t *testing.T) {
	var buf bytes.Buffer
	w := &limitWriter{buf: &buf, limit: 100}

	data := []byte("hello")
	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 5 {
		t.Errorf("Write returned %d, want 5", n)
	}
	if buf.String() != "hello" {
		t.Errorf("buf = %q, want %q", buf.String(), "hello")
	}
}

func TestLimitWriter_AtLimit(t *testing.T) {
	var buf bytes.Buffer
	w := &limitWriter{buf: &buf, limit: 5}

	n, err := w.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 5 {
		t.Errorf("Write returned %d, want 5", n)
	}
	if buf.Len() != 5 {
		t.Errorf("buf len = %d, want 5", buf.Len())
	}
}

func TestLimitWriter_OverLimit(t *testing.T) {
	var buf bytes.Buffer
	w := &limitWriter{buf: &buf, limit: 5}

	n, err := w.Write([]byte("hello world"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 5 {
		t.Errorf("Write returns bytes written to buf: got %d, want 5", n)
	}
	if buf.String() != "hello" {
		t.Errorf("buf = %q, want %q", buf.String(), "hello")
	}

	n, err = w.Write([]byte("more"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 4 {
		t.Errorf("Write returned %d, want 4", n)
	}
	if buf.String() != "hello" {
		t.Errorf("buf should not grow past limit: %q", buf.String())
	}
}

func TestRun_AllowedBinary(t *testing.T) {
	e := New(Config{
		Timeout:         5,
		AllowedBinaries: map[string]string{"echo": "/bin/echo"},
		MaxOutputBytes:  1024,
	})

	result, err := e.Run(context.Background(), "echo", "hello")
	if err != nil {
		t.Fatalf("Run(echo hello) error: %v", err)
	}
	got := string(bytes.TrimSpace(result.Stdout))
	if got != "hello" {
		t.Errorf("stdout = %q, want %q", got, "hello")
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}
}

func TestRun_DisallowedBinary(t *testing.T) {
	e := New(Config{
		Timeout:         5,
		AllowedBinaries: map[string]string{"echo": "/bin/echo"},
		MaxOutputBytes:  1024,
	})

	_, err := e.Run(context.Background(), "rm", "-rf", "/")
	if err == nil {
		t.Fatal("Run with disallowed binary should error")
	}
}

func TestRun_MaliciousArgs(t *testing.T) {
	e := New(Config{
		Timeout:         5,
		AllowedBinaries: map[string]string{"echo": "/bin/echo"},
		MaxOutputBytes:  1024,
	})

	_, err := e.Run(context.Background(), "echo", "$(whoami)")
	if err == nil {
		t.Fatal("Run with shell metachar should error")
	}
}

func TestRun_Timeout(t *testing.T) {
	e := New(Config{
		Timeout:         1,
		AllowedBinaries: map[string]string{"sleep": "/bin/sleep"},
		MaxOutputBytes:  1024,
	})

	_, err := e.Run(context.Background(), "sleep", "10")
	if err == nil {
		t.Fatal("Run should error on timeout")
	}
}

func TestRun_NonZeroExit(t *testing.T) {
	e := New(Config{
		Timeout:         5,
		AllowedBinaries: map[string]string{"false": "/bin/false"},
		MaxOutputBytes:  1024,
	})

	result, err := e.Run(context.Background(), "false")
	if err == nil {
		t.Fatal("Run with /bin/false should error")
	}
	if result == nil {
		t.Fatal("result should not be nil even on error")
	}
	if result.ExitCode == 0 {
		t.Error("exit code should be non-zero")
	}
}
