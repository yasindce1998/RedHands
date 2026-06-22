package nmap

import "testing"

func TestValidateTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"valid IPv4", "192.168.1.1", false},
		{"valid IPv6", "::1", false},
		{"valid CIDR", "10.0.0.0/24", false},
		{"valid hostname", "example.com", false},
		{"valid subdomain", "scan.example.com", false},
		{"empty", "", true},
		{"shell injection semicolon", "127.0.0.1; rm -rf /", true},
		{"shell injection pipe", "127.0.0.1 | cat /etc/passwd", true},
		{"shell injection backtick", "127.0.0.1`whoami`", true},
		{"shell injection dollar", "$(whoami).evil.com", true},
		{"shell injection ampersand", "127.0.0.1 && whoami", true},
		{"too long", string(make([]byte, 300)), true},
		{"newline injection", "127.0.0.1\n-oN /tmp/evil", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTarget(%q) error = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePorts(t *testing.T) {
	tests := []struct {
		name    string
		ports   string
		wantErr bool
	}{
		{"empty", "", false},
		{"single port", "80", false},
		{"port range", "1-1024", false},
		{"multiple ports", "80,443,8080", false},
		{"TCP prefix", "T:80,443", false},
		{"UDP prefix", "U:53", false},
		{"mixed", "T:80,U:53,443", false},
		{"invalid chars", "80;whoami", true},
		{"too long", string(make([]byte, 2000)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePorts(tt.ports)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePorts(%q) error = %v, wantErr %v", tt.ports, err, tt.wantErr)
			}
		})
	}
}
