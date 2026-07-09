package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// --- ScoutAWSTool ---

type ScoutAWSInput struct {
	Profile  string   `json:"profile,omitempty"`
	Regions  []string `json:"regions,omitempty"`
	Services []string `json:"services,omitempty"`
}

type ScoutAWSTool struct {
	exec executor.Executor
}

func NewScoutAWS(exec executor.Executor) *ScoutAWSTool {
	return &ScoutAWSTool{exec: exec}
}

func (t *ScoutAWSTool) Name() string { return "cloud_scout_aws" }

func (t *ScoutAWSTool) Description() string {
	return "AWS cloud enumeration and security auditing with ScoutSuite. Scans AWS services for misconfigurations, overly permissive policies, and security risks."
}

func (t *ScoutAWSTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"profile": {
				"type": "string",
				"description": "AWS CLI profile name"
			},
			"regions": {
				"type": "array",
				"items": {"type": "string"},
				"description": "AWS regions to scan"
			},
			"services": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Specific AWS services to audit (e.g. iam, s3, ec2)"
			}
		}
	}`)
}

func (t *ScoutAWSTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ScoutAWSInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Profile != "" {
		if err := validateInput(input.Profile); err != nil {
			return errorResult("profile: " + err.Error()), nil
		}
	}
	for _, r := range input.Regions {
		if err := validateInput(r); err != nil {
			return errorResult("regions: " + err.Error()), nil
		}
	}
	for _, s := range input.Services {
		if err := validateInput(s); err != nil {
			return errorResult("services: " + err.Error()), nil
		}
	}

	args := []string{"aws"}
	if input.Profile != "" {
		args = append(args, "--profile", input.Profile)
	}
	if len(input.Regions) > 0 {
		args = append(args, "--regions", strings.Join(input.Regions, ","))
	}
	if len(input.Services) > 0 {
		args = append(args, "--services", strings.Join(input.Services, ","))
	}

	result, err := t.exec.Run(ctx, "scout", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("scout aws failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## ScoutSuite AWS Audit\n\n")
	if input.Profile != "" {
		fmt.Fprintf(&sb, "**Profile**: %s\n", input.Profile)
	}
	if len(input.Regions) > 0 {
		fmt.Fprintf(&sb, "**Regions**: %s\n", strings.Join(input.Regions, ", "))
	}
	if len(input.Services) > 0 {
		fmt.Fprintf(&sb, "**Services**: %s\n", strings.Join(input.Services, ", "))
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("No output.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- ScoutAzureTool ---

type ScoutAzureInput struct {
	TenantID       string   `json:"tenant_id,omitempty"`
	SubscriptionID string   `json:"subscription_id,omitempty"`
	Services       []string `json:"services,omitempty"`
}

type ScoutAzureTool struct {
	exec executor.Executor
}

func NewScoutAzure(exec executor.Executor) *ScoutAzureTool {
	return &ScoutAzureTool{exec: exec}
}

func (t *ScoutAzureTool) Name() string { return "cloud_scout_azure" }

func (t *ScoutAzureTool) Description() string {
	return "Azure cloud enumeration and security auditing with ScoutSuite. Scans Azure subscriptions for misconfigurations and security risks."
}

func (t *ScoutAzureTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"tenant_id": {
				"type": "string",
				"description": "Azure tenant ID"
			},
			"subscription_id": {
				"type": "string",
				"description": "Azure subscription ID"
			},
			"services": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Specific Azure services to audit"
			}
		}
	}`)
}

func (t *ScoutAzureTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ScoutAzureInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.TenantID != "" {
		if err := validateInput(input.TenantID); err != nil {
			return errorResult("tenant_id: " + err.Error()), nil
		}
	}
	if input.SubscriptionID != "" {
		if err := validateInput(input.SubscriptionID); err != nil {
			return errorResult("subscription_id: " + err.Error()), nil
		}
	}
	for _, s := range input.Services {
		if err := validateInput(s); err != nil {
			return errorResult("services: " + err.Error()), nil
		}
	}

	args := []string{"azure"}
	if input.TenantID != "" {
		args = append(args, "--tenant", input.TenantID)
	}
	if input.SubscriptionID != "" {
		args = append(args, "--subscription-id", input.SubscriptionID)
	}
	if len(input.Services) > 0 {
		args = append(args, "--services", strings.Join(input.Services, ","))
	}

	result, err := t.exec.Run(ctx, "scout", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("scout azure failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## ScoutSuite Azure Audit\n\n")
	if input.TenantID != "" {
		fmt.Fprintf(&sb, "**Tenant**: %s\n", input.TenantID)
	}
	if input.SubscriptionID != "" {
		fmt.Fprintf(&sb, "**Subscription**: %s\n", input.SubscriptionID)
	}
	if len(input.Services) > 0 {
		fmt.Fprintf(&sb, "**Services**: %s\n", strings.Join(input.Services, ", "))
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("No output.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- ProwlerTool ---

type ProwlerInput struct {
	Provider string   `json:"provider"`
	Profile  string   `json:"profile,omitempty"`
	Region   string   `json:"region,omitempty"`
	Checks   []string `json:"checks,omitempty"`
	Severity string   `json:"severity,omitempty"`
}

type ProwlerTool struct {
	exec executor.Executor
}

func NewProwler(exec executor.Executor) *ProwlerTool {
	return &ProwlerTool{exec: exec}
}

func (t *ProwlerTool) Name() string { return "cloud_prowler" }

func (t *ProwlerTool) Description() string {
	return "Cloud security assessment with Prowler. Performs CIS benchmark checks and security best practice audits across AWS, Azure, and GCP."
}

func (t *ProwlerTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"provider": {
				"type": "string",
				"enum": ["aws", "azure", "gcp"],
				"description": "Cloud provider to assess"
			},
			"profile": {
				"type": "string",
				"description": "Cloud provider profile name"
			},
			"region": {
				"type": "string",
				"description": "Region to assess"
			},
			"checks": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Specific check IDs to run"
			},
			"severity": {
				"type": "string",
				"enum": ["critical", "high", "medium", "low", "informational"],
				"description": "Minimum severity level to report"
			}
		},
		"required": ["provider"]
	}`)
}

func (t *ProwlerTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ProwlerInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Provider == "" {
		return errorResult("provider is required"), nil
	}
	validProviders := map[string]bool{"aws": true, "azure": true, "gcp": true}
	if !validProviders[input.Provider] {
		return errorResult("provider must be one of: aws, azure, gcp"), nil
	}
	if input.Profile != "" {
		if err := validateInput(input.Profile); err != nil {
			return errorResult("profile: " + err.Error()), nil
		}
	}
	if input.Region != "" {
		if err := validateInput(input.Region); err != nil {
			return errorResult("region: " + err.Error()), nil
		}
	}
	for _, c := range input.Checks {
		if err := validateInput(c); err != nil {
			return errorResult("checks: " + err.Error()), nil
		}
	}
	if input.Severity != "" {
		validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "informational": true}
		if !validSeverities[input.Severity] {
			return errorResult("severity must be one of: critical, high, medium, low, informational"), nil
		}
	}

	args := []string{input.Provider}
	if input.Profile != "" {
		args = append(args, "-p", input.Profile)
	}
	if input.Region != "" {
		args = append(args, "-r", input.Region)
	}
	if len(input.Checks) > 0 {
		args = append(args, "-c", strings.Join(input.Checks, ","))
	}
	if input.Severity != "" {
		args = append(args, "--severity", input.Severity)
	}

	result, err := t.exec.Run(ctx, "prowler", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("prowler failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Prowler Security Assessment\n\n")
	fmt.Fprintf(&sb, "**Provider**: %s\n", input.Provider)
	if input.Profile != "" {
		fmt.Fprintf(&sb, "**Profile**: %s\n", input.Profile)
	}
	if input.Region != "" {
		fmt.Fprintf(&sb, "**Region**: %s\n", input.Region)
	}
	if input.Severity != "" {
		fmt.Fprintf(&sb, "**Severity**: %s\n", input.Severity)
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("No findings.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- PacuEnumTool ---

type PacuEnumInput struct {
	Module  string   `json:"module"`
	Profile string   `json:"profile,omitempty"`
	Regions []string `json:"regions,omitempty"`
}

type PacuEnumTool struct {
	exec executor.Executor
}

func NewPacuEnum(exec executor.Executor) *PacuEnumTool {
	return &PacuEnumTool{exec: exec}
}

func (t *PacuEnumTool) Name() string { return "cloud_pacu_enum" }

func (t *PacuEnumTool) Description() string {
	return "AWS exploitation framework using Pacu. Enumerates and exploits AWS misconfigurations through modular attack modules for IAM, EC2, S3, Lambda, and more."
}

func (t *PacuEnumTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"module": {
				"type": "string",
				"description": "Pacu module to run (e.g. iam__enum_permissions, ec2__enum)"
			},
			"profile": {
				"type": "string",
				"description": "AWS CLI profile name"
			},
			"regions": {
				"type": "array",
				"items": {"type": "string"},
				"description": "AWS regions to target"
			}
		},
		"required": ["module"]
	}`)
}

func (t *PacuEnumTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PacuEnumInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Module == "" {
		return errorResult("module is required"), nil
	}
	if err := validateInput(input.Module); err != nil {
		return errorResult("module: " + err.Error()), nil
	}
	if input.Profile != "" {
		if err := validateInput(input.Profile); err != nil {
			return errorResult("profile: " + err.Error()), nil
		}
	}
	for _, r := range input.Regions {
		if err := validateInput(r); err != nil {
			return errorResult("regions: " + err.Error()), nil
		}
	}

	args := []string{"--module", input.Module}
	if input.Profile != "" {
		args = append(args, "--profile", input.Profile)
	}
	if len(input.Regions) > 0 {
		args = append(args, "--regions", strings.Join(input.Regions, ","))
	}

	result, err := t.exec.Run(ctx, "pacu", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("pacu failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Pacu AWS Exploitation\n\n")
	fmt.Fprintf(&sb, "**Module**: %s\n", input.Module)
	if input.Profile != "" {
		fmt.Fprintf(&sb, "**Profile**: %s\n", input.Profile)
	}
	if len(input.Regions) > 0 {
		fmt.Fprintf(&sb, "**Regions**: %s\n", strings.Join(input.Regions, ", "))
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("No output.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- RoadtoolsAuthTool ---

type RoadtoolsAuthInput struct {
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	Tenant     string `json:"tenant"`
	ClientID   string `json:"client_id,omitempty"`
	AuthMethod string `json:"auth_method,omitempty"`
}

type RoadtoolsAuthTool struct {
	exec executor.Executor
}

func NewRoadtoolsAuth(exec executor.Executor) *RoadtoolsAuthTool {
	return &RoadtoolsAuthTool{exec: exec}
}

func (t *RoadtoolsAuthTool) Name() string { return "cloud_roadtools_auth" }

func (t *RoadtoolsAuthTool) Description() string {
	return "Azure AD authentication via ROADtools. Authenticates to Azure AD using password, device code, or certificate methods for subsequent enumeration."
}

func (t *RoadtoolsAuthTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"username": {
				"type": "string",
				"description": "Azure AD username (UPN)"
			},
			"password": {
				"type": "string",
				"description": "Password for authentication"
			},
			"tenant": {
				"type": "string",
				"description": "Azure AD tenant ID or domain"
			},
			"client_id": {
				"type": "string",
				"description": "Application (client) ID"
			},
			"auth_method": {
				"type": "string",
				"enum": ["password", "device_code", "certificate"],
				"description": "Authentication method to use"
			}
		},
		"required": ["username", "tenant"]
	}`)
}

func (t *RoadtoolsAuthTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input RoadtoolsAuthInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Username == "" {
		return errorResult("username is required"), nil
	}
	if err := validateInput(input.Username); err != nil {
		return errorResult("username: " + err.Error()), nil
	}
	if input.Tenant == "" {
		return errorResult("tenant is required"), nil
	}
	if err := validateInput(input.Tenant); err != nil {
		return errorResult("tenant: " + err.Error()), nil
	}
	if input.Password != "" {
		if err := validateInput(input.Password); err != nil {
			return errorResult("password: " + err.Error()), nil
		}
	}
	if input.ClientID != "" {
		if err := validateInput(input.ClientID); err != nil {
			return errorResult("client_id: " + err.Error()), nil
		}
	}
	if input.AuthMethod != "" {
		validMethods := map[string]bool{"password": true, "device_code": true, "certificate": true}
		if !validMethods[input.AuthMethod] {
			return errorResult("auth_method must be one of: password, device_code, certificate"), nil
		}
	}

	args := []string{"auth", "-u", input.Username}
	if input.Password != "" {
		args = append(args, "-p", input.Password)
	}
	args = append(args, "-t", input.Tenant)
	if input.ClientID != "" {
		args = append(args, "-c", input.ClientID)
	}
	if input.AuthMethod != "" {
		args = append(args, "--method", input.AuthMethod)
	}

	result, err := t.exec.Run(ctx, "roadtx", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("roadtools auth failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## ROADtools Authentication\n\n")
	fmt.Fprintf(&sb, "**Username**: %s\n", input.Username)
	fmt.Fprintf(&sb, "**Tenant**: %s\n", input.Tenant)
	if input.AuthMethod != "" {
		fmt.Fprintf(&sb, "**Method**: %s\n", input.AuthMethod)
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("Authentication completed.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- RoadtoolsDumpTool ---

type RoadtoolsDumpInput struct {
	Tenant    string `json:"tenant"`
	TokenFile string `json:"token_file,omitempty"`
}

type RoadtoolsDumpTool struct {
	exec executor.Executor
}

func NewRoadtoolsDump(exec executor.Executor) *RoadtoolsDumpTool {
	return &RoadtoolsDumpTool{exec: exec}
}

func (t *RoadtoolsDumpTool) Name() string { return "cloud_roadtools_dump" }

func (t *RoadtoolsDumpTool) Description() string {
	return "Dump Azure AD directory data via ROADtools. Gathers users, groups, applications, service principals, and other directory objects."
}

func (t *RoadtoolsDumpTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"tenant": {
				"type": "string",
				"description": "Azure AD tenant ID or domain"
			},
			"token_file": {
				"type": "string",
				"description": "Path to token file from previous authentication"
			}
		},
		"required": ["tenant"]
	}`)
}

func (t *RoadtoolsDumpTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input RoadtoolsDumpInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Tenant == "" {
		return errorResult("tenant is required"), nil
	}
	if err := validateInput(input.Tenant); err != nil {
		return errorResult("tenant: " + err.Error()), nil
	}
	if input.TokenFile != "" {
		if err := validateInput(input.TokenFile); err != nil {
			return errorResult("token_file: " + err.Error()), nil
		}
	}

	args := []string{"gather", "-t", input.Tenant}
	if input.TokenFile != "" {
		args = append(args, "--token", input.TokenFile)
	}

	result, err := t.exec.Run(ctx, "roadtx", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("roadtools dump failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## ROADtools Directory Dump\n\n")
	fmt.Fprintf(&sb, "**Tenant**: %s\n", input.Tenant)
	if input.TokenFile != "" {
		fmt.Fprintf(&sb, "**Token File**: %s\n", input.TokenFile)
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("Dump completed.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- EnumS3Tool ---

type EnumS3Input struct {
	Keyword string `json:"keyword"`
	Region  string `json:"region,omitempty"`
	Profile string `json:"profile,omitempty"`
}

type EnumS3Tool struct {
	exec executor.Executor
}

func NewEnumS3(exec executor.Executor) *EnumS3Tool {
	return &EnumS3Tool{exec: exec}
}

func (t *EnumS3Tool) Name() string { return "cloud_enum_s3" }

func (t *EnumS3Tool) Description() string {
	return "Enumerate S3 buckets using keyword-based guessing. Discovers publicly accessible or misconfigured S3 buckets by generating permutations of target keywords."
}

func (t *EnumS3Tool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"keyword": {
				"type": "string",
				"description": "Keyword for bucket name guessing (e.g. company name)"
			},
			"region": {
				"type": "string",
				"description": "AWS region to check"
			},
			"profile": {
				"type": "string",
				"description": "AWS CLI profile name"
			}
		},
		"required": ["keyword"]
	}`)
}

func (t *EnumS3Tool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input EnumS3Input
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Keyword == "" {
		return errorResult("keyword is required"), nil
	}
	if err := validateInput(input.Keyword); err != nil {
		return errorResult("keyword: " + err.Error()), nil
	}
	if input.Region != "" {
		if err := validateInput(input.Region); err != nil {
			return errorResult("region: " + err.Error()), nil
		}
	}
	if input.Profile != "" {
		if err := validateInput(input.Profile); err != nil {
			return errorResult("profile: " + err.Error()), nil
		}
	}

	args := []string{"s3", "ls"}
	if input.Profile != "" {
		args = append(args, "--profile", input.Profile)
	}
	if input.Region != "" {
		args = append(args, "--region", input.Region)
	}

	result, err := t.exec.Run(ctx, "aws", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("s3 enumeration failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## S3 Bucket Enumeration\n\n")
	fmt.Fprintf(&sb, "**Keyword**: %s\n", input.Keyword)
	if input.Region != "" {
		fmt.Fprintf(&sb, "**Region**: %s\n", input.Region)
	}
	sb.WriteString("\n")

	// Filter output for lines matching the keyword
	if output == "" {
		sb.WriteString("No buckets found.\n")
	} else {
		lines := strings.Split(output, "\n")
		var matches []string
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), strings.ToLower(input.Keyword)) {
				matches = append(matches, line)
			}
		}
		if len(matches) > 0 {
			fmt.Fprintf(&sb, "**Matching Buckets** (%d found):\n```\n", len(matches))
			sb.WriteString(strings.Join(matches, "\n"))
			sb.WriteString("\n```\n")
		} else {
			sb.WriteString("No buckets matching keyword found.\n\n**All Buckets**:\n```\n")
			sb.WriteString(output)
			sb.WriteString("\n```\n")
		}
	}

	return textResult(sb.String()), nil
}

// --- EnumBlobsTool ---

type EnumBlobsInput struct {
	AccountName string `json:"account_name"`
	Container   string `json:"container,omitempty"`
}

type EnumBlobsTool struct {
	exec executor.Executor
}

func NewEnumBlobs(exec executor.Executor) *EnumBlobsTool {
	return &EnumBlobsTool{exec: exec}
}

func (t *EnumBlobsTool) Name() string { return "cloud_enum_blobs" }

func (t *EnumBlobsTool) Description() string {
	return "Enumerate Azure Blob Storage containers and objects. Discovers publicly accessible or misconfigured blob storage accounts."
}

func (t *EnumBlobsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"account_name": {
				"type": "string",
				"description": "Azure storage account name"
			},
			"container": {
				"type": "string",
				"description": "Specific container name to enumerate"
			}
		},
		"required": ["account_name"]
	}`)
}

func (t *EnumBlobsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input EnumBlobsInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.AccountName == "" {
		return errorResult("account_name is required"), nil
	}
	if err := validateInput(input.AccountName); err != nil {
		return errorResult("account_name: " + err.Error()), nil
	}
	if input.Container != "" {
		if err := validateInput(input.Container); err != nil {
			return errorResult("container: " + err.Error()), nil
		}
	}

	args := []string{"storage", "blob", "list", "--account-name", input.AccountName}
	if input.Container != "" {
		args = append(args, "--container-name", input.Container)
	}

	result, err := t.exec.Run(ctx, "scout", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("blob enumeration failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Azure Blob Storage Enumeration\n\n")
	fmt.Fprintf(&sb, "**Account**: %s\n", input.AccountName)
	if input.Container != "" {
		fmt.Fprintf(&sb, "**Container**: %s\n", input.Container)
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("No blobs found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}
