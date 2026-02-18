package sso

import "testing"

func TestRoleSuffix(t *testing.T) {
	tests := []struct {
		role string
		want string
	}{
		{"ViewOnlyAccess", "-view-only"},
		{"PowerUserAccess", "-power-user"},
		{"BillingAccess", "-billing"},
		{"CustomPermission", "-custom"},
		{"SomeRole", "-some-role"},
	}
	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			got := roleSuffix(tt.role)
			if got != tt.want {
				t.Errorf("roleSuffix(%q) = %q, want %q", tt.role, got, tt.want)
			}
		})
	}
}

func TestCamelToKebab(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ViewOnly", "view-only"},
		{"PowerUser", "power-user"},
		{"ABC", "abc"},
		{"ABCDef", "abc-def"},
		{"APIGateway", "api-gateway"},
		{"MyAWSRole", "my-aws-role"},
		{"S3Access", "s3-access"},
		{"EC2ReadOnly", "ec2-read-only"},
		{"camelCase", "camel-case"},
		{"already-kebab", "already-kebab"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := camelToKebab(tt.input)
			if got != tt.want {
				t.Errorf("camelToKebab(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
