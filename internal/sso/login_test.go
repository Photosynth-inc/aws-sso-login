package sso

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintAuthorizationInstructions_Headless(t *testing.T) {
	var out bytes.Buffer

	printAuthorizationInstructions(&out, "https://example.awsapps.com/verify", "ABCD-EFGH", false)

	got := out.String()
	for _, want := range []string{
		"Headless mode: browser auto-open disabled.",
		"https://example.awsapps.com/verify",
		"Confirmation code: ABCD-EFGH",
		"Authorize the device in any browser, then return here.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output %q does not contain %q", got, want)
		}
	}
}

func TestNormalizeLoginOptions_Defaults(t *testing.T) {
	opts := normalizeLoginOptions(LoginOptions{OpenBrowser: true})
	if opts.Output == nil {
		t.Fatal("Output was nil")
	}
	if opts.BrowserOpener == nil {
		t.Fatal("BrowserOpener was nil")
	}
}
