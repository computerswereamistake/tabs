package web

import (
	"os"
	"os/exec"
	"testing"
)

// TestJS runs the browser-script tests in testdata/ with Node's built-in
// test runner. Locally it skips when Node isn't installed; in CI (CI is set
// by GitHub Actions) a missing Node is a failure, so the suite can't
// silently stop running.
func TestJS(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the JS tests")
		}
		t.Skip("node not installed; skipping JS tests")
	}
	cmd := exec.Command(node, "--test", "testdata/")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("JS tests failed: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}
