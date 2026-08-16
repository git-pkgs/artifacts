package artifacts

import (
	"os/exec"
	"testing"
)

func TestStandaloneConsumerAcceptsSHA256(t *testing.T) {
	command := exec.Command("go", "run", "./testdata/sha256")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("standalone consumer failed: %v\n%s", err, output)
	}
}
