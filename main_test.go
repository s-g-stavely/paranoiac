package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestScanTestdata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Build the binary.
	binPath := filepath.Join(t.TempDir(), "paranoiac")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir, _ = os.Getwd()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	outputPath := filepath.Join(t.TempDir(), "output.json")
	testdataPath, _ := filepath.Abs("testdata")

	// First run: scan testdata and check minimum issue count.
	run1 := exec.Command(binPath,
		"-repo", testdataPath,
		"-output", outputPath,
		"-languages", "go",
		"-concurrency", "2",
	)
	if out, err := run1.CombinedOutput(); err != nil {
		t.Fatalf("first run failed: %v\n%s", err, out)
	}

	output1 := readOutput(t, outputPath)
	minExpected := 4
	if len(output1.Vulnerabilities) < minExpected {
		t.Errorf("first run: got %d vulnerabilities, want at least %d", len(output1.Vulnerabilities), minExpected)
	}
	t.Logf("first run found %d vulnerabilities across %d scanned files", len(output1.Vulnerabilities), len(output1.ScannedFiles))

	// Second run: same input, should produce no new results (dedup + resume).
	run2 := exec.Command(binPath,
		"-repo", testdataPath,
		"-output", outputPath,
		"-languages", "go",
		"-concurrency", "2",
	)
	if out, err := run2.CombinedOutput(); err != nil {
		t.Fatalf("second run failed: %v\n%s", err, out)
	}

	output2 := readOutput(t, outputPath)
	if len(output2.Vulnerabilities) != len(output1.Vulnerabilities) {
		t.Errorf("dedup check: vulnerability count changed from %d to %d on second run",
			len(output1.Vulnerabilities), len(output2.Vulnerabilities))
	}
	t.Logf("second run: vulnerability count stayed at %d (dedup working)", len(output2.Vulnerabilities))
}

func readOutput(t *testing.T, path string) Output {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	var out Output
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("parsing output file: %v", err)
	}
	return out
}
