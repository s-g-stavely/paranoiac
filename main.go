package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var languageExtensions = map[string][]string{
	"go":         {".go"},
	"java":       {".java"},
	"python":     {".py"},
	"javascript": {".js", ".jsx"},
	"typescript": {".ts", ".tsx"},
}

type Vulnerability struct {
	ShortDescription    string   `json:"short_description"`
	DetailedDescription string   `json:"detailed_description"`
	Locations           []string `json:"locations"`
	FoundFromFile       string   `json:"found_from_file"`
}

type Output struct {
	ScannedFiles    []string        `json:"scanned_files"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// ClaudeResponse is what we ask Claude to return as JSON.
type ClaudeResponse struct {
	Vulnerabilities []struct {
		ShortDescription    string `json:"short_description"`
		DetailedDescription string `json:"detailed_description"`
		Locations           []struct {
			File string `json:"file"`
			Line int    `json:"line,omitempty"`
		} `json:"locations"`
	} `json:"vulnerabilities"`
}

func main() {
	outputPath := flag.String("output", "paranoiac-output.json", "path to the JSON output file")
	languages := flag.String("languages", "go", "comma-separated list of languages to scan (e.g. go,java,python)")
	concurrency := flag.Int("concurrency", 5, "number of parallel Claude instances")
	repoPath := flag.String("repo", ".", "path to the repository to scan")
	maxTurns := flag.Int("max-turns", 50, "max conversation turns per Claude instance")
	timeout := flag.Duration("timeout", 15*time.Minute, "timeout per Claude instance")
	mode := flag.String("mode", "security", "what to scan for: security, bugs, or custom")
	customPrompt := flag.String("custom-prompt", "", "description of what issues to look for (requires -mode=custom)")
	flag.Parse()

	scanPrompt := buildScanPrompt(*mode, *customPrompt)
	if scanPrompt == "" {
		log.Fatalf("-mode must be one of: security, bugs, custom")
	}

	absRepo, err := filepath.Abs(*repoPath)
	if err != nil {
		log.Fatalf("resolving repo path: %v", err)
	}

	// Build set of extensions to scan.
	exts := map[string]bool{}
	for lang := range strings.SplitSeq(*languages, ",") {
		lang = strings.TrimSpace(strings.ToLower(lang))
		if e, ok := languageExtensions[lang]; ok {
			for _, ext := range e {
				exts[ext] = true
			}
		} else {
			log.Fatalf("unsupported language: %q (supported: %s)", lang, supportedLanguages())
		}
	}

	// Discover files.
	files, err := discoverFiles(absRepo, exts)
	if err != nil {
		log.Fatalf("discovering files: %v", err)
	}
	log.Printf("found %d source files to scan", len(files))

	// Load existing output (for resume support).
	output := loadOutput(*outputPath)
	alreadyScanned := map[string]bool{}
	for _, f := range output.ScannedFiles {
		alreadyScanned[f] = true
	}

	// Filter out already-scanned files.
	var toScan []string
	for _, f := range files {
		if !alreadyScanned[f] {
			toScan = append(toScan, f)
		}
	}
	log.Printf("%d files already scanned, %d remaining", len(files)-len(toScan), len(toScan))

	if len(toScan) == 0 {
		log.Println("nothing to scan")
		return
	}

	// Scan files with bounded concurrency.
	var mu sync.Mutex
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup

	for _, file := range toScan {
		wg.Add(1)
		sem <- struct{}{}
		go func(f string) {
			defer wg.Done()
			defer func() { <-sem }()

			log.Printf("scanning %s", f)
			vulns, err := scanFile(absRepo, f, scanPrompt, *maxTurns, *timeout)
			if err != nil {
				log.Printf("error scanning %s: %v", f, err)
				// Still mark as scanned so we don't retry on resume.
			}

			if len(vulns) > 0 {
				// Ask Claude to dedup against the existing output file.
				absOutput, _ := filepath.Abs(*outputPath)
				newVulns, err := dedup(absOutput, vulns, *timeout)
				if err != nil {
					log.Printf("  dedup error, keeping all: %v", err)
					newVulns = vulns
				}

				mu.Lock()
				output = loadOutput(*outputPath)
				output.ScannedFiles = append(output.ScannedFiles, f)
				for _, v := range newVulns {
					output.Vulnerabilities = append(output.Vulnerabilities, v)
					log.Printf("  found: %s", v.ShortDescription)
				}
				if err := saveOutput(*outputPath, output); err != nil {
					log.Printf("error saving output: %v", err)
				}
				mu.Unlock()
			} else {
				mu.Lock()
				output = loadOutput(*outputPath)
				output.ScannedFiles = append(output.ScannedFiles, f)
				if err := saveOutput(*outputPath, output); err != nil {
					log.Printf("error saving output: %v", err)
				}
				mu.Unlock()
			}
		}(file)
	}

	wg.Wait()
	log.Printf("done. %d vulnerabilities found across %d files", len(loadOutput(*outputPath).Vulnerabilities), len(files))
}

func discoverFiles(repoPath string, exts map[string]bool) ([]string, error) {
	// Try git ls-files first. Use --full-name and then make paths relative to repoPath.
	cmd := exec.Command("git", "ls-files", "--full-name")
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err == nil {
		raw := strings.TrimSpace(string(out))
		if raw != "" {
			// Determine the git repo root so we can compute relative paths.
			rootCmd := exec.Command("git", "rev-parse", "--show-toplevel")
			rootCmd.Dir = repoPath
			rootOut, rootErr := rootCmd.Output()
			if rootErr == nil {
				gitRoot := strings.TrimSpace(string(rootOut))
				var relFiles []string
				for f := range strings.SplitSeq(raw, "\n") {
					absFile := filepath.Join(gitRoot, f)
					rel, err := filepath.Rel(repoPath, absFile)
					if err != nil {
						continue
					}
					// Skip files outside repoPath (they'd start with "..").
					if strings.HasPrefix(rel, "..") {
						continue
					}
					relFiles = append(relFiles, rel)
				}
				if len(relFiles) > 0 {
					return filterByExtension(repoPath, relFiles, exts), nil
				}
			}
		}
	}

	// Fall back to filesystem walk.
	var files []string
	err = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "vendor" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(repoPath, path)
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return filterByExtension(repoPath, files, exts), nil
}

func filterByExtension(_ string, files []string, exts map[string]bool) []string {
	var result []string
	for _, f := range files {
		if f == "" {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f))
		if exts[ext] {
			result = append(result, f)
		}
	}
	return result
}

func buildScanPrompt(mode, customPrompt string) string {
	switch mode {
	case "security":
		return `You are a security auditor. Look for security vulnerabilities.`

	case "bugs":
		return `You are a code reviewer looking for bugs. Look for logic errors, unhandled error/corner cases, or anything that won't work correctly.`

	case "custom":
		if customPrompt == "" {
			log.Fatal("-custom-prompt is required when -mode=custom")
		}
		return customPrompt

	default:
		return ""
	}
}

func scanFile(repoPath, file, scanInstructions string, maxTurns int, timeout time.Duration) ([]Vulnerability, error) {
	prompt := fmt.Sprintf(`Analyze the file %q in this repository.

Start by reading the file, then follow any relevant code paths by reading other files as needed.

%s

Only report issues you are confident about. Do not report speculative or low-confidence findings.

You MUST respond with ONLY a JSON object in this exact format, with no other text before or after:
{"vulnerabilities": [{"short_description": "brief title", "detailed_description": "full explanation of the issue and its impact", "locations": [{"file": "path/to/file.go", "line": 42}]}]}

If you find no issues, respond with: {"vulnerabilities": []}`, file, scanInstructions)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "claude",
		"--print",
		"--output-format", "text",
		"--max-turns", fmt.Sprintf("%d", maxTurns),
		"--allowedTools", "Read,Grep,Glob",
		"-p", prompt,
	)
	cmd.Dir = repoPath

	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("timed out after %v", timeout)
		}
		return nil, fmt.Errorf("claude exited with error: %w", err)
	}

	return parseClaudeOutput(out, file)
}

func parseClaudeOutput(out []byte, sourceFile string) ([]Vulnerability, error) {
	text := strings.TrimSpace(string(out))

	// Claude might wrap the JSON in markdown code fences.
	text = stripCodeFences(text)

	var resp ClaudeResponse
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		// Try to find JSON object in the output.
		start := strings.Index(text, "{")
		end := strings.LastIndex(text, "}")
		if start >= 0 && end > start {
			if err2 := json.Unmarshal([]byte(text[start:end+1]), &resp); err2 != nil {
				return nil, fmt.Errorf("parsing claude output: %w (raw: %s)", err, truncate(text, 500))
			}
		} else {
			return nil, fmt.Errorf("parsing claude output: %w (raw: %s)", err, truncate(text, 500))
		}
	}

	var vulns []Vulnerability
	for _, v := range resp.Vulnerabilities {
		var locs []string
		for _, l := range v.Locations {
			if l.Line > 0 {
				locs = append(locs, fmt.Sprintf("%s:%d", l.File, l.Line))
			} else {
				locs = append(locs, l.File)
			}
		}
		vulns = append(vulns, Vulnerability{
			ShortDescription:    v.ShortDescription,
			DetailedDescription: v.DetailedDescription,
			Locations:           locs,
			FoundFromFile:       sourceFile,
		})
	}
	return vulns, nil
}

func stripCodeFences(s string) string {
	lines := strings.Split(s, "\n")
	if len(lines) >= 2 && strings.HasPrefix(lines[0], "```") {
		lines = lines[1:]
		if strings.HasPrefix(lines[len(lines)-1], "```") {
			lines = lines[:len(lines)-1]
		}
	}
	return strings.Join(lines, "\n")
}

// dedup asks Claude to compare candidate vulnerabilities against the existing
// output file and return only the ones that are genuinely new.
func dedup(outputPath string, candidates []Vulnerability, timeout time.Duration) ([]Vulnerability, error) {
	existingData, _ := os.ReadFile(outputPath)
	existingJSON := string(existingData)
	if existingJSON == "" {
		existingJSON = `{"scanned_files":[],"vulnerabilities":[]}`
	}

	candidatesJSON, err := json.MarshalIndent(candidates, "", "  ")
	if err != nil {
		return nil, err
	}

	prompt := fmt.Sprintf(`You are deduplicating vulnerability scan results.

Here is the current contents of the output file:
%s

Here are newly found candidate vulnerabilities:
%s

Compare each candidate against the existing vulnerabilities. A candidate is a duplicate if it describes the same underlying issue — even if the wording, detail level, or exact line numbers differ slightly. Use your judgment: two entries about the same SQL injection in the same function are duplicates even if described differently.

Return ONLY a JSON array of the candidates that are NOT duplicates. Use the exact same format as the candidates above. If all candidates are duplicates, return an empty array [].

Respond with ONLY the JSON array, no other text.`, existingJSON, string(candidatesJSON))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "claude",
		"--print",
		"--output-format", "text",
		"--max-turns", "1",
		"-p", prompt,
	)

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("claude dedup call failed: %w", err)
	}

	text := strings.TrimSpace(string(out))
	text = stripCodeFences(text)

	// Find the JSON array in the output.
	start := strings.Index(text, "[")
	end := strings.LastIndex(text, "]")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no JSON array in dedup response: %s", truncate(text, 500))
	}

	var newVulns []Vulnerability
	if err := json.Unmarshal([]byte(text[start:end+1]), &newVulns); err != nil {
		return nil, fmt.Errorf("parsing dedup response: %w", err)
	}
	return newVulns, nil
}

func loadOutput(path string) Output {
	data, err := os.ReadFile(path)
	if err != nil {
		return Output{}
	}
	var out Output
	if err := json.Unmarshal(data, &out); err != nil {
		return Output{}
	}
	return out
}

func saveOutput(path string, output Output) error {
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func supportedLanguages() string {
	langs := make([]string, 0, len(languageExtensions))
	for k := range languageExtensions {
		langs = append(langs, k)
	}
	return strings.Join(langs, ", ")
}
