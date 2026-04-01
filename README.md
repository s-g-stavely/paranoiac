# paranoiac

Uses Claude Code to scan a repo for vulnerabilities, bugs, or anything else interesting.

## Usage

```
go build -o paranoiac .

# scan for security vulnerabilities (default)
./paranoiac -repo /path/to/repo

# scan for bugs
./paranoiac -repo /path/to/repo -mode bugs

# scan for something else
./paranoiac -repo /path/to/repo -mode custom -custom-prompt "find performance issues"
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-repo` | `.` | Repository to scan |
| `-output` | `paranoiac-output.json` | Output JSON file |
| `-mode` | `security` | `security`, `bugs`, or `custom` |
| `-custom-prompt` | | What to look for (requires `-mode custom`) |
| `-languages` | `go` | Comma-separated: `go,java,python,javascript,typescript` |
| `-concurrency` | `5` | Parallel Claude instances |
| `-max-turns` | `50` | Max conversation turns per instance |
| `-timeout` | `15m` | Timeout per instance |

Results are saved incrementally. Re-running skips already-scanned files.
