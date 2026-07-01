# SentryGrep

A CI-integrated security scanner that detects **CWE-78 (OS Command Injection)** in Go codebases using [Semgrep](https://semgrep.dev) with a custom rule + community rulesets. Built as an AppSec portfolio project.

## What It Does

```
Go Codebase → Semgrep (custom + community rules) → JSON Report → Dashboard
                                                         ↓
                                                   GitHub Actions
                                                   (fail on ERROR)
```

1. **Custom Semgrep rule** targeting `exec.Command`/`exec.CommandContext` with shell invocation (`sh -c`) and dynamically-built arguments (string concatenation, `fmt.Sprintf`)
2. **Python scanner** (~140 lines) that runs Semgrep, parses JSON output, and buckets findings by CWE/severity
3. **HTML dashboard** (single file, zero dependencies) with severity charts, CWE breakdown, and filterable findings table
4. **GitHub Actions workflow** that runs on push/PR and fails the build above a configurable severity threshold

## Quick Start

```bash
# 1. Run the scanner against the test fixtures
python3 scanner.py --target testdata/ --output report.json

# 2. View the dashboard
python3 -m http.server 8080
# Open http://localhost:8080/dashboard.html

# 3. Run against a real Go repo
git clone https://github.com/civo/cli /tmp/civo-cli
python3 scanner.py --target /tmp/civo-cli --output report.json
```

## Project Structure

```
sentrygrep/
├── rules/
│   └── cwe-78-command-injection.yaml   # Custom Semgrep rule (CWE-78)
├── testdata/
│   ├── vulnerable.go                   # Known-vulnerable patterns (true positives)
│   └── safe.go                         # Known-safe patterns (false positive checks)
├── .github/workflows/
│   └── security-scan.yml               # CI pipeline
├── scanner.py                          # Scanner script (Python, stdlib only)
├── dashboard.html                      # Results dashboard (vanilla HTML/JS)
└── report.json                         # Generated scan report (gitignored)
```

## The CWE-78 Rule

Targets this specific pattern in Go:

```go
// VULNERABLE — shell interprets concatenated input
exec.Command("sh", "-c", "ping " + userInput)     // string concat
exec.Command("sh", "-c", fmt.Sprintf("curl %s", url)) // Sprintf

// SAFE — no shell, arguments passed separately
exec.Command("ping", "-c", "1", userInput)
```

**Detection results on test fixtures**: 4/4 true positives, 0 false positives, 1 documented false negative (intermediate variable — requires taint analysis).

## CI Configuration

The GitHub Actions workflow (`.github/workflows/security-scan.yml`) runs on every push/PR to `main`:

- Installs Semgrep (pinned version)
- Runs `scanner.py` with `--threshold ERROR`
- Uploads `report.json` as a build artifact
- Posts a findings summary to the PR
- **Fails the build** if any ERROR-severity finding exists

### Adjusting the Threshold

```yaml
# In the workflow, change --threshold:
--threshold ERROR    # Only fail on ERROR (high confidence)
--threshold WARNING  # Fail on WARNING + ERROR
--threshold INFO     # Fail on any finding
```

## Dependencies

| Component | Dependencies |
|-----------|-------------|
| Scanner | Python 3.6+ (stdlib only) |
| Dashboard | None (vanilla HTML/JS/CSS) |
| CI | Semgrep (pip install) |

## License

MIT
