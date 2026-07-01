# SentryGrep — Learning Guide & Technical Deep Dive

> A companion document to understand every decision in the SentryGrep security scanner. Written so you can defend every line in a technical interview.

---

## Table of Contents

1. [Step 1: Custom Semgrep Rule (CWE-78)](#step-1-custom-semgrep-rule-cwe-78)
2. [Step 2: Python Scanner Script](#step-2-python-scanner-script)
3. [Step 3: Dashboard](#step-3-dashboard)
4. [Step 4: GitHub Actions CI](#step-4-github-actions-ci)
5. [Rule Iteration: Catching the Real Bug](#rule-iteration-catching-the-real-bug)

---

## Step 1: Custom Semgrep Rule (CWE-78)

### What is Semgrep?

Semgrep is a **static analysis** tool that matches code patterns using **Abstract Syntax Tree (AST)** comparison — not regex on raw text. This means `exec.Command($X)` will match any call to `exec.Command` with one argument, regardless of whitespace, comments, or formatting. It understands code *structure*.

### Semgrep Rule Anatomy

Every rule lives in a YAML file and has these fields:

| Field | Purpose | Example |
|-------|---------|---------|
| `id` | Unique rule identifier | `go-cwe-78-shell-command-injection-concat` |
| `pattern` | The code shape to find | `exec.Command($SHELL, "-c", $A + $B)` |
| `message` | What to tell the developer | "OS command injection risk..." |
| `severity` | `ERROR` / `WARNING` / `INFO` | `ERROR` (breaks CI) |
| `metadata` | Structured data (CWE, OWASP) | Used by our dashboard later |
| `languages` | Target language | `[go]` |

### Key Semgrep Operators

#### `pattern` — Match This Shape
```yaml
pattern: exec.Command($SHELL, "-c", $PREFIX + $INPUT)
```
- `$SHELL`, `$PREFIX`, `$INPUT` are **metavariables** — named wildcards that bind to any expression
- Think of them as "capture groups" but for AST nodes, not regex

#### `pattern-either` — OR Logic
```yaml
pattern-either:
  - pattern: exec.Command(...)     # match this
  - pattern: exec.CommandContext(...)  # OR this
```
If *any* sub-pattern matches, the rule fires.

#### `pattern-not` — Exclusion (suppress false positives)
```yaml
patterns:
  - pattern: exec.Command($SHELL, "-c", $CMD)
  - pattern-not: exec.Command($SHELL, "-c", "hardcoded string")
```
Matches the first pattern BUT NOT the second. Used to carve out known-safe patterns.

#### `...` — Ellipsis Operator
```yaml
pattern: exec.Command($SHELL, "-c", $A + $B, ...)
```
The `...` means "zero or more additional arguments." Without it, the pattern only matches calls with exactly that many arguments.

#### `metavariable-regex` — Constrain a metavariable
```yaml
metavariable-regex:
  metavariable: $SHELL
  regex: (sh|bash|/bin/sh|/bin/bash)
```
Only matches if `$SHELL` is one of those literal values. We didn't use this in our rule because Semgrep already constrains by the argument position, but it's useful when you need tighter filtering.

### The Vulnerability: CWE-78 (OS Command Injection)

#### Why `sh -c` is the danger zone

```go
// DANGEROUS: shell interprets the entire string
exec.Command("sh", "-c", "ping " + userInput)
//                         ↑ shell sees: ping ;rm -rf /
//                         the semicolon starts a NEW command

// SAFE: no shell, kernel runs ping directly
exec.Command("ping", "-c", "1", userInput)
//                               ↑ just an argument to ping
//                               semicolons are literal characters
```

**Key insight**: `exec.Command` without a shell passes each argument as a separate `argv[]` element to the kernel. The kernel doesn't interpret shell metacharacters (`;`, `|`, `&&`, `` ` ``, `$()`). Only when you route through `sh -c` does a shell parse the string.

#### Attack Example

```
GET /ping?host=8.8.8.8;cat+/etc/passwd
```

The server runs:
```go
exec.Command("sh", "-c", "ping -c 1 " + "8.8.8.8;cat /etc/passwd")
// Shell sees: ping -c 1 8.8.8.8; cat /etc/passwd
// Executes BOTH commands
```

#### The Correct Fix

```go
// Pass arguments separately — no shell involved
cmd := exec.Command("ping", "-c", "1", userInput)
// Even if userInput is "8.8.8.8;cat /etc/passwd",
// ping receives it as ONE argument and fails gracefully
```

### Our Rule's Detection Results

| Test Case | Line | Pattern | Rule | Detected? | Why |
|-----------|------|---------|------|-----------|-----|
| vuln1 | 22 | `"ping -c 1 " + host` | Rule 1 (inline) | ✅ Yes | Direct concat in exec.Command with `-c` |
| vuln2 | 31 | `fmt.Sprintf("nslookup %s", ip)` | Rule 1 (inline) | ✅ Yes | Sprintf pattern matched |
| vuln3 | 41 | `"curl " + target` via CommandContext | Rule 1 (inline) | ✅ Yes | CommandContext variant covered |
| vuln4 | 54 | Intermediate variable `payload` | Rule 2 (indirect) | ✅ Yes | Multi-statement `...` matched |
| vuln5 | 66 | `"id " + user + " | grep admin"` | Rule 1 (inline) | ✅ Yes | Multi-part concat matched |
| safe1 | — | Hardcoded `"echo hello world"` | — | ✅ Ignored | No dynamic input |
| safe2 | — | `exec.Command("ping", ..., target)` | — | ✅ Ignored | No shell invocation |
| safe3 | — | CommandContext with literals | — | ✅ Ignored | No dynamic input |
| safe4 | — | `exec.Command("sh", script)` | — | ✅ Ignored | No `-c` flag |
| safe5 | — | Correct fix pattern | — | ✅ Ignored | Arguments passed separately |

**5/5 true positives, 0 false positives.** vuln4 was originally a false negative — see [Rule Iteration](#rule-iteration-catching-the-real-bug) for how we fixed it.

### File References

- Rule: [cwe-78-command-injection.yaml](file:///home/comrade/Desktop/sentrygrep/rules/cwe-78-command-injection.yaml)
- Vulnerable test: [vulnerable.go](file:///home/comrade/Desktop/sentrygrep/testdata/vulnerable.go)
- Safe test: [safe.go](file:///home/comrade/Desktop/sentrygrep/testdata/safe.go)

---

## Step 2: Python Scanner Script

### Why Python Over Go?

We chose Python for the scanner script. Here's the tradeoff analysis:

| Factor | Python | Go |
|--------|--------|----|
| **Semgrep integration** | Semgrep itself is Python; its JSON output is trivially parsed with `json.loads()` | Would need `os/exec` + JSON parsing — works fine but more boilerplate |
| **Scripting speed** | Faster to write, modify, iterate | Requires compile step, more verbose |
| **Dependencies** | `subprocess` + `json` — both in stdlib, zero pip installs | Same: `os/exec` + `encoding/json` in stdlib |
| **Portfolio signal** | Shows polyglot ability (Go target, Python tooling) | Shows Go depth but less breadth |
| **CI compatibility** | Python 3 is pre-installed on all GitHub Actions runners | Go needs a setup step |
| **Lines of code** | ~100 lines | ~150-200 lines for equivalent functionality |

> [!NOTE]
> **Interview answer**: "I chose Python for the tooling layer because Semgrep is a Python tool, JSON parsing is trivial in Python, and it demonstrates I pick the right tool for the job rather than forcing one language everywhere. The *target* codebase is Go — the *tooling* doesn't need to be."

### Script Architecture

The scanner script has exactly **three responsibilities**, each as a single function:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  run_semgrep │────▶│ parse_results│────▶│ write_report │
│              │     │              │     │              │
│ Calls semgrep│     │ Buckets by   │     │ Writes JSON  │
│ subprocess   │     │ CWE/severity │     │ for dashboard│
└──────────────┘     └──────────────┘     └──────────────┘
```

**No classes, no frameworks, no abstractions beyond functions.** Each function takes input and returns output — easy to test, easy to explain.

### Key Design Decisions

#### 1. `subprocess.run()` vs `os.system()` vs Semgrep Python API

```python
subprocess.run(["semgrep", "--config", ...], capture_output=True)
```

- **`os.system()`** — Returns only exit code, stdout goes to terminal. Can't capture output. Also a shell injection risk itself (ironic for a security tool).
- **Semgrep Python API** — Exists but is undocumented, unstable, and tightly coupled to Semgrep's internals. It would make the codebase fragile.
- **`subprocess.run()`** — Clean, explicit, captures stdout/stderr, no shell involvement. This is the right choice.

> [!TIP]
> We pass the command as a **list** `["semgrep", "--config", ...]` not a string `"semgrep --config ..."`. Lists bypass the shell — each element becomes a direct `argv` entry. This is the same principle as our CWE-78 rule: avoid shell interpretation.

#### 2. Why `--json` Output Format

Semgrep supports text, JSON, SARIF, and other output formats. We use `--json` because:
- It's structured and machine-parseable
- It includes metadata (CWE, severity, confidence) that text output strips
- The dashboard in Step 3 can consume it directly
- SARIF is more complex (GitHub-specific) — we'll generate it in Step 4 if needed

#### 3. Severity Mapping

Semgrep uses three severity levels: `ERROR`, `WARNING`, `INFO`. Our scanner maps these to a richer classification:

| Semgrep Severity | Our Label | CI Action |
|-----------------|-----------|-----------|
| `ERROR` | Critical/High | Fail build |
| `WARNING` | Medium | Warn but pass |
| `INFO` | Low | Log only |

#### 4. Exit Codes

The script uses exit codes that CI systems understand:

| Code | Meaning |
|------|---------|
| 0 | No findings above threshold |
| 1 | Findings above threshold — fail the build |
| 2 | Scanner itself errored (Semgrep not found, etc.) |

### Dependencies

**Zero external dependencies.** Every import is from Python's standard library:

| Module | Purpose | Why stdlib |
|--------|---------|-----------| 
| `subprocess` | Run semgrep as a child process | No pip install, no version conflicts |
| `json` | Parse semgrep JSON output | Native JSON support |
| `argparse` | CLI argument parsing | Cleaner than manual `sys.argv` parsing |
| `pathlib` | File path handling | Cross-platform, cleaner than `os.path` |
| `sys` | Exit codes | Standard process control |
| `datetime` | Timestamp the report | Audit trail for when scan ran |

### File Reference

- Scanner script: [scanner.py](file:///home/comrade/Desktop/sentrygrep/scanner.py)

---

## Step 3: Dashboard

### Why Plain HTML/JS Over React?

| Factor | Plain HTML/JS | React |
|--------|--------------|-------|
| **Build step** | None — open the file | Needs `npm install`, webpack/vite, transpilation |
| **Dependencies** | Zero | react, react-dom, + bundler = 40KB+ min |
| **Explainability** | Every line is native browser API | Must explain JSX, virtual DOM, hooks |
| **Rendering model** | Render once from static JSON | React's reconciliation is overkill for static data |
| **Portfolio signal** | Shows you can build without a crutch | Shows framework familiarity (but everyone has that) |

> [!NOTE]
> **Interview answer**: "This dashboard renders static JSON once — there are no user-driven state mutations that would benefit from React's virtual DOM diffing. Filtering works by toggling `display:none` on existing rows. A framework would add 40KB of runtime for zero functional benefit."

### Architecture

The dashboard has no build step, no bundler, no transpiler. It's one HTML file with embedded CSS and JS:

```
dashboard.html
├── <style>     → CSS design system (custom properties, glassmorphism, animations)
├── <div#app>   → Single mount point
└── <script>    → ~200 lines of vanilla JS
     ├── loadReport()      → fetch('report.json')
     ├── render()          → builds all DOM sections
     ├── renderDonut()     → CSS conic-gradient chart
     ├── renderSeverityBars() → animated bar chart
     ├── renderFindings()  → table rows
     ├── attachFilters()   → client-side search/filter
     └── attachSorting()   → column sort with visual indicators
```

### How to Run

```bash
# 1. Generate the report
python3 scanner.py --target testdata/ --output report.json

# 2. Serve the dashboard (fetch() requires HTTP, not file://)
python3 -m http.server 8080

# 3. Open http://localhost:8080/dashboard.html
```

> [!WARNING]
> **Why can't you just double-click the HTML file?** The `fetch()` API blocks requests from `file://` URLs due to CORS (Cross-Origin Resource Sharing) restrictions. The browser treats each local file as a separate "origin" and refuses to let one file read another. The one-liner HTTP server makes everything same-origin at `http://localhost:8080`.

### Key Design Decisions

#### 1. CSS Custom Properties (Design System)

```css
:root {
    --color-error: #f43f5e;
    --color-error-bg: rgba(244, 63, 94, 0.12);
    --bg-card: rgba(18, 24, 40, 0.75);
    /* ... */
}
```

Every color, spacing value, and radius is defined as a CSS variable in `:root`. This is the same approach used by professional design systems (Material UI, Radix, Shadcn). Benefits:
- **Single source of truth** — change a color once, it updates everywhere
- **Self-documenting** — variable names describe their purpose
- **Themeable** — swap `:root` values for a light theme

#### 2. Glassmorphism (The Frosted Glass Effect)

```css
.stat-card {
    background: rgba(18, 24, 40, 0.75);     /* semi-transparent */
    backdrop-filter: blur(12px);              /* blurs content behind */
    -webkit-backdrop-filter: blur(12px);      /* Safari prefix */
    border: 1px solid rgba(255, 255, 255, 0.06); /* subtle edge */
}
```

**What's happening**: `backdrop-filter: blur()` applies a gaussian blur to whatever is *behind* the element. Combined with a semi-transparent background, it creates the "frosted glass" look. The `-webkit-` prefix is needed because Safari still hasn't unprefixed this property.

> [!TIP]
> **Non-obvious CSS feature**: `backdrop-filter` is CSS Filters Level 2. It's supported in all major browsers since 2020, but you should know it's a relatively new property if asked.

#### 3. Donut Chart with `conic-gradient()` (No Chart Library)

```css
.donut {
    background: conic-gradient(
        var(--color-error) 0% 75%,     /* red sector: 0° to 270° */
        var(--color-warning) 75% 90%,  /* amber sector: 270° to 324° */
        var(--color-info) 90% 100%     /* blue sector: 324° to 360° */
    );
    border-radius: 50%;
}
```

**How it works**: `conic-gradient()` paints color around a center point, like a pie chart. Each color stop defines a sector with start/end percentages. The inner hole is a pseudo-element (`::after`) with the card's background color, positioned on top.

**Why no Chart.js/D3?** We have 3 data points (ERROR/WARNING/INFO counts). A charting library would add 200KB+ of JavaScript for a pie chart we can build in 10 lines of CSS. The tradeoff flips if you need 20+ chart types — then a library earns its weight.

> [!TIP]
> **Non-obvious CSS feature**: `conic-gradient()` is CSS Images Level 4. It's the property that makes pure-CSS pie/donut charts possible. Supported in all modern browsers since 2020.

#### 4. Client-Side Filtering (No Re-render)

```javascript
function applyFilters() {
    rows.forEach((row, i) => {
        const matches = /* check search + severity + CWE */;
        row.style.display = matches ? '' : 'none';
    });
}
```

**Why toggle `display` instead of re-rendering?** The DOM is expensive to create but cheap to show/hide. Since all rows already exist, toggling `display:none` is O(n) with zero DOM allocation. Re-rendering would mean creating new elements, which triggers layout recalculation and repainting — orders of magnitude slower for large result sets.

#### 5. Column Sorting

```javascript
th.addEventListener('click', () => {
    const sorted = [...findings].sort(/* comparator */);
    renderFindings(sorted);
});
```

Clicking a column header sorts the table. We re-render the table body (not the whole page) with sorted data. Visual indicators (`↑`/`↓`) are added via CSS pseudo-elements (`.sorted-asc::after`), not inline text — keeping data and presentation separate.

#### 6. XSS Protection: `escapeHtml()`

```javascript
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
```

**Why this matters for a security tool**: Semgrep findings contain source code snippets. If a snippet contains `<script>alert(1)</script>`, inserting it via `innerHTML` would execute it. The `escapeHtml` function uses the browser's own text-node encoding to convert `<` to `&lt;`, etc.

> [!IMPORTANT]
> **Interview talking point**: "Even though this is a local-only portfolio tool, I still escape HTML output. It's a good habit, and it demonstrates I think about XSS even in contexts where the risk is low. A security tool that's vulnerable to injection would be embarrassing."

### Visual Features

| Feature | Technique | Why |
|---------|-----------|-----|
| Dark theme | CSS custom properties | Professional security-tool aesthetic |
| Glassmorphic cards | `backdrop-filter: blur()` | Modern, premium feel without images |
| Animated severity bars | CSS `transition` on `width` | Bars grow on load — draws the eye to high counts |
| Donut chart | `conic-gradient()` | Zero-dependency pie chart |
| Hover effects | `transform: translateY(-2px)` | Micro-interaction — cards lift on hover |
| Fade-in animation | `@keyframes fadeInUp` | Staggered entry — cards appear sequentially |
| Responsive grid | CSS Grid with `@media` breakpoints | Works on mobile (2-col) and desktop (4-col) |

### File Reference

- Dashboard: [dashboard.html](file:///home/comrade/Desktop/sentrygrep/dashboard.html)

---

## Step 4: GitHub Actions CI

### How GitHub Actions Works

A GitHub Actions **workflow** is a YAML file in `.github/workflows/` that defines automated tasks triggered by repository events.

```
Event (push/PR) → Workflow → Job(s) → Step(s) → Commands/Actions
```

| Concept | What it is |
|---------|------------|
| **Workflow** | The YAML file — defines the entire pipeline |
| **Event/Trigger** | What starts the workflow (push, PR, schedule, manual) |
| **Job** | A set of steps that run on the same runner (VM). Jobs run in parallel by default |
| **Step** | One unit of work — either a shell command (`run:`) or a reusable action (`uses:`) |
| **Action** | A published, reusable step (e.g., `actions/checkout@v4`) from GitHub's marketplace |
| **Runner** | The VM that executes the job (`ubuntu-latest` = fresh Ubuntu VM per run) |

### Our Workflow: Step by Step

```
Trigger (push/PR to main)
    │
    ▼
┌─ Job: security-scan ──────────────────────────────┐
│                                                     │
│  1. Checkout repo           (actions/checkout@v4)   │
│  2. Setup Python            (actions/setup-python)  │
│  3. Install Semgrep         (pip install)           │
│  4. Run scanner.py          (continue-on-error)     │
│  5. Upload report artifact  (always runs)           │
│  6. Post findings summary   (always runs)           │
│  7. Enforce quality gate    (fail if scan failed)   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Key Design Decisions

#### 1. Why `pip install semgrep` Instead of the Official Semgrep Action?

Semgrep provides `returntocorp/semgrep-action`, but we don't use it because:

- **It pushes you toward Semgrep App (SaaS)** — requires a `SEMGREP_APP_TOKEN`, uploads results to their cloud, and adds telemetry we don't need
- **It hides the JSON output** — we need the raw JSON for our `scanner.py` parser and dashboard
- **It's a black box** — our pipeline should be explainable line by line

Direct `pip install` gives us full control. We pin the version (`semgrep==1.167.0`) so CI is reproducible — without pinning, a Semgrep update could change rule behavior and break your build on a Tuesday morning with no code changes.

> [!IMPORTANT]
> **Interview talking point**: "I chose direct pip install over the official action because I needed raw JSON output for my custom parser and dashboard. The official action is optimized for their SaaS platform, which adds dependencies I don't need. I pin the Semgrep version for CI reproducibility."

#### 2. The `continue-on-error` + Re-fail Pattern

This is the most non-obvious part of the workflow:

```yaml
# Step 4: Run scanner — DON'T fail yet, let upload/comment run
- name: Run SentryGrep scanner
  id: scan
  continue-on-error: true    # ← absorbs exit code 1
  run: python3 scanner.py --threshold ERROR

# Step 5: Upload report — runs even if Step 4 "failed"
- name: Upload scan report
  if: always()               # ← runs regardless of prior failures

# Step 7: NOW fail — after all reporting steps completed
- name: Enforce quality gate
  if: steps.scan.outcome == 'failure'
  run: exit 1                # ← THIS is what actually fails the job
```

**Why this complexity?** Without `continue-on-error`, a failed Step 4 would skip Steps 5-6 by default. We'd lose the report upload and PR comment — exactly the information developers need to fix the issues.

The pattern is: **do work → save results → THEN fail.** This is standard in production CI pipelines.

> [!TIP]
> `steps.scan.outcome` references Step 4 by its `id: scan`. The value is `'success'` or `'failure'` (as strings, with quotes). `continue-on-error` changes the step's `conclusion` (what the UI shows) but preserves the `outcome` (the actual exit code result), so we can still check what really happened.

#### 3. `if: always()` — Running Steps After Failure

```yaml
- name: Upload scan report
  if: always()
```

By default, GitHub Actions skips all subsequent steps when one fails. The `always()` function overrides this — the step runs no matter what happened before. Alternatives:

| Condition | Runs when |
|-----------|-----------|
| *(default)* | All previous steps succeeded |
| `always()` | Always, even if previous steps failed or were cancelled |
| `failure()` | At least one previous step failed |
| `success()` | All previous steps succeeded (same as default) |

#### 4. `$GITHUB_STEP_SUMMARY` — Job Summary Markdown

```python
summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
with open(summary_path, "a") as f:
    f.write(markdown_string)
```

`$GITHUB_STEP_SUMMARY` is a special environment variable containing a file path. When you write Markdown to this file, GitHub renders it in the **Actions tab summary** for that run — no API calls, no tokens, no special permissions.

> [!NOTE]
> **Non-obvious feature**: `GITHUB_STEP_SUMMARY` was introduced in May 2022. Before that, posting summaries required the GitHub API + a token. Many older tutorials still show the API approach — the summary file is simpler.

#### 5. Explicit Permissions (Principle of Least Privilege)

```yaml
permissions:
  contents: read
  pull-requests: write
```

GitHub Actions tokens default to broad access. Our workflow only needs:
- **`contents: read`** — clone the repository
- **`pull-requests: write`** — post PR comments

We explicitly restrict permissions. This is a security best practice: if a supply chain attack compromises a dependency, the token can't write to the repository or manage releases.

> [!WARNING]
> **Security note**: Many public GitHub Actions workflows use `permissions: write-all` or don't set permissions at all (defaulting to broad access). This is a common finding in CI/CD security audits. Always set minimum required permissions.

#### 6. Version Pinning

Every external action and dependency is pinned:

| Dependency | Pinned to | Why |
|-----------|-----------|-----|
| `actions/checkout` | `@v4` | Major version pin — gets security patches, no breaking changes |
| `actions/setup-python` | `@v5` | Same strategy |
| `actions/upload-artifact` | `@v4` | Same strategy |
| `semgrep` | `==1.167.0` | Exact pin — rule behavior changes between versions |

> [!TIP]
> Actions are pinned to major versions (`@v4`) which get non-breaking updates. For maximum security, you can pin to exact commit SHAs (`@abcdef123...`), but that requires manual updates for security patches. Major version pins are the standard tradeoff.

### Workflow Trigger Logic

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
```

| Event | When it fires | Purpose |
|-------|--------------|---------|
| `push` to `main` | Code merged to main | Catch issues post-merge (safety net) |
| `pull_request` to `main` | PR opened/updated targeting main | Catch issues pre-merge (shift-left) |

We don't trigger on all branches — that would burn CI minutes on every feature branch push. PR events already cover feature branches since they target main.

### Exit Code Flow

```
scanner.py exit 0 → step.outcome = success → quality gate skipped → ✅ Job passes
scanner.py exit 1 → step.outcome = failure → quality gate fails   → ❌ Job fails
scanner.py exit 2 → step.outcome = failure → quality gate fails   → ❌ Job fails
```

### What Developers See

On a **failing PR**, the developer sees:

1. **Red ❌ check** on the PR — blocks merge (if branch protection is enabled)
2. **Job summary** with severity table and top findings (via `GITHUB_STEP_SUMMARY`)
3. **Downloadable `report.json`** artifact — can be loaded into the dashboard locally
4. **Error annotation** from the `::error::` workflow command

### File Reference

- Workflow: [security-scan.yml](file:///home/comrade/Desktop/sentrygrep/.github/workflows/security-scan.yml)
- README: [README.md](file:///home/comrade/Desktop/sentrygrep/README.md)

---

## Complete Project Map

| File | Purpose | Lines | Dependencies |
|------|---------|-------|-------------|
| [cwe-78-command-injection.yaml](file:///home/comrade/Desktop/sentrygrep/rules/cwe-78-command-injection.yaml) | Custom Semgrep rule (2 rules) | ~185 | None |
| [vulnerable.go](file:///home/comrade/Desktop/sentrygrep/testdata/vulnerable.go) | True positive test cases | ~69 | None |
| [safe.go](file:///home/comrade/Desktop/sentrygrep/testdata/safe.go) | False positive test cases | ~48 | None |
| [scanner.py](file:///home/comrade/Desktop/sentrygrep/scanner.py) | Runs Semgrep + parses results | ~145 | Python stdlib only |
| [dashboard.html](file:///home/comrade/Desktop/sentrygrep/dashboard.html) | Results visualization | ~530 | None (vanilla HTML/JS/CSS) |
| [security-scan.yml](file:///home/comrade/Desktop/sentrygrep/.github/workflows/security-scan.yml) | CI pipeline | ~180 | Semgrep (pip) |
| [README.md](file:///home/comrade/Desktop/sentrygrep/README.md) | Repo documentation | ~85 | None |
| [LEARNING_GUIDE.md](file:///home/comrade/Desktop/sentrygrep/LEARNING_GUIDE.md) | This guide — all explanations | ~700 | None |

---

## Rule Iteration: Catching the Real Bug

This section documents the most important lesson in the project: **testing your tool against real code, finding its gaps, and fixing them.**

### The Problem

We ran SentryGrep against the [Civo CLI](https://github.com/civo/cli) — a real open-source Go project where a CWE-78 bug exists in [kubernetes_app_remove.go](file:///home/comrade/Desktop/sentrygrep/cli/cmd/kubernetes/kubernetes_app_remove.go#L57-L58):

```go
// Line 44: appName comes from CLI arguments (user input)
allApps := strings.Split(args[0], ",")

// Line 57: fmt.Sprintf builds the shell command — injection point
filepath := fmt.Sprintf("bash <(curl -s .../%s/uninstall.sh)", appName)

// Line 58: passes to /bin/bash -c — the shell interprets it
cmdConfig := exec.Command("/bin/bash", "-c", filepath)
```

**Attack vector**: `civo kubernetes app remove "legit); rm -rf /" --cluster mycluster`

Rule 1 (our original rule) **missed this completely**. It only matches patterns where the `fmt.Sprintf` or concatenation happens **inside** the `exec.Command()` call. Here, they're on separate lines.

### Why Rule 1 Missed It

Rule 1 uses single-expression patterns:

```yaml
# This ONLY matches when Sprintf is INLINE:
pattern: exec.Command($SHELL, "-c", fmt.Sprintf($FMT, ...))

# The Civo code has Sprintf on line 57 and exec.Command on line 58.
# Semgrep sees exec.Command("/bin/bash", "-c", filepath) — just a
# variable name, not a Sprintf call. No match.
```

### The Fix: Multi-Statement Pattern Matching (Rule 2)

Semgrep OSS has a feature I initially overlooked: the `...` operator works **across statements** in multi-line patterns, not just as "zero or more arguments" within a function call.

```yaml
# The key insight — match TWO statements with ... in between:
pattern: |
    $VAR := fmt.Sprintf(...)          # ← match statement 1
    ...                                # ← zero or more lines between
    exec.Command($SHELL, "-c", $VAR)  # ← match statement 2
```

**How this works**:
1. Semgrep finds a `fmt.Sprintf(...)` assignment and binds the left-hand side to `$VAR`
2. The `...` matches any number of statements in between (including zero)
3. Semgrep then looks for an `exec.Command` call using **the same `$VAR`** name
4. If both match within the same function scope → finding reported

> [!IMPORTANT]
> **This is NOT taint analysis.** Semgrep is matching by **variable name**, not by data flow. If `$VAR` were reassigned to a safe value between the two lines, Semgrep would still match (false positive). In practice, this is rare — developers don't usually reassign a variable between constructing it and using it one line later.

### Why `:=` AND `=` Patterns Are Both Needed

Go has two assignment operators:

```go
filepath := fmt.Sprintf(...)   // := short variable declaration (new variable)
filepath = fmt.Sprintf(...)    // =  assignment (existing variable)
```

Semgrep treats these as different AST nodes, so we need separate patterns for each. Missing either one would create blind spots.

### Results After Adding Rule 2

| Target | Before (Rule 1 only) | After (Rule 1 + Rule 2) |
|--------|---------------------|-------------------------|
| testdata/vulnerable.go | 4/5 detected | **5/5** detected |
| testdata/safe.go | 0 false positives | 0 false positives |
| Civo CLI CWE-78 bug | ❌ **Missed** | ✅ **Caught** (line 57) |
| CI build result (Civo) | PASS (wrongly) | **FAIL** (correctly) |

### The Full Scan Output Against Civo CLI

```
============================================================
  SentryGrep Scan Report
============================================================
  Total findings: 2

  By Severity:
    ERROR       1  █       ← CWE-78 command injection (our rule)
    WARNING     1  █       ← CWE-328 weak crypto (community rule)
    INFO        0

  Top findings:
    [ERROR  ] cli/cmd/kubernetes/kubernetes_app_remove.go:57 — CWE-78
    [WARNING] cli/cmd/diskimage/disk_image_create.go:59 — CWE-328
============================================================

FAIL: ERROR finding exceeds threshold (ERROR)
```

### Interview Narrative

This is the story you tell when asked "walk me through a project you built":

> [!TIP]
> **Interview script**: "I built a Semgrep-based scanner targeting CWE-78 in Go. My first rule caught inline patterns — `exec.Command('sh', '-c', fmt.Sprintf(...))` — and I validated it with 5 test cases: 4 true positives, 0 false positives.
>
> Then I tested against a real open-source project, Civo CLI, where I'd previously found a command injection bug manually. **My rule missed it.** The vulnerable code had `fmt.Sprintf` on one line and `exec.Command` on the next — my rule only matched single-expression patterns.
>
> I diagnosed the gap and learned that Semgrep's `...` operator works across statements, not just within function arguments. I added a second rule using multi-statement matching: `$VAR := fmt.Sprintf(...) ... exec.Command($S, '-c', $VAR)`. This caught the real bug.
>
> The tool now detects both inline and cross-statement injection patterns, surfaces them in a dashboard with severity/CWE classification, and fails CI builds through a GitHub Actions workflow. The iteration — write rule, test on real code, find gap, fix gap — is exactly how AppSec engineering works in practice."

### What This Teaches About Static Analysis

| Concept | Lesson |
|---------|--------|
| **Syntactic matching** | Fast and precise, but only sees code *shape* at one location |
| **Multi-statement matching** | Extends syntactic matching across lines using `...` — bridges the gap without full data flow |
| **Taint analysis** | Tracks data from *source* (user input) to *sink* (dangerous function) across the entire program — most powerful but requires Semgrep Pro or CodeQL |
| **Defense in depth** | No single tool catches everything. Layer: custom rules + community rules + manual review |
| **Test against real code** | Unit tests (testdata/) validate correctness; real codebases validate usefulness |

### Remaining Limitations (Honest Assessment)

Even with Rule 2, there are patterns we won't catch:

1. **Cross-function flow**: If `fmt.Sprintf` happens in function A and `exec.Command` in function B, multi-statement matching won't connect them (different scopes)
2. **Struct field storage**: `s.cmd = fmt.Sprintf(...)` then later `exec.Command("sh", "-c", s.cmd)` — Semgrep can't track through struct fields
3. **Dynamic shell selection**: `shell := getShell()` then `exec.Command(shell, "-c", ...)` — our rule looks for literal `"sh"` or `"bash"` values

These require full taint analysis (Semgrep Pro `mode: taint`, or CodeQL's data-flow engine). Acknowledging limitations honestly is stronger than claiming perfect coverage.
