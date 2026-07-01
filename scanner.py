#!/usr/bin/env python3
"""
SentryGrep Scanner — runs Semgrep with custom + default rules, parses results.

Usage:
    python3 scanner.py --target ./path/to/go/code
    python3 scanner.py --target ./path/to/go/code --threshold WARNING
    python3 scanner.py --target ./path/to/go/code --output report.json

Exit codes:
    0 — no findings above threshold
    1 — findings above threshold (CI should fail)
    2 — scanner error (semgrep not found, bad config, etc.)
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# WHY this ordering?  We define severity as a numeric scale so we can do
# threshold comparisons like "fail if anything >= WARNING".  The mapping
# is intentionally simple — three levels, matching Semgrep's own model.
# ---------------------------------------------------------------------------
SEVERITY_RANK = {"ERROR": 3, "WARNING": 2, "INFO": 1}


def run_semgrep(target: str, rules_dir: str) -> dict:
    """
    Run Semgrep and return parsed JSON output.

    We run TWO configs in one invocation:
      1. Our custom rules directory (rules/)
      2. Semgrep's community Go security ruleset ("p/golang")

    WHY one invocation, not two?
      - Semgrep deduplicates findings across configs automatically
      - One process = one JSON blob = simpler parsing
      - Faster: Semgrep parses each file once regardless of rule count

    WHY "p/golang"?
      - "p/" is Semgrep's registry prefix for community rulesets
      - "p/golang" includes ~200 rules for Go: SQL injection, path traversal,
        hardcoded secrets, crypto misuse, etc.
      - This gives breadth; our custom rule gives depth on CWE-78 specifically
    """
    cmd = [
        "semgrep",
        "--config", rules_dir,       # our custom rules
        "--config", "p/golang",      # community Go rules (downloaded on first run)
        "--json",                    # machine-readable output
        "--quiet",                   # suppress progress bars / status messages
        target,                      # directory or file to scan
    ]

    try:
        # capture_output=True → stdout and stderr go into result object
        # text=True → decode bytes to str (UTF-8)
        # We do NOT use shell=True — list form avoids shell interpretation
        # (practicing what our CWE-78 rule preaches)
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        # Semgrep binary not on PATH
        print("ERROR: 'semgrep' not found. Install: pip install semgrep", file=sys.stderr)
        sys.exit(2)

    # Semgrep exit codes:
    #   0 = ran successfully, no findings
    #   1 = ran successfully, findings found  ← this is normal, not an error
    #   2+ = actual error (bad rule, parse failure, etc.)
    if result.returncode > 1:
        print(f"ERROR: Semgrep failed (exit {result.returncode}):", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(2)

    return json.loads(result.stdout)


def parse_results(raw: dict) -> dict:
    """
    Transform Semgrep's raw JSON into a structured report.

    Input shape (from Semgrep):
        { "results": [ { "check_id": ..., "path": ..., "start": ..., ... } ] }

    Output shape (for our dashboard):
        {
            "scan_timestamp": "...",
            "total_findings": N,
            "by_severity": { "ERROR": N, "WARNING": N, "INFO": N },
            "by_cwe": { "CWE-78": N, "CWE-89": N, ... },
            "findings": [ { normalized finding objects } ]
        }

    WHY normalize?  Semgrep's JSON is verbose and nested. The dashboard
    needs a flat, consistent shape. We also extract CWE from metadata —
    not every Semgrep rule has a CWE, so we default to "UNCLASSIFIED".
    """
    findings = []
    by_severity = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    by_cwe = {}

    for result in raw.get("results", []):
        severity = result["extra"]["severity"]
        metadata = result["extra"].get("metadata", {})

        # --- Extract CWE ---
        # Semgrep stores CWE as a list of strings like:
        #   ["CWE-78: Improper Neutralization of ..."]
        # We extract just the ID part ("CWE-78") for bucketing.
        # Some community rules don't have CWE at all → "UNCLASSIFIED"
        cwe_list = metadata.get("cwe", [])
        if cwe_list:
            # Take the first CWE, split on ":", keep just "CWE-78"
            cwe = cwe_list[0].split(":")[0].strip()
        else:
            cwe = "UNCLASSIFIED"

        # --- Extract the source code snippet ---
        # Semgrep includes the matched source in "extra.lines"
        snippet = result["extra"].get("lines", "").strip()

        finding = {
            "rule_id": result["check_id"],
            "file": result["path"],
            "line": result["start"]["line"],
            "col": result["start"]["col"],
            "end_line": result["end"]["line"],
            "severity": severity,
            "cwe": cwe,
            "message": result["extra"]["message"],
            "snippet": snippet,
            "confidence": metadata.get("confidence", "UNKNOWN"),
        }

        findings.append(finding)
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_cwe[cwe] = by_cwe.get(cwe, 0) + 1

    # Sort findings: ERROR first, then WARNING, then INFO
    findings.sort(key=lambda f: -SEVERITY_RANK.get(f["severity"], 0))

    return {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_cwe": by_cwe,
        "findings": findings,
    }


def write_report(report: dict, output_path: str) -> None:
    """Write the report as pretty-printed JSON for the dashboard."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print(f"Report written to {path} ({report['total_findings']} findings)")


def print_summary(report: dict) -> None:
    """Print a human-readable summary to stdout."""
    print(f"\n{'='*60}")
    print(f"  SentryGrep Scan Report — {report['scan_timestamp']}")
    print(f"{'='*60}")
    print(f"  Total findings: {report['total_findings']}")
    print()

    print("  By Severity:")
    for sev in ["ERROR", "WARNING", "INFO"]:
        count = report["by_severity"].get(sev, 0)
        bar = "█" * count
        print(f"    {sev:8s}  {count:3d}  {bar}")
    print()

    print("  By CWE:")
    for cwe, count in sorted(report["by_cwe"].items(), key=lambda x: -x[1]):
        print(f"    {cwe:30s}  {count:3d}")
    print()

    # Show top 10 findings with file:line
    print("  Top findings:")
    for f in report["findings"][:10]:
        print(f"    [{f['severity']:7s}] {f['file']}:{f['line']} — {f['cwe']}")
        if f["snippet"]:
            # Show first line of snippet, truncated
            first_line = f["snippet"].split("\n")[0][:72]
            print(f"             {first_line}")
    if report["total_findings"] > 10:
        print(f"    ... and {report['total_findings'] - 10} more")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SentryGrep: Run Semgrep with custom CWE-78 rules and parse results."
    )
    parser.add_argument(
        "--target", required=True,
        help="Path to the Go codebase to scan"
    )
    parser.add_argument(
        "--rules", default="rules",
        help="Path to custom rules directory (default: rules/)"
    )
    parser.add_argument(
        "--output", default="report.json",
        help="Output file for the JSON report (default: report.json)"
    )
    parser.add_argument(
        "--threshold", default="ERROR",
        choices=["ERROR", "WARNING", "INFO"],
        help="Fail (exit 1) if any finding meets or exceeds this severity"
    )

    args = parser.parse_args()

    # 1. Run Semgrep
    raw = run_semgrep(args.target, args.rules)

    # 2. Parse and structure results
    report = parse_results(raw)

    # 3. Output
    write_report(report, args.output)
    print_summary(report)

    # 4. Threshold check for CI — exit 1 if findings above threshold
    threshold_rank = SEVERITY_RANK[args.threshold]
    for finding in report["findings"]:
        if SEVERITY_RANK.get(finding["severity"], 0) >= threshold_rank:
            print(f"FAIL: {finding['severity']} finding exceeds threshold ({args.threshold})")
            sys.exit(1)

    print(f"PASS: No findings at or above {args.threshold} severity")
    sys.exit(0)


if __name__ == "__main__":
    main()
