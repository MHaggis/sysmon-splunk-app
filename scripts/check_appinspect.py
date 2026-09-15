#!/usr/bin/env python3
"""Fail closed on incomplete AppInspect reports and unreviewed findings."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
STATES = {"success", "not_applicable", "warning", "skipped", "failure", "error", "future_failure"}
BLOCKING = {"failure", "error", "future_failure"}


class ReportError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ReportError(message)


def fingerprint(message):
    require(isinstance(message, dict), "Invalid check message")
    require(message.get("result") in STATES, "Missing or unknown message result")
    require(isinstance(message.get("message"), str), "Missing message text")
    # Line numbers move as the app changes. Keep the full finding text and the
    # affected file; ignore only AppInspect's appended file/line display suffix.
    return {"result": message["result"], "file": message.get("message_filename"),
            "text": re.sub(r" File: .*$", "", message["message"])}


def validate_report(data, baseline):
    require(isinstance(data, dict), "Report must be an object")
    reports = data.get("reports")
    require(isinstance(reports, list) and len(reports) == 1, "Expected exactly one app report")
    report = reports[0]
    require(isinstance(report, dict), "Invalid app report")
    require(report.get("app_package_id") == baseline["app_package_id"], "Wrong app package identity")
    parameters = report.get("run_parameters", {})
    require(parameters.get("appinspect_version") == baseline["appinspect_version"], "Unreviewed AppInspect version")
    for key in ("checks", "included_tags", "excluded_tags"):
        require(parameters.get(key) == [], "Filtered or incomplete AppInspect run: " + key)
    groups = report.get("groups")
    require(isinstance(groups, list) and groups, "Missing check groups")
    checks = []
    for group in groups:
        require(isinstance(group, dict) and isinstance(group.get("checks"), list), "Invalid check group")
        checks.extend(group["checks"])
    require(checks and all(isinstance(c, dict) for c in checks), "Missing or invalid checks")
    names = [c.get("name") for c in checks]
    require(all(isinstance(n, str) and n for n in names), "Missing check name")
    require(len(names) == len(set(names)), "Duplicate check names")
    require(set(names) == set(baseline["required_checks"]), "Check inventory changed or incomplete; review the baseline")

    counts = Counter()
    visible = []
    observed_findings = set()
    for check in checks:
        name, result = check["name"], check.get("result")
        require(result in STATES, "Unknown result for " + repr(name))
        require(result not in BLOCKING, "Blocking AppInspect result: " + repr(name) + " / " + result)
        messages = check.get("messages")
        require(isinstance(messages, list), "Missing messages for " + repr(name))
        messages = [fingerprint(m) for m in messages]
        require(not any(m["result"] in BLOCKING for m in messages), "Blocking message inside " + repr(name))
        if result in ("warning", "skipped"):
            observed_findings.add(name)
            accepted = baseline["accepted_findings"].get(name)
            require(accepted and accepted["result"] == result, "Unreviewed finding: " + repr(name))
            require(messages, "Non-passing check has no diagnostic messages: " + repr(name))
            # Require the exact reviewed diagnostics. A missing message can be
            # truncation; a resolved warning also deserves a baseline update.
            allowed = Counter(json.dumps(m, sort_keys=True) for m in accepted["messages"])
            observed = Counter(json.dumps(m, sort_keys=True) for m in messages)
            require(observed == allowed, "New, changed or missing finding in " + repr(name))
            visible.append((name, result, accepted["reason"]))
        else:
            require(all(m["result"] == result for m in messages), "Hidden non-passing message in " + repr(name))
        counts[result] += 1

    require(observed_findings == set(baseline["accepted_findings"]), "Finding inventory changed; review the baseline")

    for summary in (report.get("summary"), data.get("summary")):
        require(isinstance(summary, dict) and set(summary) == STATES, "Invalid summary schema")
        require(all(type(v) is int and v >= 0 for v in summary.values()), "Invalid summary count")
        require(all(summary[k] == counts[k] for k in STATES), "Summary disagrees with check results")
    require(counts["success"] > 0, "No checks succeeded")
    return dict(counts), visible


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--baseline", type=Path, default=ROOT / ".ci/appinspect-baseline.json")
    parser.add_argument("--summary-file", type=Path)
    args = parser.parse_args()
    try:
        counts, visible = validate_report(json.loads(args.report.read_text()), json.loads(args.baseline.read_text()))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print("AppInspect gate FAILED: " + str(error), file=sys.stderr)
        return 1
    lines = ["## AppInspect gate: PASS with reviewed exceptions", "",
             json.dumps(counts, sort_keys=True), ""]
    for name, result, reason in visible:
        lines.append(f"- `{name}` ({result}): {reason}")
    lines += ["", "Static package evidence only; Splunk runtime and Cloud approval remain separate gates.", ""]
    text = "\n".join(lines)
    print(text)
    if args.summary_file:
        with args.summary_file.open("a") as output:
            output.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
