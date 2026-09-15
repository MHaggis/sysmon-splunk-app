#!/usr/bin/env python3
"""Static regression checks only: this is not a Splunk parser or runtime."""
import configparser
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def read_conf(path):
    text = path.read_text(encoding="utf-8-sig")
    # Splunk uses trailing backslashes for continuation, independent of indent.
    text = text.replace("\\\n", " ")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string(text)
    return parser


def quotes_balanced(query):
    quoted = escaped = False
    for character in query:
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
    return not quoted


def validate(root=ROOT):
    errors = []
    saved = read_conf(root / "default/savedsearches.conf")
    macros = read_conf(root / "default/macros.conf")
    props = read_conf(root / "default/props.conf")
    app = read_conf(root / "default/app.conf")
    selector = macros["sysmon"]["definition"]
    if "|" in selector or not (selector.startswith("(") and selector.endswith(")")):
        errors.append("sysmon must remain a parenthesized selector without a pipeline")
    if re.search(r'sourcetype\s*=\s*"?(?:xmlwineventlog|wineventlog)"?(?:\s|$|\))', selector, re.I):
        errors.append("generic Windows sourcetype may select unrelated logs")
    for stanza in props.sections():
        for key, expression in props[stanza].items():
            if not key.startswith("EVAL-sysmon_"):
                errors.append(f"props {stanza}: overriding native/CIM field: {key}")
            if re.search(r"\bsysmon_\w+\b", expression):
                errors.append(f"props {stanza}: calculated-field dependency: {key}")
    queries = []
    for name in saved.sections():
        stanza = saved[name]
        if "search" not in stanza:
            continue
        queries.append((name, stanza["search"]))
        if not stanza.get("dispatch.earliest_time") or not stanza.get("dispatch.latest_time"):
            errors.append(f"{name}: missing explicit search time bound")
    views = list((root / "default/data/ui/views").glob("*.xml"))
    for path in views:
        doc = ET.parse(path).getroot()
        if doc.get("version") != "1.1":
            errors.append(f"{path.name}: Simple XML version must be 1.1")
        for query in doc.findall(".//query"):
            queries.append((path.name, query.text or ""))
        for search in doc.findall(".//search"):
            if search.get("ref") and search.get("ref") not in saved:
                errors.append(f"{path.name}: missing saved-search reference {search.get('ref')}")
        for fieldset in doc.findall("fieldset"):
            if fieldset.get("autoRun") != "true":
                errors.append(f"{path.name}: form must initialize default inputs")
        for time_input in doc.findall(".//input[@type='time']"):
            if time_input.get("searchWhenChanged") != "true":
                errors.append(f"{path.name}: time picker does not trigger searches")
    for name, query in queries:
        if not quotes_balanced(query):
            errors.append(f"{name}: unbalanced SPL double quotes")
        if "ComputerNameName" in query or re.search(r"\bDestinationIP\b", query):
            errors.append(f"{name}: incorrect native field spelling")
        # Ignore quoted literal values: process::* is valid detection content.
        terms = re.sub(r'"(?:\\.|[^"\\])*"', '""', query)
        if re.search(r"\b(?:Computer|ComputerName|process|dest_host|dest_ip|dest_port|src_host|protocol|user)\b", terms):
            errors.append(f"{name}: query still uses an ambiguous legacy field")
    version = app["launcher"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version):
        errors.append("app version is not semantic versioning")
    if app["id"].get("name") != "sysmon-splunk-app" or app["id"].get("version") != version:
        errors.append("app identity/version mismatch")
    return errors, {"views": len(views), "saved_searches": len(saved.sections()), "queries": len(queries)}


if __name__ == "__main__":
    failures, inventory = validate()
    print(inventory)
    for failure in failures:
        print("FAIL:", failure)
    print("Static checks: " + ("FAIL" if failures else "PASS (SPL/runtime not exercised)"))
    sys.exit(bool(failures))
