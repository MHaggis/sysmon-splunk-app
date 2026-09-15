#!/usr/bin/env python3
"""Emit read-only makeresults checks using actual shipped EVAL expressions.

Paste each generated search into Splunk. Zero result rows means that fixture
passed. This checks SPL expressions, not add-on extraction or props scoping.
"""
import json
from pathlib import Path
from validate_app import ROOT, read_conf


def spl_string(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def generate():
    fixtures = json.loads((ROOT / 'tests/fixtures/normalization.json').read_text())
    props = read_conf(ROOT / 'default/props.conf')
    expressions = props[props.sections()[0]]
    searches = []
    for fixture in fixtures:
        query = '| makeresults\n| eval ' + ', '.join(
            key + '=' + spl_string(value) for key, value in fixture['fields'].items())
        query += '\n| eval ' + ', '.join(key.removeprefix('EVAL-') + '=' + expr for key, expr in expressions.items())
        failures = []
        for key, expected in fixture['expected'].items():
            failures.append('isnotnull(' + key + ')' if expected is None else
                            '(isnull(' + key + ') OR ' + key + '!=' + spl_string(expected) + ')')
        query += '\n| where ' + ' OR '.join(failures)
        query += '\n| eval failed_fixture=' + spl_string(fixture['name'])
        query += '\n| table failed_fixture sysmon_*\n'
        searches.append({'name': fixture['name'], 'expected_rows': 0, 'search': query})
    return searches


if __name__ == '__main__':
    output = ROOT / '.context/review/splunk-normalization-checks.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(generate(), indent=2) + '\n')
    print(output)
