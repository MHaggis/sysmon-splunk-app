"""Corrupted/changed report cases must fail the CI gate, even with exit code 0."""
from collections import Counter
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_appinspect import ROOT, STATES, ReportError, validate_report


class AppInspectGateTests(unittest.TestCase):
    def setUp(self):
        self.baseline = json.loads((ROOT / '.ci/appinspect-baseline.json').read_text())
        checks = []
        for name in self.baseline['required_checks']:
            accepted = self.baseline['accepted_findings'].get(name)
            check = {'name': name, 'result': 'success', 'messages': []}
            if accepted:
                check['result'] = accepted['result']
                check['messages'] = [{'result': m['result'], 'message_filename': m['file'],
                                      'message': m['text']} for m in accepted['messages']]
            checks.append(check)
        self.report = {'app_package_id': self.baseline['app_package_id'],
                       'run_parameters': {'appinspect_version': self.baseline['appinspect_version'],
                                          'checks': [], 'included_tags': [], 'excluded_tags': []},
                       'groups': [{'checks': checks}]}
        self.data = {'reports': [self.report]}
        self.recount()

    def recount(self):
        counts = Counter(c['result'] for g in self.report['groups'] for c in g['checks'])
        self.report['summary'] = {key: counts[key] for key in STATES}
        self.data['summary'] = dict(self.report['summary'])

    def check(self, name):
        return next(c for c in self.report['groups'][0]['checks'] if c['name'] == name)

    def reject(self):
        with self.assertRaises(ReportError):
            validate_report(self.data, self.baseline)

    def test_exact_reviewed_findings_pass(self):
        counts, visible = validate_report(self.data, self.baseline)
        self.assertEqual(counts['warning'], 2)
        self.assertEqual(counts['skipped'], 1)
        self.assertEqual(len(visible), 3)

    def test_check_failures_errors_and_future_failures_fail(self):
        original = copy.deepcopy(self.data)
        for result in ('failure', 'error', 'future_failure', 'manual_check', 'unknown'):
            with self.subTest(result=result):
                self.data = copy.deepcopy(original)
                self.report = self.data['reports'][0]
                self.report['groups'][0]['checks'][0]['result'] = result
                self.recount()
                self.reject()

    def test_hidden_failure_message_fails(self):
        self.report['groups'][0]['checks'][0]['messages'] = [
            {'result': 'failure', 'message': 'Hidden failure', 'message_filename': 'default/app.conf'}]
        self.reject()

    def test_new_warning_on_previously_passing_check_fails(self):
        self.report['groups'][0]['checks'][0].update(result='warning', messages=[])
        self.recount()
        self.reject()

    def test_new_message_in_known_warning_fails(self):
        check = self.check('check_props_conf_has_no_prohibited_characters_in_sourcetypes')
        check['messages'].append({'result': 'warning', 'message': 'Another bad sourcetype',
                                  'message_filename': 'default/props.conf'})
        self.reject()

    def test_removed_message_in_known_warning_fails(self):
        self.check('check_props_conf_has_no_prohibited_characters_in_sourcetypes')['messages'].pop()
        self.reject()

    def test_resolved_warning_requires_baseline_update(self):
        self.check('check_for_updates_disabled').update(result='success', messages=[])
        self.recount()
        self.reject()

    def test_same_message_on_different_file_fails(self):
        self.check('check_for_updates_disabled')['messages'][0]['message_filename'] = 'default/other.conf'
        self.reject()

    def test_source_line_movement_is_not_a_new_finding(self):
        self.check('check_for_updates_disabled')['messages'][0]['message'] += ' File: default/app.conf Line Number: 99'
        validate_report(self.data, self.baseline)

    def test_partial_inventory_fails_even_when_summaries_agree(self):
        self.report['groups'][0]['checks'].pop()
        self.recount()
        self.reject()

    def test_duplicate_check_fails(self):
        self.report['groups'][0]['checks'].append(copy.deepcopy(self.report['groups'][0]['checks'][0]))
        self.recount()
        self.reject()

    def test_empty_or_multiple_reports_fail(self):
        for reports in ([], [self.report, self.report]):
            with self.subTest(count=len(reports)):
                self.data['reports'] = reports
                self.reject()

    def test_wrong_app_or_appinspect_version_fails(self):
        self.report['app_package_id'] = 'other-app'
        self.reject()
        self.report['app_package_id'] = self.baseline['app_package_id']
        self.report['run_parameters']['appinspect_version'] = '99.0.0'
        self.reject()

    def test_filtered_run_fails(self):
        self.report['run_parameters']['excluded_tags'] = ['cloud']
        self.reject()

    def test_inconsistent_missing_or_boolean_summary_fails(self):
        original = dict(self.data['summary'])
        for bad in (dict(original, success=0), dict(original, error=False), {}):
            with self.subTest(summary=bad):
                self.data['summary'] = bad
                self.reject()

    def test_unknown_message_result_fails(self):
        self.check('check_for_updates_disabled')['messages'][0]['result'] = 'unknown'
        self.reject()

    def test_missing_or_invalid_json_file_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'report.json'
            for content in (None, '{bad json', '{}'):
                if content is not None:
                    path.write_text(content)
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/check_appinspect.py'), str(path)],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('FAILED', result.stderr)


if __name__ == '__main__':
    unittest.main()
