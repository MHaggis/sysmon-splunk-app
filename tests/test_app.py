"""Static/fixture regression guards. These tests do not execute Splunk SPL."""
import hashlib
import fnmatch
from pathlib import Path
import re
import sys
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from package_app import package
from validate_app import ROOT, quotes_balanced, read_conf, validate


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = read_conf(ROOT / "default/savedsearches.conf")
        cls.props = read_conf(ROOT / "default/props.conf")

    def test_all_static_checks(self):
        errors, inventory = validate()
        self.assertEqual(errors, [])
        self.assertEqual(inventory["saved_searches"], 77)
        self.assertEqual(inventory["views"], 12)

    def test_selector_covers_formats_without_other_windows_channels(self):
        # Selector is deliberately restricted to ORs of exact field comparisons.
        selector = read_conf(ROOT / "default/macros.conf")["sysmon"]["definition"]
        clauses = re.findall(r'(source|sourcetype)="([^"]+)"', selector)
        remainder = re.sub(r'(source|sourcetype)="[^"]+"', '', selector)
        self.assertEqual(re.sub(r'OR|[()\s]', '', remainder), '')
        cases = [
            ({"source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "sourcetype": "XmlWinEventLog"}, True),
            ({"source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "sourcetype": "xmlwineventlog"}, True),
            ({"source": "WinEventLog:Microsoft-Windows-Sysmon/Operational", "sourcetype": "WinEventLog"}, True),
            ({"sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"}, True),
            ({"sourcetype": "WinEventLog:Microsoft-Windows-Sysmon/Operational"}, True),
            ({"sourcetype": "WinEventLog:Sysmon"}, True),
            ({"source": "XmlWinEventLog:Security", "sourcetype": "XmlWinEventLog"}, False),
            ({"source": "WinEventLog:System", "sourcetype": "WinEventLog"}, False),
            ({"source": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational", "sourcetype": "xmlwineventlog"}, False),
        ]
        for event, expected in cases:
            with self.subTest(event=event):
                self.assertEqual(any(event.get(key) == value for key, value in clauses), expected)

    def test_source_and_legacy_normalization_are_identical(self):
        definitions = [dict(self.props[section]) for section in self.props.sections()]
        self.assertEqual(len(definitions), 5)
        self.assertTrue(all(item == definitions[0] for item in definitions))

    def test_basename_regex_handles_paths_without_using_commandline(self):
        for section in self.props.sections():
            expression = self.props[section]["EVAL-sysmon_process_name"]
            match = re.fullmatch(r'replace\(Image, "(.*)", ""\)', expression)
            self.assertIsNotNone(match)
            # Decode one SPL string escaping layer; run the simple regex fixture
            # locally. PCRE/Splunk execution remains a separate release gate.
            pattern = match[1].replace('\\\\', '\\')
            for path, name in [
                (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe"),
                (r"C:\Program Files\Example\example.exe", "example.exe"),
                (r"\\server\share\cmd.exe", "cmd.exe"),
                ("powershell.exe", "powershell.exe"),
                ("C:/Windows/cmd.exe", "cmd.exe"),
            ]:
                self.assertEqual(re.sub(pattern, '', path), name)
            self.assertEqual(self.props[section]["EVAL-sysmon_process_path"], "Image")

    def test_computer_identity_cannot_fall_back_to_collector(self):
        for section in self.props.sections():
            self.assertEqual(self.props[section]["EVAL-sysmon_computer"], "coalesce(Computer, ComputerName)")

    def test_network_fallback_handles_missing_hostname(self):
        for section in self.props.sections():
            expression = self.props[section]["EVAL-sysmon_dest_host"]
            self.assertIn('nullif(nullif(DestinationHostname, "-"), "")', expression)
            self.assertIn('DestinationIp, DestinationIP', expression)
            self.assertIn('DestinationPort', self.props[section]["EVAL-sysmon_dest_port"])

    def test_field_conversion_preserves_detection_literals(self):
        self.assertIn('CommandLine="*process call create*"', self.saved["wmic - process call create"]["search"])
        self.assertIn('CommandLine="*process::*"', self.saved["mimikatz"]["search"])

    def test_basename_filters_do_not_compare_full_image_to_bare_exe(self):
        for name in self.saved.sections():
            query = self.saved[name]["search"]
            self.assertIsNone(re.search(r'\b(?:Image|ParentImage)=["\']?[\w.-]+\.exe(?:["\']|\s|$)', query), name)

    def test_critical_process_threshold_filters_aggregated_count(self):
        query = self.saved["IOC - >5 Critical Process in 10m"]["search"]
        self.assertRegex(query, r'\| stats .*count by sysmon_computer _time \| where count > 5$')
        self.assertNotRegex(query, r'(?<!!)ParentImage="')

    def test_rundll_browser_query_quote_is_closed(self):
        query = self.saved["IOC - Suspicious execution of rundll - User Profile/Browser"]["search"]
        self.assertTrue(quotes_balanced(query))
        self.assertTrue(query.endswith('Iexplore.exe*"'))
        self.assertFalse(quotes_balanced('ParentCommandLine="iexplore.exe\\"'))

    def test_suspicious_path_patterns_match_full_paths(self):
        query = self.saved["IOC - Suspicious Exe Path"]["search"]
        patterns = [pattern.replace('\\\\', '\\') for pattern in
                    re.findall(r'sysmon_process_path="([^"]+)"', query)]
        self.assertEqual(len(patterns), 8)
        for path, expected in [
            (r"C:\$Recycle.Bin\S-1-5-21\payload.exe", True),
            (r"D:\Users\All Users\payload.exe", True),
            (r"C:\Windows\System32\config\systemprofile\payload.exe", True),
            (r"C:\Windows\Fonts\payload.exe", True),
            (r"C:\Perflogs\payload.exe", True),
            (r"C:\Windows\System32\cmd.exe", False),
            (r"C:\Program Files\FontsTool\normal.exe", False),
        ]:
            with self.subTest(path=path):
                self.assertEqual(any(fnmatch.fnmatchcase(path.lower(), pattern.lower()) for pattern in patterns), expected)

    def test_optional_author_environment_dependencies_removed(self):
        text = (ROOT / "default/savedsearches.conf").read_text()
        self.assertNotIn("Splunk_ML_Toolkit", text)
        self.assertNotIn("securityanalytics_ar", text)

    def test_timeline_drilldown_keeps_input_and_detail_consistent(self):
        doc = ET.parse(ROOT / "default/data/ui/views/process_timeline.xml").getroot()
        condition = doc.find('.//drilldown/condition[@field="LogonGuid"]')
        self.assertIsNotNone(condition)
        tokens = {node.get('token') for node in condition.findall('set')}
        self.assertEqual(tokens, {'form.logsel', 'logsel'})
        self.assertIsNotNone(condition.find('unset[@token="procsel"]'))
        self.assertIsNotNone(doc.find('.//input[@token="logsel"]/change/unset[@token="procsel"]'))
        chart = doc.find('.//chart/search/query').text
        self.assertIn('useother=f usenull=f', chart)
        detail = doc.find('.//table[@id="detail"]/search/query').text
        self.assertIn('sysmon_process_name=$procsel|s$', detail)

    def test_short_filename_panel_reuses_normalized_basename(self):
        doc = ET.parse(ROOT / "default/data/ui/views/suspicious_indicators.xml").getroot()
        query = next(node.text for node in doc.findall('.//query') if 'file_length' in node.text)
        self.assertIn('eval filename=sysmon_process_name', query)
        self.assertNotIn('rex ', query)

    def test_packaging_is_repeatable_and_excludes_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = package(Path(tmp) / "one.tgz")
            second = package(Path(tmp) / "two.tgz")
            self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())
            with tarfile.open(first) as archive:
                names = archive.getnames()
                self.assertIn("sysmon-splunk-app/default/props.conf", names)
                self.assertIn("sysmon-splunk-app/default/savedsearches.conf", names)
                for name in names:
                    self.assertNotRegex(name, r'/(?:\.context|\.git|local|tests|scripts)/')
                    self.assertTrue(name.startswith("sysmon-splunk-app/"))


if __name__ == "__main__":
    unittest.main()
