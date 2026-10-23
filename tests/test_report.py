import os
import re
import tempfile
import unittest
import zipfile

from click.testing import CliRunner

import nessus_file_reader as nfr
from nessus_file_reader.__main__ import cli

try:
    import xlsxwriter  # noqa: F401

    XLSXWRITER_AVAILABLE = True
except ImportError:
    XLSXWRITER_AVAILABLE = False


NESSUS_FILE_CONTENT = """<?xml version="1.0" ?>
<NessusClientData_v2>
<Policy><policyName>test policy</policyName>
<Preferences><ServerPreferences>
<preference><name>TARGET</name><value>192.168.1.10</value></preference>
<preference><name>max_hosts</name><value>100</value></preference>
<preference><name>max_checks</name><value>5</value></preference>
<preference><name>checks_read_timeout</name><value>5</value></preference>
<preference><name>reverse_lookup</name><value>no</value></preference>
<preference><name>plugin_set</name><value>19506;11111</value></preference>
</ServerPreferences><PluginsPreferences></PluginsPreferences></Preferences>
</Policy>
<Report name="test scan">
<ReportHost name="192.168.1.10"><HostProperties>
<tag name="HOST_START">Mon Jan 15 10:00:00 2024</tag>
<tag name="HOST_END">Mon Jan 15 10:30:00 2024</tag>
<tag name="host-ip">192.168.1.10</tag>
<tag name="host-fqdn">test.example.com</tag>
<tag name="operating-system">Linux Kernel 5.15</tag>
<tag name="Credentialed_Scan">true</tag>
</HostProperties>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings">
<plugin_publication_date>2024/01/01</plugin_publication_date>
<plugin_modification_date>2024/01/02</plugin_modification_date>
<risk_factor>None</risk_factor>
<plugin_type>summary</plugin_type>
<plugin_output>Information about this scan :

Nessus version : 10.7.0
Plugin feed version : 202401150000
Scanner IP : 192.168.1.2
Credentialed checks : yes
Scan Start Date : 2024/1/15 10:00 UTC
Scan duration : 1800 sec
</plugin_output>
</ReportItem>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="3" pluginID="11111" pluginName="Test High Vulnerability" pluginFamily="General">
<plugin_publication_date>2024/01/01</plugin_publication_date>
<plugin_modification_date>2024/01/02</plugin_modification_date>
<risk_factor>High</risk_factor>
<plugin_type>remote</plugin_type>
<cvss3_base_score>7.5</cvss3_base_score>
<cve>CVE-2024-0001</cve>
<description>Test description.</description>
<solution>Upgrade.</solution>
<plugin_output>Test output.</plugin_output>
</ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="3" pluginID="21157" pluginName="Unix Compliance Checks" pluginFamily="Policy Compliance" xmlns:cm="http://www.nessus.org/cm">
<plugin_publication_date>2024/01/01</plugin_publication_date>
<plugin_modification_date>2024/01/02</plugin_modification_date>
<risk_factor>None</risk_factor>
<compliance>true</compliance>
<cm:compliance-check-name>1.1 Ensure test</cm:compliance-check-name>
<cm:compliance-result>FAILED</cm:compliance-result>
<cm:compliance-audit-file>test.audit</cm:compliance-audit-file>
</ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>
"""


def sheet_names(xlsx_path):
    with zipfile.ZipFile(xlsx_path) as xlsx:
        workbook_xml = xlsx.read("xl/workbook.xml").decode("utf-8")
    return re.findall(r'<sheet name="([^"]+)"', workbook_xml)


@unittest.skipUnless(XLSXWRITER_AVAILABLE, "XlsxWriter not installed")
class TestReport(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.source_dir = os.path.join(self.temp_dir.name, "scans")
        os.makedirs(self.source_dir)
        self.nessus_file = os.path.join(self.source_dir, "test.nessus")
        with open(self.nessus_file, "w", encoding="utf-8") as f:
            f.write(NESSUS_FILE_CONTENT)
        self.zip_file = os.path.join(self.source_dir, "test.zip")
        with zipfile.ZipFile(self.zip_file, "w") as z:
            z.write(self.nessus_file, "inside.nessus")
        self.output_dir = os.path.join(self.temp_dir.name, "out")

    def test_generate_xlsx_report_all_reports(self):
        output_path = os.path.join(self.temp_dir.name, "report.xlsx")
        result = nfr.report.generate_xlsx_report(
            [self.nessus_file, self.zip_file], output_path, log=lambda message: None
        )
        self.assertTrue(os.path.isfile(output_path))
        self.assertEqual(result["files_processed"], 2)
        self.assertEqual(result["files_with_errors"], 0)
        self.assertEqual(
            sheet_names(output_path),
            ["scans", "hosts", "vulnerabilities", "noncompliance"],
        )

    def test_generate_xlsx_report_zip_with_macos_metadata(self):
        zip_file = os.path.join(self.temp_dir.name, "folder.zip")
        with zipfile.ZipFile(zip_file, "w") as z:
            z.write(self.nessus_file, "folder/test.nessus")
            z.writestr("__MACOSX/folder/._test.nessus", b"\x00\x05\x16\x07binary")
            z.writestr("folder/._other.nessus", b"\x00\x05\x16\x07binary")
        result = nfr.report.generate_xlsx_report(
            [zip_file],
            os.path.join(self.temp_dir.name, "report.xlsx"),
            log=lambda message: None,
        )
        self.assertEqual(result["files_processed"], 1)
        self.assertEqual(result["files_with_errors"], 0)

    def test_generate_xlsx_report_selected_reports(self):
        output_path = os.path.join(self.temp_dir.name, "report.xlsx")
        nfr.report.generate_xlsx_report(
            [self.nessus_file],
            output_path,
            reports=["vulnerabilities"],
            debug_data=["vulnerabilities"],
            none_skip=True,
            log=lambda message: None,
        )
        self.assertEqual(sheet_names(output_path), ["vulnerabilities"])

    def test_generate_xlsx_report_debug_policy_numbers(self):
        output_path = os.path.join(self.temp_dir.name, "report.xlsx")
        nfr.report.generate_xlsx_report(
            [self.nessus_file],
            output_path,
            reports=["scans", "hosts"],
            debug_data=["scans", "hosts"],
            log=lambda message: None,
        )
        # Max hosts, Max checks, Network timeout columns per sheet
        for sheet_file, columns in [("sheet1.xml", "QRS"), ("sheet2.xml", "UVW")]:
            with zipfile.ZipFile(output_path) as xlsx:
                sheet_xml = xlsx.read(f"xl/worksheets/{sheet_file}").decode("utf-8")
            for column, value in zip(columns, [100, 5, 5]):
                self.assertIn(f'<c r="{column}2"><v>{value}</v></c>', sheet_xml)

    def test_generate_xlsx_report_none_skip_autofilter_range(self):
        output_path = os.path.join(self.temp_dir.name, "report.xlsx")
        for debug_data in [(), ["vulnerabilities"]]:
            nfr.report.generate_xlsx_report(
                [self.nessus_file],
                output_path,
                reports=["vulnerabilities"],
                debug_data=debug_data,
                none_skip=True,
                log=lambda message: None,
            )
            with zipfile.ZipFile(output_path) as xlsx:
                sheet_xml = xlsx.read("xl/worksheets/sheet1.xml").decode("utf-8")
            # header and the only vulnerability with risk factor other than None
            self.assertRegex(sheet_xml, r'<autoFilter ref="A1:[A-Z]+2"/>')

    def test_generate_xlsx_report_none_options_exclusive(self):
        with self.assertRaises(ValueError):
            nfr.report.generate_xlsx_report(
                [self.nessus_file],
                os.path.join(self.temp_dir.name, "report.xlsx"),
                none_filter_out=True,
                none_skip=True,
            )

    def test_cli_report_directory(self):
        result = CliRunner().invoke(
            cli,
            [
                "report",
                self.source_dir,
                "-o",
                self.output_dir,
                "--no-timestamp",
                "--suffix",
                "ci",
                "-q",
            ],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        expected_path = os.path.join(self.output_dir, "security_report_ci.xlsx")
        self.assertTrue(os.path.isfile(expected_path))
        self.assertEqual(result.stdout.strip(), expected_path)

    def test_cli_report_file_with_errors(self):
        broken_file = os.path.join(self.source_dir, "broken.nessus")
        with open(broken_file, "w", encoding="utf-8") as f:
            f.write("<NessusClientData_v2><Report>")
        result = CliRunner().invoke(
            cli, ["report", broken_file, "-o", self.output_dir, "-q"]
        )
        self.assertEqual(result.exit_code, 1)

    def test_cli_report_no_files(self):
        result = CliRunner().invoke(
            cli,
            [
                "report",
                os.path.join(self.temp_dir.name, "empty"),
                "-o",
                self.output_dir,
            ],
        )
        self.assertEqual(result.exit_code, 2)

    def test_cli_report_none_options_exclusive(self):
        result = CliRunner().invoke(
            cli, ["report", self.source_dir, "--none-filter-out", "--none-skip"]
        )
        self.assertEqual(result.exit_code, 2)


if __name__ == "__main__":
    unittest.main()
