# -*- coding: utf-8 -*-
"""
LimberDuck NFR (nessus file reader) (pronounced *ˈlɪm.bɚ dʌk*) is a python module
created to quickly parse nessus files containing the results of scans
performed by using Nessus by (C) Tenable, Inc.
Copyright (C) 2019 Damian Krawczyk

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import fnmatch
import time
import traceback
import zipfile
from nessus_file_reader.file import file
from nessus_file_reader.host import host
from nessus_file_reader.plugin import plugin
from nessus_file_reader.scan import scan

REPORT_TYPES = ("scans", "hosts", "vulnerabilities", "noncompliance")


def generate_xlsx_report(
    source_files,
    output_path,
    reports=REPORT_TYPES,
    debug_data=(),
    none_filter_out=False,
    none_skip=False,
    log=print,
):
    """
    Function creates xlsx workbook with selected reports for given nessus files.
    Reports are the same as in LimberDuck NFA (nessus file analyzer).
    Requires XlsxWriter: pip install nessus-file-reader[xlsx]
    :param source_files: list of *.nessus files or *.zip files containing *.nessus files
    :param output_path: path of xlsx file to create
    :param reports: report types to generate, any of REPORT_TYPES
    :param debug_data: report types for which additional debug columns are added
    :param none_filter_out: filter out vulnerabilities with risk factor None in Excel
    :param none_skip: skip vulnerabilities with risk factor None
    :param log: function called with log messages
    :return: dictionary with output path, number of processed files and files with errors
    """
    try:
        import xlsxwriter
    except ImportError as e:
        raise ImportError(
            "XlsxWriter is required to generate xlsx reports. "
            "Install it with: pip install nessus-file-reader[xlsx]"
        ) from e

    if none_filter_out and none_skip:
        raise ValueError("none_filter_out and none_skip are mutually exclusive")

    options = {
        f"{report_type}_debug_data": report_type in debug_data
        for report_type in REPORT_TYPES
    }
    options["none_filter_out"] = none_filter_out
    options["none_skip"] = none_skip

    worksheet_creators = {
        "scans": create_worksheet_for_scans,
        "hosts": create_worksheet_for_hosts,
        "vulnerabilities": create_worksheet_for_vulnerabilities,
        "noncompliance": create_worksheet_for_noncompliance,
    }

    workbook = xlsxwriter.Workbook(output_path, {"constant_memory": True})
    workbook.use_zip64()
    workbook.set_properties(
        {
            "title": "Security report",
            "subject": "Vulnerability Assessment results",
            "category": "Report",
            "keywords": "Vulnerabilities, VA, VM, Nessus",
            "comments": "Report generated with LimberDuck NFR (nessus file reader). "
            "Check https://limberduck.org for more details.",
        }
    )

    files_processed = 0
    files_with_errors = 0
    try:
        for report_type in REPORT_TYPES:
            if report_type in reports:
                processed, errors = worksheet_creators[report_type](
                    workbook, source_files, options, log
                )
                files_processed = max(files_processed, processed)
                files_with_errors = max(files_with_errors, errors)
    finally:
        workbook.close()

    return {
        "output_path": output_path,
        "files_processed": files_processed,
        "files_with_errors": files_with_errors,
    }


def _log(log, action_name, source_file_name, additional_info=""):
    """
    Function passes information about parsing progress to given log function.
    :param log: function called with log message
    :param action_name: information about action name
    :param source_file_name: information about related source file
    :param additional_info: add more information if needed
    """
    log(
        f"[action={action_name}] [source_file_name={source_file_name}] {additional_info}"
    )


def _nessus_files_in_source(scan_file):
    """
    Function returns nessus files to parse from given source file.
    :param scan_file: *.nessus file or *.zip file containing *.nessus files
    :return: source file type, list of nessus files, opened zip file or None
    """
    source_file_type = ""
    files_to_pars = []
    zip_source = None
    if fnmatch.fnmatch(scan_file, "*.nessus"):
        files_to_pars.append(scan_file)
        source_file_type = "nessus"
    elif fnmatch.fnmatch(scan_file, "*.zip"):
        source_file_type = "zip"
        zip_source = zipfile.ZipFile(scan_file)
        for zip_file in zip_source.namelist():
            # skip macOS metadata added when folder is compressed in Finder
            if zip_file.startswith("__MACOSX/") or zip_file.rsplit("/", 1)[
                -1
            ].startswith("._"):
                continue
            if fnmatch.fnmatch(zip_file, "*.nessus"):
                files_to_pars.append(zip_file)
    return source_file_type, files_to_pars, zip_source


def _number_or_value(value):
    """
    Function converts given value to number to write it in xlsx as number.
    :param value: value to convert, e.g. policy setting
    :return: int or float if value is numeric, otherwise given value
    """
    for number_type in (int, float):
        try:
            return number_type(value)
        except (TypeError, ValueError):
            pass
    return value


def create_worksheet_for_scans(workbook, list_of_source_files, options, log=print):
    """
    Function create spreadsheet with scan sum-up in given workbook for selected files.
    :param workbook: workbook where spreadsheet are created
    :param list_of_source_files: list of selected files
    """
    report_name = "scans"

    worksheet = workbook.add_worksheet(report_name)

    cell_format_bold = workbook.add_format({"bold": True})
    worksheet.set_row(0, None, cell_format_bold)

    # print('>>>>>>>>>>>>>>>> ', options["scans_debug_data"])

    if not options["scans_debug_data"]:
        headers = [
            "Target hosts",
            "Target hosts (without duplicates)",
            "Scanned hosts",
            "Scanned hosts with credentialed checks",
            "Unreachable hosts",
            "Scan started",
            "Scan ended",
            "Elapsed time per scan",
            "Login used",
            "DB SID",
            "DB port",
            "ALL plugins",
            "Critical plugins",
            "High plugins",
            "Medium plugins",
            "Low plugins",
            "None plugins",
            "ALL compliance",
            "Passed compliance",
            "Failed compliance",
            "Warning compliance",
        ]
    else:
        headers = [
            "Nessus scan name",
            "Nessus file name",
            "nessus file size",
            "Target hosts",
            "Target hosts (without duplicates)",
            "Scanned hosts",
            "Scanned hosts with credentialed checks",
            "Unreachable hosts",
            "Scan started",
            "Scan ended",
            "Elapsed time per scan",
            "Policy name",
            "Login used",
            "DB SID",
            "DB port",
            "Reverse lookup",
            "Max hosts",
            "Max checks",
            "Network timeout",
            "Used plugins",
            "ALL plugins",
            "Critical plugins",
            "High plugins",
            "Medium plugins",
            "Low plugins",
            "None plugins",
            "ALL compliance",
            "Passed compliance",
            "Failed compliance",
            "Warning compliance",
        ]

    number_of_columns = len(headers)
    # print('Number of columns: ' + str(number_of_columns))

    worksheet.set_column(0, number_of_columns - 1, 18)

    debug_columns_list = [0, 1, 2, 11, 15, 16, 17, 18, 19]

    for column_index, header in enumerate(headers):
        if options["scans_debug_data"] and column_index in debug_columns_list:
            cell_format_bold_blue = workbook.add_format()
            cell_format_bold_blue.set_bold()
            cell_format_bold_blue.set_font_color("blue")
            worksheet.write(0, column_index, header, cell_format_bold_blue)
        else:
            worksheet.write(0, column_index, header)

    worksheet.freeze_panes(1, 0)  # Freeze the first row.

    nessus_scan_file_number = 0
    number_of_files_with_errors = 0

    number_of_rows = 0
    row_index = 0
    for scan_file in list_of_source_files:
        source_file_type, files_to_pars, zip_source = _nessus_files_in_source(scan_file)

        for file_to_pars in files_to_pars:
            # print(row_index, number_of_rows, nessus_scan_file_number)
            row_index += 1
            number_of_rows += 1
            nessus_scan_file_number += 1

            try:
                file_to_pars_full_name = ""
                source_file_size = 0
                if source_file_type == "nessus":
                    root = file.nessus_scan_file_root_element(file_to_pars)
                    scan_file_source = scan.scan_file_source(root)
                    file_to_pars_full_name = file.nessus_scan_file_name_with_path(
                        file_to_pars
                    )
                    source_file_size = file.nessus_scan_file_size_human(
                        file_to_pars_full_name
                    )
                elif source_file_type == "zip":
                    source_file_size = file.nessus_scan_file_inside_zip_size_human(
                        zip_source, file_to_pars
                    )
                    file_to_pars_full_name = (
                        f"{file.nessus_scan_file_name_with_path(scan_file)} "
                        f"[{zip_source.getinfo(file_to_pars).filename}]"
                    )
                    file_to_pars = zip_source.open(file_to_pars)
                    root = file.nessus_scan_file_root_element(file_to_pars)
                    scan_file_source = scan.scan_file_source(root)

                start_time = time.time()
                _log(log, "start", file_to_pars_full_name)

                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[scan_file_source={scan_file_source}]",
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[source_file_size={source_file_size}]",
                )
                _log(
                    log, "info ", file_to_pars_full_name, f"[report_type={report_name}]"
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[number_of_target_hosts={scan.number_of_target_hosts(root)}]",
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[number_of_scanned_hosts={scan.number_of_scanned_hosts(root)}]",
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[number_of_scanned_hosts_with_credentials="
                    f"{scan.number_of_scanned_hosts_with_credentialed_checks_yes(root)}]",
                )

                date_format = workbook.add_format({"num_format": "yyyy-mm-dd hh:mm:ss"})

                login_used = None
                number_of_plugins = 0
                number_of_plugins_critical = 0
                number_of_plugins_high = 0
                number_of_plugins_medium = 0
                number_of_plugins_low = 0
                number_of_plugins_none = 0
                number_of_compliance_plugins = 0
                number_of_compliance_plugins_passed = 0
                number_of_compliance_plugins_failed = 0
                number_of_compliance_plugins_warning = 0

                policy_max_hosts = _number_or_value(scan.policy_max_hosts(root))
                policy_max_checks = _number_or_value(scan.policy_max_checks(root))
                policy_checks_read_timeout = _number_or_value(
                    scan.policy_checks_read_timeout(root)
                )

                report_host_counter = 0
                number_of_report_hosts = scan.number_of_scanned_hosts(root)

                for report_host in scan.report_hosts(root):
                    report_host_counter += 1

                    login_used = host.login_used(report_host)

                    number_of_plugins += host.number_of_plugins(report_host)
                    number_of_plugins_critical += (
                        host.number_of_plugins_per_risk_factor(report_host, "Critical")
                    )
                    number_of_plugins_high += host.number_of_plugins_per_risk_factor(
                        report_host, "High"
                    )
                    number_of_plugins_medium += host.number_of_plugins_per_risk_factor(
                        report_host, "Medium"
                    )
                    number_of_plugins_low += host.number_of_plugins_per_risk_factor(
                        report_host, "Low"
                    )
                    number_of_plugins_none += host.number_of_plugins_per_risk_factor(
                        report_host, "None"
                    )
                    number_of_compliance_plugins += host.number_of_compliance_plugins(
                        report_host
                    )
                    number_of_compliance_plugins_passed += (
                        host.number_of_compliance_plugins_per_result(
                            report_host, "PASSED"
                        )
                    )
                    number_of_compliance_plugins_failed += (
                        host.number_of_compliance_plugins_per_result(
                            report_host, "FAILED"
                        )
                    )
                    number_of_compliance_plugins_warning += (
                        host.number_of_compliance_plugins_per_result(
                            report_host, "WARNING"
                        )
                    )

                if not options["scans_debug_data"]:
                    worksheet.write(row_index, 0, scan.number_of_target_hosts(root))
                    worksheet.write(
                        row_index,
                        1,
                        scan.number_of_target_hosts_without_duplicates(root),
                    )
                    worksheet.write(row_index, 2, scan.number_of_scanned_hosts(root))
                    worksheet.write(
                        row_index,
                        3,
                        scan.number_of_scanned_hosts_with_credentialed_checks_yes(root),
                    )
                    worksheet.write(
                        row_index, 4, scan.number_of_not_scanned_hosts(root)
                    )

                    scan_start_time = scan.scan_time_start(root)
                    if scan_start_time is not None:
                        worksheet.write_datetime(
                            row_index, 5, scan_start_time, date_format
                        )
                    else:
                        worksheet.write_blank(row_index, 5, None)

                    scan_end_time = scan.scan_time_end(root)
                    if scan_end_time is not None:
                        worksheet.write_datetime(
                            row_index, 6, scan_end_time, date_format
                        )
                    else:
                        worksheet.write_blank(row_index, 6, None)

                    worksheet.write(row_index, 7, scan.scan_time_elapsed(root))
                    worksheet.write(row_index, 8, login_used)
                    worksheet.write(row_index, 9, scan.policy_db_sid(root))
                    worksheet.write(row_index, 10, scan.policy_db_port(root))
                    worksheet.write(row_index, 11, number_of_plugins)
                    worksheet.write(row_index, 12, number_of_plugins_critical)
                    worksheet.write(row_index, 13, number_of_plugins_high)
                    worksheet.write(row_index, 14, number_of_plugins_medium)
                    worksheet.write(row_index, 15, number_of_plugins_low)
                    worksheet.write(row_index, 16, number_of_plugins_none)
                    worksheet.write(row_index, 17, number_of_compliance_plugins)
                    worksheet.write(row_index, 18, number_of_compliance_plugins_passed)
                    worksheet.write(row_index, 19, number_of_compliance_plugins_failed)
                    worksheet.write(row_index, 20, number_of_compliance_plugins_warning)
                else:
                    worksheet.write(row_index, 0, scan.report_name(root))
                    worksheet.write(row_index, 1, file_to_pars_full_name)
                    worksheet.write(row_index, 2, source_file_size)
                    worksheet.write(row_index, 3, scan.number_of_target_hosts(root))
                    worksheet.write(
                        row_index,
                        4,
                        scan.number_of_target_hosts_without_duplicates(root),
                    )
                    worksheet.write(row_index, 5, scan.number_of_scanned_hosts(root))
                    worksheet.write(
                        row_index,
                        6,
                        scan.number_of_scanned_hosts_with_credentialed_checks_yes(root),
                    )
                    worksheet.write(
                        row_index, 7, scan.number_of_not_scanned_hosts(root)
                    )

                    scan_start_time = scan.scan_time_start(root)
                    if scan_start_time is not None:
                        worksheet.write_datetime(
                            row_index, 8, scan_start_time, date_format
                        )
                    else:
                        worksheet.write_blank(row_index, 8, None)

                    scan_end_time = scan.scan_time_end(root)
                    if scan_end_time is not None:
                        worksheet.write_datetime(
                            row_index, 9, scan_end_time, date_format
                        )
                    else:
                        worksheet.write_blank(row_index, 9, None)

                    worksheet.write(row_index, 10, scan.scan_time_elapsed(root))
                    worksheet.write(row_index, 11, scan.policy_name(root))
                    worksheet.write(row_index, 12, login_used)
                    worksheet.write(row_index, 13, scan.policy_db_sid(root))
                    worksheet.write(row_index, 14, scan.policy_db_port(root))
                    worksheet.write(row_index, 15, scan.reverse_lookup(root))
                    worksheet.write(row_index, 16, policy_max_hosts)
                    worksheet.write(row_index, 17, policy_max_checks)
                    worksheet.write(row_index, 18, policy_checks_read_timeout)
                    worksheet.write(row_index, 19, scan.plugin_set_number(root))
                    worksheet.write(row_index, 20, number_of_plugins)
                    worksheet.write(row_index, 21, number_of_plugins_critical)
                    worksheet.write(row_index, 22, number_of_plugins_high)
                    worksheet.write(row_index, 23, number_of_plugins_medium)
                    worksheet.write(row_index, 24, number_of_plugins_low)
                    worksheet.write(row_index, 25, number_of_plugins_none)
                    worksheet.write(row_index, 26, number_of_compliance_plugins)
                    worksheet.write(row_index, 27, number_of_compliance_plugins_passed)
                    worksheet.write(row_index, 28, number_of_compliance_plugins_failed)
                    worksheet.write(row_index, 29, number_of_compliance_plugins_warning)

                end_time = time.time()
                elapsed_time = end_time - start_time
                elapsed_time_parsed = time.strftime(
                    "%H:%M:%S", time.gmtime(elapsed_time)
                )

                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[elapsed_time={elapsed_time_parsed}]",
                )
                _log(log, "end  ", file_to_pars_full_name)

            except Exception as e:
                number_of_files_with_errors += 1
                traceback.print_exc()
                _log(
                    log,
                    "info",
                    "ERROR Parsing ["
                    + str(nessus_scan_file_number)
                    + "/"
                    + str(len(list_of_source_files))
                    + "] nessus files",
                )
                _log(log, "info", e)

    if number_of_rows > 0:
        worksheet.autofilter(0, 0, number_of_rows, number_of_columns - 1)

    return nessus_scan_file_number, number_of_files_with_errors


def create_worksheet_for_hosts(workbook, list_of_source_files, options, log=print):
    """
    Function create spreadsheet with host sum-up in given workbook for selected files.
    :param workbook: workbook where spreadsheet are created
    :param list_of_source_files: list of selected files
    """
    report_name = "hosts"

    worksheet = workbook.add_worksheet(report_name)

    cell_format_bold = workbook.add_format({"bold": True})
    worksheet.set_row(0, None, cell_format_bold)

    # print('>>>>>>>>>>>>>>>> ', options["hosts_debug_data"])

    if not options["hosts_debug_data"]:
        headers = [
            # "Nessus scanner IP",
            # "Nessus scan name",
            # "Nessus file name",
            "Target",
            "Hostname",
            "FQDN",
            # "NetBIOS Computer name",
            # "NetBIOS Domain name",
            "IP",
            "Scanned",
            "Credentialed checks",
            "Scan started",
            "Scan ended",
            "Elapsed time per host",
            "Elapsed time per scan",
            # "Policy name",
            "Login used",
            "DB SID",
            "DB port",
            # "Max hosts",
            # "Max checks",
            # "Network timeout",
            "Operating System",
            "ALL plugins",
            "Critical plugins",
            "High plugins",
            "Medium plugins",
            "Low plugins",
            "None plugins",
            "ALL compliance",
            "Passed compliance",
            "Failed compliance",
            "Warning compliance",
            # "10180: Ping to remote host",
            # "10287: Traceroute Information",
            # "11936: OS Identification",
            # "45590: Common Platform Enumeration (CPE)",
            # "54615: Device Type",
            # "21745: Authentication Failure - Local Checks Not Run",
            # "12634: Authenticated Check : OS Name and Installed Package Enumeration",
            # "110385: Authentication Success Insufficient Access",
            # "102094: SSH Commands Require Privilege Escalation",
            # "10394: Microsoft Windows SMB Log In Possible",
            # "24786: Nessus Windows Scan Not Performed with Admin Privileges",
            # "24269: Windows Management Instrumentation (WMI) Available",
            # "11011: Microsoft Windows SMB Service Detection",
            # "10400: Microsoft Windows SMB Registry Remotely Accessible",
            # "26917: Microsoft Windows SMB Registry : Nessus Cannot Access the Windows Registry",
            # "42897: SMB Registry : Start the Registry Service during the scan (WMI)",
            # "20811: Microsoft Windows Installed Software Enumeration (credentialed check)",
            # "91825: Oracle DB Login Possible",
            # "91827: Microsoft SQL Server Login Possible",
            # "47864: Cisco IOS Version",
            # "67217: Cisco IOS XE Version"
        ]
    else:
        headers = [
            "Nessus scanner IP",
            "Nessus scan name",
            "Nessus file name",
            "Target",
            "Hostname",
            "FQDN",
            "NetBIOS Computer name",
            "NetBIOS Domain name",
            "IP",
            "Scanned",
            "Credentialed checks",
            "Scan started",
            "Scan ended",
            "Elapsed time per host",
            "Elapsed time per scan",
            "Policy name",
            "Login used",
            "DB SID",
            "DB port",
            "Reverse lookup",
            "Max hosts",
            "Max checks",
            "Network timeout",
            "Operating System",
            "ALL plugins",
            "Critical plugins",
            "High plugins",
            "Medium plugins",
            "Low plugins",
            "None plugins",
            "ALL compliance",
            "Passed compliance",
            "Failed compliance",
            "Warning compliance",
            "10180: Ping to remote host",
            "10287: Traceroute Information",
            "11936: OS Identification",
            "45590: Common Platform Enumeration (CPE)",
            "54615: Device Type",
            "21745: Authentication Failure - Local Checks Not Run",
            "12634: Authenticated Check : OS Name and Installed Package Enumeration",
            "110385: Authentication Success Insufficient Access",
            "102094: SSH Commands Require Privilege Escalation",
            "10394: Microsoft Windows SMB Log In Possible",
            "24786: Nessus Windows Scan Not Performed with Admin Privileges",
            "24269: Windows Management Instrumentation (WMI) Available",
            "11011: Microsoft Windows SMB Service Detection",
            "10400: Microsoft Windows SMB Registry Remotely Accessible",
            "26917: Microsoft Windows SMB Registry : Nessus Cannot Access the Windows Registry",
            "42897: SMB Registry : Start the Registry Service during the scan (WMI)",
            "20811: Microsoft Windows Installed Software Enumeration (credentialed check)",
            "91825: Oracle DB Login Possible",
            "91827: Microsoft SQL Server Login Possible",
            "47864: Cisco IOS Version",
            "67217: Cisco IOS XE Version",
        ]
    number_of_columns = len(headers)
    # print('Number of columns: ' + str(number_of_columns))

    worksheet.set_column(0, number_of_columns - 1, 18)

    debug_columns_list = [
        0,
        1,
        2,
        6,
        7,
        13,
        17,
        18,
        19,
        20,
        32,
        33,
        34,
        35,
        36,
        37,
        38,
        39,
        40,
        41,
        42,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        50,
        51,
        52,
    ]

    for column_index, header in enumerate(headers):
        if options["hosts_debug_data"] and column_index in debug_columns_list:
            cell_format_bold_blue = workbook.add_format()
            cell_format_bold_blue.set_bold()
            cell_format_bold_blue.set_font_color("blue")
            worksheet.write(0, column_index, header, cell_format_bold_blue)
        else:
            worksheet.write(0, column_index, header)

    worksheet.freeze_panes(1, 0)  # Freeze the first row.

    nessus_scan_file_number = 0
    number_of_files_with_errors = 0

    number_of_rows = 0
    row_index = 0
    row_index_per_file = 0
    for scan_file in list_of_source_files:
        source_file_type, files_to_pars, zip_source = _nessus_files_in_source(scan_file)

        for file_to_pars in files_to_pars:
            row_index_per_file += 1
            nessus_scan_file_number += 1

            try:
                file_to_pars_full_name = ""
                source_file_size = 0
                if source_file_type == "nessus":
                    root = file.nessus_scan_file_root_element(file_to_pars)
                    scan_file_source = scan.scan_file_source(root)
                    file_to_pars_full_name = file.nessus_scan_file_name_with_path(
                        file_to_pars
                    )
                    source_file_size = file.nessus_scan_file_size_human(
                        file_to_pars_full_name
                    )
                elif source_file_type == "zip":
                    source_file_size = file.nessus_scan_file_inside_zip_size_human(
                        zip_source, file_to_pars
                    )
                    file_to_pars_full_name = (
                        f"{file.nessus_scan_file_name_with_path(scan_file)} "
                        f"[{zip_source.getinfo(file_to_pars).filename}]"
                    )
                    file_to_pars = zip_source.open(file_to_pars)
                    root = file.nessus_scan_file_root_element(file_to_pars)
                    scan_file_source = scan.scan_file_source(root)

                start_time = time.time()
                _log(log, "start", file_to_pars_full_name)

                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[scan_file_source={scan_file_source}]",
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[source_file_size={source_file_size}]",
                )
                _log(
                    log, "info ", file_to_pars_full_name, f"[report_type={report_name}]"
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[number_of_target_hosts={scan.number_of_target_hosts(root)}]",
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[number_of_scanned_hosts={scan.number_of_scanned_hosts(root)}]",
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[number_of_scanned_hosts_with_credentials="
                    f"{scan.number_of_scanned_hosts_with_credentialed_checks_yes(root)}]",
                )

                date_format = workbook.add_format({"num_format": "yyyy-mm-dd hh:mm:ss"})
                policy_max_hosts = _number_or_value(scan.policy_max_hosts(root))
                policy_max_checks = _number_or_value(scan.policy_max_checks(root))
                policy_checks_read_timeout = _number_or_value(
                    scan.policy_checks_read_timeout(root)
                )
                scan_report_name = scan.report_name(root)
                nessus_scan_file_name_with_path = file.nessus_scan_file_name_with_path(
                    file_to_pars_full_name
                )
                scan_time_elapsed = scan.scan_time_elapsed(root)
                scan_policy_name = scan.policy_name(root)
                scan_policy_db_sid = scan.policy_db_sid(root)
                scan_policy_db_port = scan.policy_db_port(root)
                scan_reverse_lookup = scan.reverse_lookup(root)
                scan_policy_login_specified = scan.policy_login_specified(root)

                report_host_counter = 0
                number_of_report_hosts = scan.number_of_scanned_hosts(root)

                for report_host in scan.report_hosts(root):
                    # print(row_index, number_of_rows, nessus_scan_file_number)
                    row_index += 1
                    number_of_rows += 1

                    report_host_counter += 1

                    login_used = host.login_used(report_host)
                    if login_used is None:
                        login_used = scan_policy_login_specified

                    number_of_plugins = host.number_of_plugins(report_host)
                    number_of_plugins_critical = host.number_of_plugins_per_risk_factor(
                        report_host, "Critical"
                    )
                    number_of_plugins_high = host.number_of_plugins_per_risk_factor(
                        report_host, "High"
                    )
                    number_of_plugins_medium = host.number_of_plugins_per_risk_factor(
                        report_host, "Medium"
                    )
                    number_of_plugins_low = host.number_of_plugins_per_risk_factor(
                        report_host, "Low"
                    )
                    number_of_plugins_none = host.number_of_plugins_per_risk_factor(
                        report_host, "None"
                    )
                    number_of_compliance_plugins = host.number_of_compliance_plugins(
                        report_host
                    )
                    number_of_compliance_plugins_passed = (
                        host.number_of_compliance_plugins_per_result(
                            report_host, "PASSED"
                        )
                    )
                    number_of_compliance_plugins_failed = (
                        host.number_of_compliance_plugins_per_result(
                            report_host, "FAILED"
                        )
                    )
                    number_of_compliance_plugins_warning = (
                        host.number_of_compliance_plugins_per_result(
                            report_host, "WARNING"
                        )
                    )
                    if not options["hosts_debug_data"]:
                        worksheet.write(
                            row_index, 0, host.report_host_name(report_host)
                        )
                        worksheet.write(
                            row_index, 1, host.resolved_hostname(report_host)
                        )
                        worksheet.write(row_index, 2, host.resolved_fqdn(report_host))
                        worksheet.write(row_index, 3, host.resolved_ip(report_host))
                        worksheet.write(row_index, 4, "yes")
                        worksheet.write(
                            row_index,
                            5,
                            host.credentialed_checks(root, report_host),
                        )

                        host_start_time = host.host_time_start(report_host)
                        if host_start_time is not None:
                            worksheet.write_datetime(
                                row_index, 6, host_start_time, date_format
                            )
                        else:
                            worksheet.write_blank(row_index, 6, None)

                        host_end_time = host.host_time_end(report_host)
                        if host_end_time is not None:
                            worksheet.write_datetime(
                                row_index, 7, host_end_time, date_format
                            )
                        else:
                            worksheet.write_blank(row_index, 7, None)

                        worksheet.write(
                            row_index, 8, host.host_time_elapsed(report_host)
                        )
                        worksheet.write(row_index, 9, scan_time_elapsed)
                        worksheet.write(row_index, 10, login_used)
                        worksheet.write(row_index, 11, scan_policy_db_sid)
                        worksheet.write(row_index, 12, scan_policy_db_port)
                        worksheet.write(row_index, 13, host.detected_os(report_host))
                        worksheet.write(row_index, 14, number_of_plugins)
                        worksheet.write(row_index, 15, number_of_plugins_critical)
                        worksheet.write(row_index, 16, number_of_plugins_high)
                        worksheet.write(row_index, 17, number_of_plugins_medium)
                        worksheet.write(row_index, 18, number_of_plugins_low)
                        worksheet.write(row_index, 19, number_of_plugins_none)
                        worksheet.write(row_index, 20, number_of_compliance_plugins)
                        worksheet.write(
                            row_index, 21, number_of_compliance_plugins_passed
                        )
                        worksheet.write(
                            row_index, 22, number_of_compliance_plugins_failed
                        )
                        worksheet.write(
                            row_index, 23, number_of_compliance_plugins_warning
                        )

                    else:
                        worksheet.write(
                            row_index, 0, host.scanner_ip(root, report_host)
                        )
                        worksheet.write(row_index, 1, scan_report_name)
                        worksheet.write(row_index, 2, nessus_scan_file_name_with_path)
                        worksheet.write(
                            row_index, 3, host.report_host_name(report_host)
                        )
                        worksheet.write(
                            row_index, 4, host.resolved_hostname(report_host)
                        )
                        worksheet.write(row_index, 5, host.resolved_fqdn(report_host))
                        worksheet.write(
                            row_index,
                            6,
                            host.netbios_network_name(root, report_host)[
                                "netbios_computer_name"
                            ],
                        )
                        worksheet.write(
                            row_index,
                            7,
                            host.netbios_network_name(root, report_host)[
                                "netbios_domain_name"
                            ],
                        )
                        worksheet.write(row_index, 8, host.resolved_ip(report_host))
                        worksheet.write(row_index, 9, "yes")
                        worksheet.write(
                            row_index,
                            10,
                            host.credentialed_checks(root, report_host),
                        )

                        host_start_time = host.host_time_start(report_host)
                        if host_start_time is not None:
                            worksheet.write_datetime(
                                row_index, 11, host_start_time, date_format
                            )
                        else:
                            worksheet.write_blank(row_index, 11, None)

                        host_end_time = host.host_time_end(report_host)
                        if host_end_time is not None:
                            worksheet.write_datetime(
                                row_index, 12, host_end_time, date_format
                            )
                        else:
                            worksheet.write_blank(row_index, 12, None)

                        worksheet.write(
                            row_index, 13, host.host_time_elapsed(report_host)
                        )
                        worksheet.write(row_index, 14, scan_time_elapsed)
                        worksheet.write(row_index, 15, scan_policy_name)
                        worksheet.write(row_index, 16, login_used)
                        worksheet.write(row_index, 17, scan_policy_db_sid)
                        worksheet.write(row_index, 18, scan_policy_db_port)
                        worksheet.write(row_index, 19, scan_reverse_lookup)
                        worksheet.write(row_index, 20, policy_max_hosts)
                        worksheet.write(row_index, 21, policy_max_checks)
                        worksheet.write(row_index, 22, policy_checks_read_timeout)
                        worksheet.write(row_index, 23, host.detected_os(report_host))
                        worksheet.write(row_index, 24, number_of_plugins)
                        worksheet.write(row_index, 25, number_of_plugins_critical)
                        worksheet.write(row_index, 26, number_of_plugins_high)
                        worksheet.write(row_index, 27, number_of_plugins_medium)
                        worksheet.write(row_index, 28, number_of_plugins_low)
                        worksheet.write(row_index, 29, number_of_plugins_none)
                        worksheet.write(row_index, 30, number_of_compliance_plugins)
                        worksheet.write(
                            row_index, 31, number_of_compliance_plugins_passed
                        )
                        worksheet.write(
                            row_index, 32, number_of_compliance_plugins_failed
                        )
                        worksheet.write(
                            row_index, 33, number_of_compliance_plugins_warning
                        )
                        # '10180: Ping to remote host'
                        worksheet.write(
                            row_index,
                            34,
                            plugin.plugin_output(root, report_host, "10180"),
                        )
                        # '10287: Traceroute Information'
                        worksheet.write(
                            row_index,
                            35,
                            plugin.plugin_output(root, report_host, "10287"),
                        )
                        # '11936: OS Identification'
                        worksheet.write(
                            row_index,
                            36,
                            plugin.plugin_output(root, report_host, "11936"),
                        )
                        # '45590: Common Platform Enumeration (CPE)'
                        worksheet.write(
                            row_index,
                            37,
                            plugin.plugin_output(root, report_host, "45590"),
                        )
                        # '54615: Device Type'
                        worksheet.write(
                            row_index,
                            38,
                            plugin.plugin_output(root, report_host, "54615"),
                        )
                        # '21745: Authentication Failure - Local Checks Not Run'
                        worksheet.write(
                            row_index,
                            39,
                            plugin.plugin_output(root, report_host, "21745"),
                        )
                        # '12634: Authenticated Check : OS Name and Installed Package Enumeration'
                        worksheet.write(
                            row_index,
                            40,
                            plugin.plugin_output(root, report_host, "12634"),
                        )
                        # '110385: Authentication Success Insufficient Access'
                        worksheet.write(
                            row_index,
                            41,
                            plugin.plugin_output(root, report_host, "110385"),
                        )
                        # '102094: SSH Commands Require Privilege Escalation'
                        worksheet.write(
                            row_index,
                            42,
                            plugin.plugin_output(root, report_host, "102094"),
                        )
                        # '10394: Microsoft Windows SMB Log In Possible'
                        worksheet.write(
                            row_index,
                            43,
                            plugin.plugin_output(root, report_host, "10394"),
                        )
                        # '24786: Nessus Windows Scan Not Performed with Admin Privileges'
                        worksheet.write(
                            row_index,
                            44,
                            plugin.plugin_output(root, report_host, "24786"),
                        )
                        # '24269: Windows Management Instrumentation (WMI) Available'
                        worksheet.write(
                            row_index,
                            45,
                            plugin.plugin_output(root, report_host, "24269"),
                        )
                        # '11011: Microsoft Windows SMB Service Detection'
                        worksheet.write(
                            row_index,
                            46,
                            plugin.plugin_outputs(root, report_host, "11011"),
                        )
                        # '10400: Microsoft Windows SMB Registry Remotely Accessible'
                        worksheet.write(
                            row_index,
                            47,
                            plugin.plugin_output(root, report_host, "10400"),
                        )
                        # '26917: Microsoft Windows SMB Registry : Nessus Cannot Access the Windows Registry'
                        worksheet.write(
                            row_index,
                            48,
                            plugin.plugin_output(root, report_host, "26917"),
                        )
                        # '42897: SMB Registry : Start the Registry Service during the scan (WMI)'
                        worksheet.write(
                            row_index,
                            49,
                            plugin.plugin_output(root, report_host, "42897"),
                        )
                        # '20811: Microsoft Windows Installed Software Enumeration (credentialed check)'
                        worksheet.write(
                            row_index,
                            50,
                            plugin.plugin_output(root, report_host, "20811"),
                        )
                        # '91825: Oracle DB Login Possible'
                        worksheet.write(
                            row_index,
                            51,
                            plugin.plugin_output(root, report_host, "91825"),
                        )
                        # '91827: Microsoft SQL Server Login Possible'
                        worksheet.write(
                            row_index,
                            52,
                            plugin.plugin_output(root, report_host, "91827"),
                        )
                        # '47864: Cisco IOS Version'
                        worksheet.write(
                            row_index,
                            53,
                            plugin.plugin_output(root, report_host, "47864"),
                        )
                        # '67217: Cisco IOS XE Version'
                        worksheet.write(
                            row_index,
                            54,
                            plugin.plugin_output(root, report_host, "67217"),
                        )

                number_of_not_scanned_hosts = scan.number_of_not_scanned_hosts(root)
                if number_of_not_scanned_hosts is not None:
                    if number_of_not_scanned_hosts > 0:
                        not_scanned_hosts = scan.list_of_not_scanned_hosts(root)
                        not_scanned_host_counter = 0

                        file_source = scan.scan_file_source(root)
                        if file_source == "Tenable.sc":
                            targets_sc = scan.list_of_target_hosts_sc_fqdn_ip(root)

                            for target in not_scanned_hosts:
                                row_index += 1
                                not_scanned_host_counter += 1

                                target_fqdn = ""
                                target_hostname = ""
                                target_ip = ""
                                for target_sc in targets_sc:
                                    if target == target_sc["target_fqdn"]:
                                        target_fqdn = target_sc["target_fqdn"]
                                        target_hostname = target_fqdn.split(".")[0]
                                        target_ip = target_sc["target_ip"]

                                if not options["hosts_debug_data"]:
                                    worksheet.write(row_index, 0, target)
                                    worksheet.write(row_index, 1, target_hostname)
                                    worksheet.write(row_index, 2, target_fqdn)
                                    worksheet.write(row_index, 3, target_ip)
                                    worksheet.write(row_index, 4, "no")
                                    worksheet.write(row_index, 5, "no")
                                    worksheet.write_blank(row_index, 6, None)
                                    worksheet.write_blank(row_index, 7, None)
                                    worksheet.write(row_index, 8, "0:00:00")
                                    worksheet.write(row_index, 9, scan_time_elapsed)
                                    worksheet.write(
                                        row_index, 10, scan_policy_login_specified
                                    )
                                    worksheet.write(row_index, 11, scan_policy_db_sid)
                                    worksheet.write(row_index, 12, scan_policy_db_port)
                                    worksheet.write_blank(row_index, 13, None)
                                    worksheet.write_blank(row_index, 14, None)
                                    worksheet.write_blank(row_index, 15, None)
                                    worksheet.write_blank(row_index, 16, None)
                                    worksheet.write_blank(row_index, 17, None)
                                    worksheet.write_blank(row_index, 18, None)
                                    worksheet.write_blank(row_index, 19, None)
                                    worksheet.write_blank(row_index, 20, None)
                                    worksheet.write_blank(row_index, 21, None)
                                    worksheet.write_blank(row_index, 22, None)
                                else:
                                    # worksheet.write_blank(row_index, 0, None)
                                    worksheet.write(row_index, 1, scan_report_name)
                                    worksheet.write(
                                        row_index,
                                        2,
                                        nessus_scan_file_name_with_path,
                                    )
                                    worksheet.write(row_index, 3, target)
                                    worksheet.write(row_index, 4, target_hostname)
                                    worksheet.write(row_index, 5, target_fqdn)
                                    # worksheet.write_blank(row_index, 6, None)
                                    # worksheet.write_blank(row_index, 7, None)
                                    worksheet.write(row_index, 8, target_ip)
                                    worksheet.write(row_index, 9, "no")
                                    worksheet.write(row_index, 10, "no")
                                    # worksheet.write_blank(row_index, 11, None)
                                    # worksheet.write_blank(row_index, 12, None)
                                    worksheet.write(row_index, 13, "0:00:00")
                                    worksheet.write(row_index, 14, scan_time_elapsed)
                                    worksheet.write(row_index, 15, scan_policy_name)
                                    worksheet.write(
                                        row_index, 16, scan_policy_login_specified
                                    )
                                    worksheet.write(row_index, 17, scan_policy_db_sid)
                                    worksheet.write(row_index, 18, scan_policy_db_port)
                                    worksheet.write(row_index, 19, scan_reverse_lookup)
                                    worksheet.write(row_index, 20, policy_max_hosts)
                                    worksheet.write(row_index, 21, policy_max_checks)
                                    # worksheet.write_blank(row_index, 22, None)
                                    # worksheet.write_blank(row_index, 23, None)
                                    # worksheet.write_blank(row_index, 24, None)
                                    # worksheet.write_blank(row_index, 25, None)
                                    # worksheet.write_blank(row_index, 26, None)
                                    # worksheet.write_blank(row_index, 27, None)
                                    # worksheet.write_blank(row_index, 28, None)
                                    # worksheet.write_blank(row_index, 29, None)
                                    # worksheet.write_blank(row_index, 30, None)
                                    # worksheet.write_blank(row_index, 31, None)
                                    # worksheet.write_blank(row_index, 32, None)
                                    # # '10180: Ping to remote host'
                                    # worksheet.write_blank(row_index, 33, None)
                                    # # '10287: Traceroute Information'
                                    # worksheet.write_blank(row_index, 34, None)
                                    # # '11936: OS Identification'
                                    # worksheet.write_blank(row_index, 35, None)
                                    # # '45590: Common Platform Enumeration (CPE)'
                                    # worksheet.write_blank(row_index, 36, None)
                                    # # '54615: Device Type'
                                    # worksheet.write_blank(row_index, 37, None)
                                    # # '21745: Authentication Failure - Local Checks Not Run'
                                    # worksheet.write_blank(row_index, 38, None)
                                    # # '12634: Authenticated Check : OS Name and Installed Package Enumeration'
                                    # worksheet.write_blank(row_index, 39, None)
                                    # # '110385: Authentication Success Insufficient Access'
                                    # worksheet.write_blank(row_index, 40, None)
                                    # # '102094: SSH Commands Require Privilege Escalation'
                                    # worksheet.write_blank(row_index, 41, None)
                                    # # '10394: Microsoft Windows SMB Log In Possible'
                                    # worksheet.write_blank(row_index, 42, None)
                                    # # '24786: Nessus Windows Scan Not Performed with Admin Privileges'
                                    # worksheet.write_blank(row_index, 43, None)
                                    # # '24269: Windows Management Instrumentation (WMI) Available'
                                    # worksheet.write_blank(row_index, 44, None)
                                    # # '11011: Microsoft Windows SMB Service Detection'
                                    # worksheet.write_blank(row_index, 45, None)
                                    # # '10400: Microsoft Windows SMB Registry Remotely Accessible'
                                    # worksheet.write_blank(row_index, 46, None)
                                    # # '26917: Microsoft Windows SMB Registry :
                                    # # Nessus Cannot Access the Windows Registry'
                                    # worksheet.write_blank(row_index, 47, None)
                                    # # '42897: SMB Registry : Start the Registry Service during the scan (WMI)'
                                    # worksheet.write_blank(row_index, 48, None)
                                    # # '20811: Microsoft Windows Installed Software Enumeration (credentialed check)'
                                    # worksheet.write_blank(row_index, 49, None)
                                    # # '91825: Oracle DB Login Possible'
                                    # worksheet.write_blank(row_index, 50, None)
                                    # # '91827: Microsoft SQL Server Login Possible'
                                    # worksheet.write_blank(row_index, 51, None)
                                    # # '47864: Cisco IOS Version'
                                    # worksheet.write_blank(row_index, 52, None)
                                    # # '67217: Cisco IOS XE Version'
                                    # worksheet.write_blank(row_index, 53, None)

                        else:
                            for target in not_scanned_hosts:
                                row_index += 1
                                not_scanned_host_counter += 1

                                if not options["hosts_debug_data"]:
                                    worksheet.write(row_index, 0, target)
                                    worksheet.write_blank(row_index, 1, None)
                                    worksheet.write_blank(row_index, 2, None)
                                    worksheet.write_blank(row_index, 3, None)
                                    worksheet.write(row_index, 4, "no")
                                    worksheet.write(row_index, 5, "no")
                                    worksheet.write_blank(row_index, 6, None)
                                    worksheet.write_blank(row_index, 7, None)
                                    worksheet.write(row_index, 8, "0:00:00")
                                    worksheet.write(row_index, 9, scan_time_elapsed)
                                    worksheet.write(
                                        row_index, 10, scan_policy_login_specified
                                    )
                                    worksheet.write(row_index, 11, scan_policy_db_sid)
                                    worksheet.write(row_index, 12, scan_policy_db_port)
                                    worksheet.write_blank(row_index, 13, None)
                                    worksheet.write_blank(row_index, 14, None)
                                    worksheet.write_blank(row_index, 15, None)
                                    worksheet.write_blank(row_index, 16, None)
                                    worksheet.write_blank(row_index, 17, None)
                                    worksheet.write_blank(row_index, 18, None)
                                    worksheet.write_blank(row_index, 19, None)
                                    worksheet.write_blank(row_index, 20, None)
                                    worksheet.write_blank(row_index, 21, None)
                                    worksheet.write_blank(row_index, 22, None)
                                else:
                                    # worksheet.write_blank(row_index, 0, None)
                                    worksheet.write(row_index, 1, scan_report_name)
                                    worksheet.write(
                                        row_index,
                                        2,
                                        nessus_scan_file_name_with_path,
                                    )
                                    worksheet.write(row_index, 3, target)
                                    # worksheet.write_blank(row_index, 4, None)
                                    # worksheet.write_blank(row_index, 5, None)
                                    # worksheet.write_blank(row_index, 6, None)
                                    # worksheet.write_blank(row_index, 7, None)
                                    # worksheet.write_blank(row_index, 8, None)
                                    worksheet.write(row_index, 9, "no")
                                    worksheet.write(row_index, 10, "no")
                                    # worksheet.write_blank(row_index, 11, None)
                                    # worksheet.write_blank(row_index, 12, None)
                                    worksheet.write(row_index, 13, "0:00:00")
                                    worksheet.write(row_index, 14, scan_time_elapsed)
                                    worksheet.write(row_index, 15, scan_policy_name)
                                    worksheet.write(
                                        row_index, 16, scan_policy_login_specified
                                    )
                                    worksheet.write(row_index, 17, scan_policy_db_sid)
                                    worksheet.write(row_index, 18, scan_policy_db_port)
                                    worksheet.write(row_index, 19, scan_reverse_lookup)
                                    worksheet.write(row_index, 20, policy_max_hosts)
                                    worksheet.write(row_index, 21, policy_max_checks)
                                    # worksheet.write_blank(row_index, 22, None)
                                    # worksheet.write_blank(row_index, 23, None)
                                    # worksheet.write_blank(row_index, 24, None)
                                    # worksheet.write_blank(row_index, 25, None)
                                    # worksheet.write_blank(row_index, 26, None)
                                    # worksheet.write_blank(row_index, 27, None)
                                    # worksheet.write_blank(row_index, 28, None)
                                    # worksheet.write_blank(row_index, 29, None)
                                    # worksheet.write_blank(row_index, 30, None)
                                    # worksheet.write_blank(row_index, 31, None)
                                    # worksheet.write_blank(row_index, 32, None)
                                    # # '10180: Ping to remote host'
                                    # worksheet.write_blank(row_index, 33, None)
                                    # # '10287: Traceroute Information'
                                    # worksheet.write_blank(row_index, 34, None)
                                    # # '11936: OS Identification'
                                    # worksheet.write_blank(row_index, 35, None)
                                    # # '45590: Common Platform Enumeration (CPE)'
                                    # worksheet.write_blank(row_index, 36, None)
                                    # # '54615: Device Type'
                                    # worksheet.write_blank(row_index, 37, None)
                                    # # '21745: Authentication Failure - Local Checks Not Run'
                                    # worksheet.write_blank(row_index, 38, None)
                                    # # '12634: Authenticated Check : OS Name and Installed Package Enumeration'
                                    # worksheet.write_blank(row_index, 39, None)
                                    # # '110385: Authentication Success Insufficient Access'
                                    # worksheet.write_blank(row_index, 40, None)
                                    # # '102094: SSH Commands Require Privilege Escalation'
                                    # worksheet.write_blank(row_index, 41, None)
                                    # # '10394: Microsoft Windows SMB Log In Possible'
                                    # worksheet.write_blank(row_index, 42, None)
                                    # # '24786: Nessus Windows Scan Not Performed with Admin Privileges'
                                    # worksheet.write_blank(row_index, 43, None)
                                    # # '24269: Windows Management Instrumentation (WMI) Available'
                                    # worksheet.write_blank(row_index, 44, None)
                                    # # '11011: Microsoft Windows SMB Service Detection'
                                    # worksheet.write_blank(row_index, 45, None)
                                    # # '10400: Microsoft Windows SMB Registry Remotely Accessible'
                                    # worksheet.write_blank(row_index, 46, None)
                                    # # '26917: Microsoft Windows SMB Registry :
                                    # # Nessus Cannot Access the Windows Registry'
                                    # worksheet.write_blank(row_index, 47, None)
                                    # # '42897: SMB Registry : Start the Registry Service during the scan (WMI)'
                                    # worksheet.write_blank(row_index, 48, None)
                                    # # '20811: Microsoft Windows Installed Software Enumeration (credentialed check)'
                                    # worksheet.write_blank(row_index, 49, None)
                                    # # '91825: Oracle DB Login Possible'
                                    # worksheet.write_blank(row_index, 50, None)
                                    # # '91827: Microsoft SQL Server Login Possible'
                                    # worksheet.write_blank(row_index, 51, None)
                                    # # '47864: Cisco IOS Version'
                                    # worksheet.write_blank(row_index, 52, None)
                                    # # '67217: Cisco IOS XE Version'
                                    # worksheet.write_blank(row_index, 53, None)

                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    elapsed_time_parsed = time.strftime(
                        "%H:%M:%S", time.gmtime(elapsed_time)
                    )

                    _log(
                        log,
                        "info ",
                        file_to_pars_full_name,
                        f"[elapsed_time={elapsed_time_parsed}]",
                    )
                    _log(log, "end  ", file_to_pars_full_name)

            except Exception as e:
                number_of_files_with_errors += 1
                traceback.print_exc()
                _log(
                    log,
                    "info",
                    "ERROR Parsing ["
                    + str(nessus_scan_file_number)
                    + "/"
                    + str(len(list_of_source_files))
                    + "] nessus files",
                )
                _log(log, "info", e)

    if number_of_rows > 0:
        worksheet.autofilter(0, 0, number_of_rows, number_of_columns - 1)

    return nessus_scan_file_number, number_of_files_with_errors


def create_worksheet_for_vulnerabilities(
    workbook, list_of_source_files, options, log=print
):
    """
    Function create spreadsheet with vulnerabilities sum-up in given workbook for selected files.
    :param workbook: workbook where spreadsheet are created
    :param list_of_source_files: list of selected files
    """

    sheet_index = 1
    row_index = 0
    rows_in_current_sheet = 0

    MAX_ROWS = 1_048_576
    HEADER_ROWS = 1

    report_name = "vulnerabilities"

    worksheet = workbook.add_worksheet(f"{report_name}")

    cell_format_bold = workbook.add_format({"bold": True})
    worksheet.set_row(0, None, cell_format_bold)

    # print('>>>>>>>>>>>>>>>> ', options["vulnerabilities_debug_data"])

    if not options["vulnerabilities_debug_data"]:
        headers = [
            # "Nessus scanner IP",
            # "Nessus scan name",
            # "Nessus file name",
            "Target",
            "Hostname",
            "FQDN",
            "IP",
            "Scanned",
            "Credentialed checks",
            # "Policy name",
            "Protocol",
            "Service Name",
            "Port",
            "Plugin ID",
            "Plugin name",
            "Plugin type",
            # "Severity Number",
            "Severity",
            "Risk Factor",
            # "CVSSv2 Base Score",
            "CVSSv2",
            # "CVSSv3 Base Score",
            "CVSSv3",
            # "CVSSv4 Base Score",
            "CVSSv4",
            # "VPR Score",
            "VPR",
            # "EPSS",
            "EPSS %",
            "Plugin family",
            # "Plugin file name",
            "Plugin version",
            "Plugin publication date",
            "Plugin modification date",
            "Plugin description",
            "Solution",
            "Plugin output",
            "CVE counter",
            "CVE number",
            "Exploit available",
            "Exploit code maturity",
            "Exploit framework metasploit",
            "Exploitability ease",
        ]
    else:
        headers = [
            "Nessus scanner IP",
            "Nessus scan name",
            "Nessus file name",
            "Target",
            "Hostname",
            "FQDN",
            "IP",
            "Scanned",
            "Credentialed checks",
            "Policy name",
            "Protocol",
            "Service Name",
            "Port",
            "Plugin ID",
            "Plugin name",
            "Plugin type",
            "Severity Number",
            "Severity",
            "Risk Factor",
            "CVSSv2 Base Score",
            "CVSSv2",
            "CVSSv3 Base Score",
            "CVSSv3",
            "CVSSv4 Base Score",
            "CVSSv4",
            "VPR Score",
            "VPR",
            "EPSS",
            "EPSS %",
            "Plugin family",
            "Plugin file name",
            "Plugin version",
            "Plugin publication date",
            "Plugin modification date",
            "Plugin description",
            "Solution",
            "Plugin output",
            "CVE counter",
            "CVE number",
            "Exploit available",
            "Exploit code maturity",
            "Exploit framework metasploit",
            "Exploitability ease",
        ]

    number_of_columns = len(headers)
    # print('Number of columns: ' + str(number_of_columns))

    worksheet.set_column(0, number_of_columns - 1, 18)

    debug_columns_list = [0, 1, 2, 9, 16, 19, 21, 23, 25, 27, 30]

    for column_index, header in enumerate(headers):
        if options["vulnerabilities_debug_data"] and column_index in debug_columns_list:
            cell_format_bold_blue = workbook.add_format()
            cell_format_bold_blue.set_bold()
            cell_format_bold_blue.set_font_color("blue")
            worksheet.write(0, column_index, header, cell_format_bold_blue)
        else:
            worksheet.write(0, column_index, header)

    worksheet.freeze_panes(1, 0)  # Freeze the first row.

    nessus_scan_file_number = 0
    number_of_files_with_errors = 0

    number_of_rows = 0
    row_index = 0
    row_index_per_file = 0
    for scan_file in list_of_source_files:
        source_file_type, files_to_pars, zip_source = _nessus_files_in_source(scan_file)

        for file_to_pars in files_to_pars:
            row_index_per_file += 1
            nessus_scan_file_number = nessus_scan_file_number + 1

            try:
                file_to_pars_full_name = ""
                source_file_size = 0
                if source_file_type == "nessus":
                    root = file.nessus_scan_file_root_element(file_to_pars)
                    scan_file_source = scan.scan_file_source(root)
                    file_to_pars_full_name = file.nessus_scan_file_name_with_path(
                        file_to_pars
                    )
                    source_file_size = file.nessus_scan_file_size_human(
                        file_to_pars_full_name
                    )
                elif source_file_type == "zip":
                    source_file_size = file.nessus_scan_file_inside_zip_size_human(
                        zip_source, file_to_pars
                    )
                    file_to_pars_full_name = (
                        f"{file.nessus_scan_file_name_with_path(scan_file)} ["
                        f"{zip_source.getinfo(file_to_pars).filename}]"
                    )
                    file_to_pars = zip_source.open(file_to_pars)
                    root = file.nessus_scan_file_root_element(file_to_pars)
                    scan_file_source = scan.scan_file_source(root)

                start_time = time.time()
                _log(log, "start", file_to_pars_full_name)

                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[scan_file_source={scan_file_source}]",
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[source_file_size={source_file_size}]",
                )
                _log(
                    log, "info ", file_to_pars_full_name, f"[report_type={report_name}]"
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[number_of_target_hosts={scan.number_of_target_hosts(root)}]",
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[number_of_scanned_hosts={scan.number_of_scanned_hosts(root)}]",
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[number_of_scanned_hosts_with_credentials="
                    f"{scan.number_of_scanned_hosts_with_credentialed_checks_yes(root)}]",
                )

                date_format = workbook.add_format({"num_format": "yyyy-mm-dd"})

                scan_report_name = scan.report_name(root)
                nessus_scan_file_name_with_path = file.nessus_scan_file_name_with_path(
                    file_to_pars_full_name
                )
                scan_policy_name = scan.policy_name(root)

                report_host_counter = 0
                number_of_report_hosts = scan.number_of_scanned_hosts(root)

                for report_host in scan.report_hosts(root):

                    report_host_counter += 1

                    report_items_per_host = host.report_items(report_host)

                    host_scanner_ip = host.scanner_ip(root, report_host)
                    host_report_host_name = host.report_host_name(report_host)
                    host_resolved_hostname = host.resolved_hostname(report_host)
                    host_resolved_fqdn = host.resolved_fqdn(report_host)
                    host_resolved_ip = host.resolved_ip(report_host)
                    host_credentialed_checks = host.credentialed_checks(
                        root, report_host
                    )

                    for report_item in report_items_per_host:
                        if row_index >= MAX_ROWS - HEADER_ROWS:
                            # Apply autofilter to the completed worksheet before creating a new one
                            if rows_in_current_sheet > 0:
                                worksheet.autofilter(
                                    0, 0, rows_in_current_sheet, number_of_columns - 1
                                )

                                if options["none_filter_out"]:
                                    risk_factors = ["Critical", "High", "Medium", "Low"]
                                    if not options["vulnerabilities_debug_data"]:
                                        worksheet.filter_column_list(12, risk_factors)
                                    else:
                                        worksheet.filter_column_list(16, risk_factors)

                            sheet_index += 1
                            worksheet = workbook.add_worksheet(
                                f"{report_name}_{sheet_index}"
                            )
                            row_index = 0  # Reset for the new sheet
                            rows_in_current_sheet = 0  # Reset row counter for new sheet

                            # Apply header formatting and freeze panes for new sheet
                            worksheet.set_row(0, None, cell_format_bold)
                            worksheet.set_column(0, number_of_columns - 1, 18)

                            # Write headers to new sheet
                            for column_index, header in enumerate(headers):
                                if (
                                    options["vulnerabilities_debug_data"]
                                    and column_index in debug_columns_list
                                ):
                                    cell_format_bold_blue = workbook.add_format()
                                    cell_format_bold_blue.set_bold()
                                    cell_format_bold_blue.set_font_color("blue")
                                    worksheet.write(
                                        0, column_index, header, cell_format_bold_blue
                                    )
                                else:
                                    worksheet.write(0, column_index, header)

                            worksheet.freeze_panes(1, 0)  # Freeze the first row

                        number_of_rows += 1
                        row_index += 1
                        rows_in_current_sheet = row_index

                        protocol = plugin.report_item_value(report_item, "protocol")
                        service_name = plugin.report_item_value(report_item, "svc_name")
                        port = int(plugin.report_item_value(report_item, "port"))
                        plugin_id = int(
                            plugin.report_item_value(report_item, "pluginID")
                        )
                        plugin_name = plugin.report_item_value(
                            report_item, "pluginName"
                        )
                        plugin_type = plugin.report_item_value(
                            report_item, "plugin_type"
                        )
                        severity = plugin.report_item_value(report_item, "severity")
                        severity_label = plugin.severity_number_to_label(severity)
                        risk_factor = plugin.report_item_value(
                            report_item, "risk_factor"
                        )
                        cvssv2_base_score = plugin.report_item_value(
                            report_item, "cvss_base_score"
                        )
                        cvssv2_base_score_label = plugin.cvssv2_score_to_severity(
                            cvssv2_base_score
                        )
                        cvssv3_base_score = plugin.report_item_value(
                            report_item, "cvss3_base_score"
                        )
                        cvssv3_base_score_label = plugin.cvssv3_score_to_severity(
                            cvssv3_base_score
                        )
                        cvssv4_base_score = plugin.report_item_value(
                            report_item, "cvss4_base_score"
                        )
                        cvssv4_base_score_label = plugin.cvssv4_score_to_severity(
                            cvssv4_base_score
                        )
                        vpr_score = plugin.report_item_value(report_item, "vpr_score")
                        vpr_score_label = plugin.vpr_score_to_severity(vpr_score)
                        epss_score = plugin.report_item_value(report_item, "epss_score")
                        epss_score_percent = plugin.epss_score_decimal_to_percent(
                            epss_score
                        )
                        plugin_family = plugin.report_item_value(
                            report_item, "pluginFamily"
                        )
                        plugin_file_name = plugin.report_item_value(
                            report_item, "fname"
                        )
                        plugin_version = plugin.report_item_value(
                            report_item, "script_version"
                        )
                        plugin_publication_date = plugin.report_item_value(
                            report_item, "plugin_publication_date"
                        )
                        plugin_modification_date = plugin.report_item_value(
                            report_item, "plugin_modification_date"
                        )
                        plugin_description = plugin.report_item_value(
                            report_item, "description"
                        )
                        solution = plugin.report_item_value(report_item, "solution")
                        plugin_output = plugin.report_item_value(
                            report_item, "plugin_output"
                        )
                        plugin_cves = plugin.report_item_values(report_item, "cve")
                        exploit_available = plugin.report_item_value(
                            report_item, "exploit_available"
                        )
                        exploit_code_maturity = plugin.report_item_value(
                            report_item, "exploit_code_maturity"
                        )
                        exploit_framework_metasploit = plugin.report_item_value(
                            report_item, "exploit_framework_metasploit"
                        )
                        exploitability_ease = plugin.report_item_value(
                            report_item, "exploitability_ease"
                        )

                        if (
                            not options["vulnerabilities_debug_data"]
                            and not options["none_skip"]
                        ):
                            worksheet.set_column("E:G", 10)
                            worksheet.set_column("I:I", 7)
                            worksheet.set_column("J:J", 10)
                            worksheet.set_column("L:L", 12)
                            worksheet.set_column("M:S", 10)
                            worksheet.set_column("V:W", 10)
                            worksheet.set_column("AA:AA", 13)
                            worksheet.write(row_index, 0, host_report_host_name)
                            worksheet.write(row_index, 1, host_resolved_hostname)
                            worksheet.write(row_index, 2, host_resolved_fqdn)
                            worksheet.write(row_index, 3, host_resolved_ip)
                            worksheet.write(row_index, 4, "yes")
                            worksheet.write(row_index, 5, host_credentialed_checks)
                            worksheet.write(row_index, 6, protocol)
                            worksheet.write(row_index, 7, service_name)
                            worksheet.write(row_index, 8, port)
                            worksheet.write(row_index, 9, plugin_id)
                            worksheet.write(row_index, 10, plugin_name)
                            worksheet.write(row_index, 11, plugin_type)
                            if options["none_filter_out"]:
                                if risk_factor == "None":
                                    worksheet.set_row(
                                        row_index, options={"hidden": True}
                                    )

                            worksheet.write(row_index, 12, severity_label)
                            worksheet.write(row_index, 13, risk_factor)
                            worksheet.write(row_index, 14, cvssv2_base_score_label)
                            worksheet.write(row_index, 15, cvssv3_base_score_label)
                            worksheet.write(row_index, 16, cvssv4_base_score_label)
                            worksheet.write(row_index, 17, vpr_score_label)
                            if epss_score is not None:
                                percent_format = workbook.add_format(
                                    {"num_format": "0.0%"}
                                )
                                worksheet.write_number(
                                    row_index, 18, float(epss_score), percent_format
                                )
                            else:
                                worksheet.write_blank(row_index, 18, None)

                            worksheet.write(row_index, 19, plugin_family)
                            worksheet.write(row_index, 20, plugin_version)
                            if plugin_publication_date is not None:
                                worksheet.write_datetime(
                                    row_index,
                                    21,
                                    plugin.plugin_date(plugin_publication_date),
                                    date_format,
                                )
                            else:
                                worksheet.write_blank(row_index, 21, None)
                            if plugin_modification_date is not None:
                                worksheet.write_datetime(
                                    row_index,
                                    22,
                                    plugin.plugin_date(plugin_modification_date),
                                    date_format,
                                )
                            else:
                                worksheet.write_blank(row_index, 22, None)
                            worksheet.write(row_index, 23, plugin_description)
                            worksheet.write(row_index, 24, solution)
                            if plugin_output is not None:
                                worksheet.write_string(row_index, 25, plugin_output)
                            else:
                                worksheet.write_blank(row_index, 25, None)
                            if plugin_cves:
                                worksheet.write_number(row_index, 26, len(plugin_cves))
                                worksheet.write_string(
                                    row_index, 27, ",".join(plugin_cves)
                                )
                            else:
                                worksheet.write_number(row_index, 26, 0)
                                worksheet.write_blank(row_index, 27, None)
                            if exploit_available is not None:
                                worksheet.write_string(row_index, 28, exploit_available)
                            else:
                                worksheet.write_blank(row_index, 28, None)
                            if exploit_code_maturity is not None:
                                worksheet.write_string(
                                    row_index, 29, exploit_code_maturity
                                )
                            else:
                                worksheet.write_blank(row_index, 29, None)
                            if exploit_framework_metasploit is not None:
                                worksheet.write_string(
                                    row_index, 30, exploit_framework_metasploit
                                )
                            else:
                                worksheet.write_blank(row_index, 30, None)
                            if exploitability_ease is not None:
                                worksheet.write_string(
                                    row_index, 31, exploitability_ease
                                )
                            else:
                                worksheet.write_blank(row_index, 31, None)
                        elif (
                            not options["vulnerabilities_debug_data"]
                            and options["none_skip"]
                        ):
                            if risk_factor == "None":
                                number_of_rows -= 1
                                row_index -= 1
                                rows_in_current_sheet = row_index
                            elif risk_factor != "None":
                                worksheet.set_column("E:G", 10)
                                worksheet.set_column("I:I", 7)
                                worksheet.set_column("J:J", 10)
                                worksheet.set_column("L:L", 12)
                                worksheet.set_column("M:S", 10)
                                worksheet.set_column("V:W", 10)
                                worksheet.set_column("AA:AA", 13)
                                worksheet.write(row_index, 0, host_report_host_name)
                                worksheet.write(row_index, 1, host_resolved_hostname)
                                worksheet.write(row_index, 2, host_resolved_fqdn)
                                worksheet.write(row_index, 3, host_resolved_ip)
                                worksheet.write(row_index, 4, "yes")
                                worksheet.write(row_index, 5, host_credentialed_checks)
                                worksheet.write(row_index, 6, protocol)
                                worksheet.write(row_index, 7, service_name)
                                worksheet.write(row_index, 8, port)
                                worksheet.write(row_index, 9, plugin_id)
                                worksheet.write(row_index, 10, plugin_name)
                                worksheet.write(row_index, 11, plugin_type)

                                worksheet.write(row_index, 12, severity_label)
                                worksheet.write(row_index, 13, risk_factor)
                                worksheet.write(row_index, 14, cvssv2_base_score_label)
                                worksheet.write(row_index, 15, cvssv3_base_score_label)
                                worksheet.write(row_index, 16, cvssv4_base_score_label)
                                worksheet.write(row_index, 17, vpr_score_label)
                                if epss_score is not None:
                                    percent_format = workbook.add_format(
                                        {"num_format": "0.0%"}
                                    )
                                    worksheet.write_number(
                                        row_index,
                                        18,
                                        float(epss_score),
                                        percent_format,
                                    )
                                else:
                                    worksheet.write_blank(row_index, 18, None)

                                worksheet.write(row_index, 19, plugin_family)
                                worksheet.write(row_index, 20, plugin_version)
                                if plugin_publication_date is not None:
                                    worksheet.write_datetime(
                                        row_index,
                                        21,
                                        plugin.plugin_date(plugin_publication_date),
                                        date_format,
                                    )
                                else:
                                    worksheet.write_blank(row_index, 21, None)
                                if plugin_modification_date is not None:
                                    worksheet.write_datetime(
                                        row_index,
                                        22,
                                        plugin.plugin_date(plugin_modification_date),
                                        date_format,
                                    )
                                else:
                                    worksheet.write_blank(row_index, 22, None)
                                worksheet.write(row_index, 23, plugin_description)
                                worksheet.write(row_index, 24, solution)
                                if plugin_output is not None:
                                    worksheet.write_string(row_index, 25, plugin_output)
                                else:
                                    worksheet.write_blank(row_index, 25, None)
                                if plugin_cves:
                                    worksheet.write_number(
                                        row_index, 26, len(plugin_cves)
                                    )
                                    worksheet.write_string(
                                        row_index, 27, ",".join(plugin_cves)
                                    )
                                else:
                                    worksheet.write_number(row_index, 26, 0)
                                    worksheet.write_blank(row_index, 27, None)
                                if exploit_available is not None:
                                    worksheet.write_string(
                                        row_index, 28, exploit_available
                                    )
                                else:
                                    worksheet.write_blank(row_index, 28, None)
                                if exploit_code_maturity is not None:
                                    worksheet.write_string(
                                        row_index, 29, exploit_code_maturity
                                    )
                                else:
                                    worksheet.write_blank(row_index, 29, None)
                                if exploit_framework_metasploit is not None:
                                    worksheet.write_string(
                                        row_index, 30, exploit_framework_metasploit
                                    )
                                else:
                                    worksheet.write_blank(row_index, 30, None)
                                if exploitability_ease is not None:
                                    worksheet.write_string(
                                        row_index, 31, exploitability_ease
                                    )
                                else:
                                    worksheet.write_blank(row_index, 31, None)
                        elif (
                            options["vulnerabilities_debug_data"]
                            and not options["none_skip"]
                        ):
                            worksheet.set_column("H:I", 10)
                            worksheet.set_column("K:K", 10)
                            worksheet.set_column("M:M", 7)
                            worksheet.set_column("N:N", 10)
                            worksheet.set_column("P:P", 12)
                            worksheet.set_column("Q:AC", 10)
                            worksheet.set_column("AG:AH", 10)
                            worksheet.set_column("AL:AL", 13)
                            worksheet.write(row_index, 0, host_scanner_ip)
                            worksheet.write(row_index, 1, scan_report_name)
                            worksheet.write(
                                row_index, 2, nessus_scan_file_name_with_path
                            )
                            worksheet.write(row_index, 3, host_report_host_name)
                            worksheet.write(row_index, 4, host_resolved_hostname)
                            worksheet.write(row_index, 5, host_resolved_fqdn)
                            worksheet.write(row_index, 6, host_resolved_ip)
                            worksheet.write(row_index, 7, "yes")
                            worksheet.write(row_index, 8, host_credentialed_checks)
                            worksheet.write(row_index, 9, scan_policy_name)
                            worksheet.write(row_index, 10, protocol)
                            worksheet.write(row_index, 11, service_name)
                            worksheet.write(row_index, 12, port)
                            worksheet.write(row_index, 13, plugin_id)
                            worksheet.write(row_index, 14, plugin_name)
                            worksheet.write(row_index, 15, plugin_type)
                            if options["none_filter_out"]:
                                if risk_factor == "None":
                                    worksheet.set_row(
                                        row_index, options={"hidden": True}
                                    )
                            worksheet.write_number(row_index, 16, int(severity))
                            worksheet.write(row_index, 17, severity_label)
                            worksheet.write(row_index, 18, risk_factor)
                            if cvssv2_base_score is not None:
                                worksheet.write_number(
                                    row_index, 19, float(cvssv2_base_score)
                                )
                            else:
                                worksheet.write_blank(row_index, 19, None)
                            worksheet.write(row_index, 20, cvssv2_base_score_label)
                            if cvssv3_base_score is not None:
                                worksheet.write_number(
                                    row_index, 21, float(cvssv3_base_score)
                                )
                            else:
                                worksheet.write_blank(row_index, 21, None)
                            worksheet.write(row_index, 22, cvssv3_base_score_label)
                            if cvssv4_base_score is not None:
                                worksheet.write_number(
                                    row_index, 23, float(cvssv4_base_score)
                                )
                            else:
                                worksheet.write_blank(row_index, 23, None)
                            worksheet.write(row_index, 24, cvssv4_base_score_label)
                            if vpr_score is not None:
                                worksheet.write_number(row_index, 25, float(vpr_score))
                            else:
                                worksheet.write_blank(row_index, 25, None)
                            worksheet.write(row_index, 26, vpr_score_label)
                            if epss_score is not None:
                                worksheet.write_number(row_index, 27, float(epss_score))
                            else:
                                worksheet.write_blank(row_index, 27, None)
                            if epss_score is not None:
                                worksheet.write_number(row_index, 27, float(epss_score))
                                percent_format = workbook.add_format(
                                    {"num_format": "0.0%"}
                                )
                                worksheet.write_number(
                                    row_index, 28, float(epss_score), percent_format
                                )
                            else:
                                worksheet.write_blank(row_index, 27, None)
                                worksheet.write_blank(row_index, 28, None)
                            worksheet.write(row_index, 29, plugin_family)
                            worksheet.write(row_index, 30, plugin_file_name)
                            worksheet.write(row_index, 31, plugin_version)
                            if plugin_publication_date is not None:
                                worksheet.write_datetime(
                                    row_index,
                                    32,
                                    plugin.plugin_date(plugin_publication_date),
                                    date_format,
                                )
                            else:
                                worksheet.write_blank(row_index, 32, None)
                            if plugin_modification_date is not None:
                                worksheet.write_datetime(
                                    row_index,
                                    33,
                                    plugin.plugin_date(plugin_modification_date),
                                    date_format,
                                )
                            else:
                                worksheet.write_blank(row_index, 33, None)
                            worksheet.write(row_index, 34, plugin_description)
                            worksheet.write(row_index, 35, solution)
                            if plugin_output is not None:
                                worksheet.write_string(row_index, 36, plugin_output)
                            else:
                                worksheet.write_blank(row_index, 36, None)
                            if plugin_cves:
                                worksheet.write_number(row_index, 37, len(plugin_cves))
                                worksheet.write_string(
                                    row_index, 38, ",".join(plugin_cves)
                                )
                            else:
                                worksheet.write_number(row_index, 37, 0)
                                worksheet.write_blank(row_index, 38, None)
                            if exploit_available is not None:
                                worksheet.write_string(row_index, 39, exploit_available)
                            else:
                                worksheet.write_blank(row_index, 39, None)
                            if exploit_code_maturity is not None:
                                worksheet.write_string(
                                    row_index, 40, exploit_code_maturity
                                )
                            else:
                                worksheet.write_blank(row_index, 40, None)
                            if exploit_framework_metasploit is not None:
                                worksheet.write_string(
                                    row_index, 41, exploit_framework_metasploit
                                )
                            else:
                                worksheet.write_blank(row_index, 41, None)
                            if exploitability_ease is not None:
                                worksheet.write_string(
                                    row_index, 42, exploitability_ease
                                )
                            else:
                                worksheet.write_blank(row_index, 42, None)
                        elif (
                            options["vulnerabilities_debug_data"]
                            and options["none_skip"]
                        ):
                            if risk_factor == "None":
                                number_of_rows -= 1
                                row_index -= 1
                                rows_in_current_sheet = row_index
                            elif risk_factor != "None":
                                worksheet.set_column("H:I", 10)
                                worksheet.set_column("K:K", 10)
                                worksheet.set_column("M:M", 7)
                                worksheet.set_column("N:N", 10)
                                worksheet.set_column("P:P", 12)
                                worksheet.set_column("Q:AC", 10)
                                worksheet.set_column("AG:AH", 10)
                                worksheet.set_column("AL:AL", 13)
                                worksheet.write(row_index, 0, host_scanner_ip)
                                worksheet.write(row_index, 1, scan_report_name)
                                worksheet.write(
                                    row_index, 2, nessus_scan_file_name_with_path
                                )
                                worksheet.write(row_index, 3, host_report_host_name)
                                worksheet.write(row_index, 4, host_resolved_hostname)
                                worksheet.write(row_index, 5, host_resolved_fqdn)
                                worksheet.write(row_index, 6, host_resolved_ip)
                                worksheet.write(row_index, 7, "yes")
                                worksheet.write(row_index, 8, host_credentialed_checks)
                                worksheet.write(row_index, 9, scan_policy_name)
                                worksheet.write(row_index, 10, protocol)
                                worksheet.write(row_index, 11, service_name)
                                worksheet.write(row_index, 12, port)
                                worksheet.write(row_index, 13, plugin_id)
                                worksheet.write(row_index, 14, plugin_name)
                                worksheet.write(row_index, 15, plugin_type)
                                worksheet.write_number(row_index, 16, int(severity))
                                worksheet.write(row_index, 17, severity_label)
                                worksheet.write(row_index, 18, risk_factor)
                                if cvssv2_base_score is not None:
                                    worksheet.write_number(
                                        row_index, 19, float(cvssv2_base_score)
                                    )
                                else:
                                    worksheet.write_blank(row_index, 19, None)
                                worksheet.write(row_index, 20, cvssv2_base_score_label)
                                if cvssv3_base_score is not None:
                                    worksheet.write_number(
                                        row_index, 21, float(cvssv3_base_score)
                                    )
                                else:
                                    worksheet.write_blank(row_index, 21, None)
                                worksheet.write(row_index, 22, cvssv3_base_score_label)
                                if cvssv4_base_score is not None:
                                    worksheet.write_number(
                                        row_index, 23, float(cvssv4_base_score)
                                    )
                                else:
                                    worksheet.write_blank(row_index, 23, None)
                                worksheet.write(row_index, 24, cvssv4_base_score_label)
                                if vpr_score is not None:
                                    worksheet.write_number(
                                        row_index, 25, float(vpr_score)
                                    )
                                else:
                                    worksheet.write_blank(row_index, 25, None)
                                worksheet.write(row_index, 26, vpr_score_label)
                                if epss_score is not None:
                                    worksheet.write_number(
                                        row_index, 27, float(epss_score)
                                    )
                                    percent_format = workbook.add_format(
                                        {"num_format": "0.0%"}
                                    )
                                    worksheet.write_number(
                                        row_index,
                                        28,
                                        float(epss_score),
                                        percent_format,
                                    )
                                else:
                                    worksheet.write_blank(row_index, 27, None)
                                    worksheet.write_blank(row_index, 28, None)
                                worksheet.write(row_index, 29, plugin_family)
                                worksheet.write(row_index, 30, plugin_file_name)
                                worksheet.write(row_index, 31, plugin_version)
                                if plugin_publication_date is not None:
                                    worksheet.write_datetime(
                                        row_index,
                                        32,
                                        plugin.plugin_date(plugin_publication_date),
                                        date_format,
                                    )
                                else:
                                    worksheet.write_blank(row_index, 32, None)
                                if plugin_modification_date is not None:
                                    worksheet.write_datetime(
                                        row_index,
                                        33,
                                        plugin.plugin_date(plugin_modification_date),
                                        date_format,
                                    )
                                else:
                                    worksheet.write_blank(row_index, 33, None)
                                worksheet.write(row_index, 34, plugin_description)
                                worksheet.write(row_index, 35, solution)
                                if plugin_output is not None:
                                    worksheet.write_string(row_index, 36, plugin_output)
                                else:
                                    worksheet.write_blank(row_index, 36, None)
                                if plugin_cves:
                                    worksheet.write_number(
                                        row_index, 37, len(plugin_cves)
                                    )
                                    worksheet.write_string(
                                        row_index, 38, ",".join(plugin_cves)
                                    )
                                else:
                                    worksheet.write_number(row_index, 37, 0)
                                    worksheet.write_blank(row_index, 38, None)
                                if exploit_available is not None:
                                    worksheet.write_string(
                                        row_index, 39, exploit_available
                                    )
                                else:
                                    worksheet.write_blank(row_index, 39, None)
                                if exploit_code_maturity is not None:
                                    worksheet.write_string(
                                        row_index, 40, exploit_code_maturity
                                    )
                                else:
                                    worksheet.write_blank(row_index, 40, None)
                                if exploit_framework_metasploit is not None:
                                    worksheet.write_string(
                                        row_index, 41, exploit_framework_metasploit
                                    )
                                else:
                                    worksheet.write_blank(row_index, 41, None)
                                if exploitability_ease is not None:
                                    worksheet.write_string(
                                        row_index, 42, exploitability_ease
                                    )
                                else:
                                    worksheet.write_blank(row_index, 42, None)

                end_time = time.time()
                elapsed_time = end_time - start_time
                elapsed_time_parsed = time.strftime(
                    "%H:%M:%S", time.gmtime(elapsed_time)
                )

                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[elapsed_time={elapsed_time_parsed}]",
                )
                _log(log, "end  ", file_to_pars_full_name)

            except Exception as e:
                number_of_files_with_errors += 1
                traceback.print_exc()
                _log(
                    log,
                    "info",
                    "ERROR Parsing ["
                    + str(nessus_scan_file_number)
                    + "/"
                    + str(len(list_of_source_files))
                    + "] nessus files",
                )
                _log(log, "info", e)

    # Apply autofilter to the final worksheet
    if rows_in_current_sheet > 0:
        worksheet.autofilter(0, 0, rows_in_current_sheet, number_of_columns - 1)

        if options["none_filter_out"]:
            risk_factors = ["Critical", "High", "Medium", "Low"]
            if not options["vulnerabilities_debug_data"]:
                worksheet.filter_column_list(12, risk_factors)
            else:
                worksheet.filter_column_list(16, risk_factors)

    return nessus_scan_file_number, number_of_files_with_errors


def create_worksheet_for_noncompliance(
    workbook, list_of_source_files, options, log=print
):
    """
    Function create spreadsheet with noncompliance sum-up in given workbook for selected files.
    :param workbook: workbook where spreadsheet are created
    :param list_of_source_files: list of selected files
    """
    report_name = "noncompliance"

    worksheet = workbook.add_worksheet(report_name)

    cell_format_bold = workbook.add_format({"bold": True})
    worksheet.set_row(0, None, cell_format_bold)

    # print('>>>>>>>>>>>>>>>> ', options["noncompliance_debug_data"])

    if not options["noncompliance_debug_data"]:
        headers = [
            # "Nessus scanner IP",
            # "Nessus scan name",
            # "Nessus file name",
            "Target",
            "Hostname",
            "FQDN",
            "IP",
            "Scanned",
            "Credentialed checks",
            # "Policy name",
            "Plugin ID",
            "Plugin name",
            "Plugin type",
            # "Risk Factor",
            "Plugin family",
            # "Compliance plugin file",
            # "Plugin file name",
            "Plugin version",
            "Plugin publication date",
            "Plugin modification date",
            "Check name",
            "Audit file name",
            # "Check ID",
            "Current value",
            # "Uname",
            "Description",
            "Check status",
            "Reference",
            "Error",
        ]
    else:
        headers = [
            "Nessus scanner IP",
            "Nessus scan name",
            "Nessus file name",
            "Target",
            "Hostname",
            "FQDN",
            "IP",
            "Scanned",
            "Credentialed checks",
            "Policy name",
            "Plugin ID",
            "Plugin name",
            "Plugin type",
            "Risk Factor",
            "Plugin family",
            "Compliance plugin file",
            "Plugin file name",
            "Plugin version",
            "Plugin publication date",
            "Plugin modification date",
            "Check name",
            "Audit file name",
            "Check ID",
            "Current value",
            "Uname",
            "Description",
            "Check status",
            "Reference",
            "Error",
        ]
    number_of_columns = len(headers)
    # print('Number of columns: ' + str(number_of_columns))

    worksheet.set_column(0, number_of_columns - 1, 18)

    debug_columns_list = [0, 1, 2, 9, 13, 15, 16, 22, 24]

    for column_index, header in enumerate(headers):
        if options["noncompliance_debug_data"] and column_index in debug_columns_list:
            cell_format_bold_blue = workbook.add_format()
            cell_format_bold_blue.set_bold()
            cell_format_bold_blue.set_font_color("blue")
            worksheet.write(0, column_index, header, cell_format_bold_blue)
        else:
            worksheet.write(0, column_index, header)

    worksheet.freeze_panes(1, 0)  # Freeze the first row.

    nessus_scan_file_number = 0
    number_of_files_with_errors = 0

    number_of_rows = 0
    row_index = 0
    row_index_per_file = 0
    for scan_file in list_of_source_files:
        source_file_type, files_to_pars, zip_source = _nessus_files_in_source(scan_file)

        for file_to_pars in files_to_pars:
            row_index_per_file += 1
            nessus_scan_file_number = nessus_scan_file_number + 1

            try:
                file_to_pars_full_name = ""
                source_file_size = 0
                if source_file_type == "nessus":
                    root = file.nessus_scan_file_root_element(file_to_pars)
                    scan_file_source = scan.scan_file_source(root)
                    file_to_pars_full_name = file.nessus_scan_file_name_with_path(
                        file_to_pars
                    )
                    source_file_size = file.nessus_scan_file_size_human(
                        file_to_pars_full_name
                    )
                elif source_file_type == "zip":
                    source_file_size = file.nessus_scan_file_inside_zip_size_human(
                        zip_source, file_to_pars
                    )
                    file_to_pars_full_name = (
                        f"{file.nessus_scan_file_name_with_path(scan_file)} ["
                        f"{zip_source.getinfo(file_to_pars).filename}]"
                    )
                    file_to_pars = zip_source.open(file_to_pars)
                    root = file.nessus_scan_file_root_element(file_to_pars)
                    scan_file_source = scan.scan_file_source(root)

                start_time = time.time()
                _log(log, "start", file_to_pars_full_name)
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[scan_file_source={scan_file_source}]",
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[source_file_size={source_file_size}]",
                )
                _log(
                    log, "info ", file_to_pars_full_name, f"[report_type={report_name}]"
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[number_of_target_hosts={scan.number_of_target_hosts(root)}]",
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[number_of_scanned_hosts={scan.number_of_scanned_hosts(root)}]",
                )
                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[number_of_scanned_hosts_with_credentials="
                    f"{scan.number_of_scanned_hosts_with_credentialed_checks_yes(root)}]",
                )

                date_format = workbook.add_format({"num_format": "yyyy-mm-dd hh:mm:ss"})

                scan_report_name = scan.report_name(root)
                nessus_scan_file_name_with_path = file.nessus_scan_file_name_with_path(
                    file_to_pars_full_name
                )
                scan_policy_name = scan.policy_name(root)

                report_host_counter = 0
                number_of_report_hosts = scan.number_of_scanned_hosts(root)

                for report_host in scan.report_hosts(root):
                    report_host_counter += 1

                    report_items_per_host = host.report_items(report_host)
                    host_scanner_ip = host.scanner_ip(root, report_host)
                    host_report_host_name = host.report_host_name(report_host)
                    host_resolved_hostname = host.resolved_hostname(report_host)
                    host_resolved_fqdn = host.resolved_fqdn(report_host)
                    host_resolved_ip = host.resolved_ip(report_host)
                    host_credentialed_checks = host.credentialed_checks(
                        root, report_host
                    )

                    for report_item in report_items_per_host:
                        if plugin.compliance_plugin(report_item):
                            compliance_plugin = "true"
                            row_index += 1
                            number_of_rows += 1
                            compliance_check_name = plugin.compliance_check_item_value(
                                report_item, "cm:compliance-check-name"
                            )
                            compliance_check_audit_file = (
                                plugin.compliance_check_item_value(
                                    report_item, "cm:compliance-audit-file"
                                )
                            )
                            compliance_check_check_id = (
                                plugin.compliance_check_item_value(
                                    report_item, "cm:compliance-check-id"
                                )
                            )
                            compliance_check_actual_value = (
                                plugin.compliance_check_item_value(
                                    report_item, "cm:compliance-actual-value"
                                )
                            )
                            compliance_check_uname = plugin.compliance_check_item_value(
                                report_item, "cm:compliance-uname"
                            )
                            compliance_check_info = plugin.compliance_check_item_value(
                                report_item, "cm:compliance-info"
                            )
                            compliance_check_result = (
                                plugin.compliance_check_item_value(
                                    report_item, "cm:compliance-result"
                                )
                            )
                            compliance_check_reference = (
                                plugin.compliance_check_item_value(
                                    report_item, "cm:compliance-reference"
                                )
                            )
                            compliance_check_error = plugin.compliance_check_item_value(
                                report_item, "cm:compliance-error"
                            )

                            plugin_id = int(
                                plugin.report_item_value(report_item, "pluginID")
                            )
                            plugin_name = plugin.report_item_value(
                                report_item, "pluginName"
                            )
                            plugin_type = plugin.report_item_value(
                                report_item, "plugin_type"
                            )
                            risk_factor = plugin.report_item_value(
                                report_item, "risk_factor"
                            )
                            plugin_family = plugin.report_item_value(
                                report_item, "pluginFamily"
                            )
                            plugin_file_name = plugin.report_item_value(
                                report_item, "fname"
                            )
                            plugin_version = plugin.report_item_value(
                                report_item, "script_version"
                            )
                            plugin_publication_date = plugin.report_item_value(
                                report_item, "plugin_publication_date"
                            )
                            plugin_modification_date = plugin.report_item_value(
                                report_item, "plugin_modification_date"
                            )

                            if not options["noncompliance_debug_data"]:
                                worksheet.write(row_index, 0, host_report_host_name)
                                worksheet.write(row_index, 1, host_resolved_hostname)
                                worksheet.write(row_index, 2, host_resolved_fqdn)
                                worksheet.write(row_index, 3, host_resolved_ip)
                                worksheet.write(row_index, 4, "yes")
                                worksheet.write(row_index, 5, host_credentialed_checks)
                                worksheet.write(row_index, 6, plugin_id)
                                worksheet.write(row_index, 7, plugin_name)
                                worksheet.write(row_index, 8, plugin_type)
                                worksheet.write(row_index, 9, plugin_family)
                                worksheet.write(row_index, 10, plugin_version)
                                worksheet.write_datetime(
                                    row_index,
                                    11,
                                    plugin.plugin_date(plugin_publication_date),
                                    date_format,
                                )
                                worksheet.write_datetime(
                                    row_index,
                                    12,
                                    plugin.plugin_date(plugin_modification_date),
                                    date_format,
                                )
                                worksheet.write(row_index, 13, compliance_check_name)
                                worksheet.write(
                                    row_index, 14, compliance_check_audit_file
                                )
                                worksheet.write(
                                    row_index, 15, compliance_check_actual_value
                                )
                                worksheet.write(row_index, 16, compliance_check_info)
                                worksheet.write(row_index, 17, compliance_check_result)
                                worksheet.write(
                                    row_index, 18, compliance_check_reference
                                )
                                worksheet.write(row_index, 19, compliance_check_error)
                            else:
                                worksheet.write(row_index, 0, host_scanner_ip)
                                worksheet.write(row_index, 1, scan_report_name)
                                worksheet.write(
                                    row_index, 2, nessus_scan_file_name_with_path
                                )
                                worksheet.write(row_index, 3, host_report_host_name)
                                worksheet.write(row_index, 4, host_resolved_hostname)
                                worksheet.write(row_index, 5, host_resolved_fqdn)
                                worksheet.write(row_index, 6, host_resolved_ip)
                                worksheet.write(row_index, 7, "yes")
                                worksheet.write(row_index, 8, host_credentialed_checks)
                                worksheet.write(row_index, 9, scan_policy_name)
                                worksheet.write(row_index, 10, plugin_id)
                                worksheet.write(row_index, 11, plugin_name)
                                worksheet.write(row_index, 12, plugin_type)
                                worksheet.write(row_index, 13, risk_factor)
                                worksheet.write(row_index, 14, plugin_family)
                                worksheet.write(row_index, 15, compliance_plugin)
                                worksheet.write(row_index, 16, plugin_file_name)
                                worksheet.write(row_index, 17, plugin_version)
                                worksheet.write_datetime(
                                    row_index,
                                    18,
                                    plugin.plugin_date(plugin_publication_date),
                                    date_format,
                                )
                                worksheet.write_datetime(
                                    row_index,
                                    19,
                                    plugin.plugin_date(plugin_modification_date),
                                    date_format,
                                )
                                worksheet.write(row_index, 20, compliance_check_name)
                                worksheet.write(
                                    row_index, 21, compliance_check_audit_file
                                )
                                worksheet.write(
                                    row_index, 22, compliance_check_check_id
                                )
                                worksheet.write(
                                    row_index, 23, compliance_check_actual_value
                                )
                                worksheet.write(row_index, 24, compliance_check_uname)
                                worksheet.write(row_index, 25, compliance_check_info)
                                worksheet.write(row_index, 26, compliance_check_result)
                                worksheet.write(
                                    row_index, 27, compliance_check_reference
                                )
                                worksheet.write(row_index, 28, compliance_check_error)

                end_time = time.time()
                elapsed_time = end_time - start_time
                elapsed_time_parsed = time.strftime(
                    "%H:%M:%S", time.gmtime(elapsed_time)
                )

                _log(
                    log,
                    "info ",
                    file_to_pars_full_name,
                    f"[elapsed_time={elapsed_time_parsed}]",
                )
                _log(log, "end  ", file_to_pars_full_name)

            except Exception as e:
                number_of_files_with_errors += 1
                traceback.print_exc()
                _log(
                    log,
                    "info",
                    "ERROR Parsing ["
                    + str(nessus_scan_file_number)
                    + "/"
                    + str(len(list_of_source_files))
                    + "] nessus files",
                )
                _log(log, "info", e)

    if number_of_rows > 0:
        worksheet.autofilter(0, 0, number_of_rows, number_of_columns - 1)

    return nessus_scan_file_number, number_of_files_with_errors
