# -*- coding: utf-8 -*-
"""
nessus file reader by LimberDuck (pronounced *ˈlɪm.bɚ dʌk*) is a python module
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

import nessus_file_reader as nfr
import os
import glob
import traceback
import time


def nfr_example_simple():

    # Provide directory path where nessus files are placed or exact path to one nessus scan file
    # default path is current directory
    nessus_scan_files = "."

    if os.path.isdir(nessus_scan_files):
        os_separator = os.path.sep
        extension = "*.nessus"
        list_of_source_files = glob.glob(
            nessus_scan_files + os_separator + "**" + os_separator + extension,
            recursive=True,
        )
        print(f"Source file path:\n{nessus_scan_files}\n")
        print("\nList of source files:")
        for source_file in list_of_source_files:
            print(f" {source_file}")
    else:
        list_of_source_files = [nessus_scan_files]
        print(f"Source file path:\n{os.path.dirname(nessus_scan_files)}")
        print(f"\nList of source files:\n{nessus_scan_files}\n")

    start_time = time.time()
    for row_index, nessus_scan_file in enumerate(list_of_source_files):
        if os.path.isfile(nessus_scan_file):

            print(
                f"\n@-[{str(row_index+1)}/{str(len(list_of_source_files))}]----------------------"
                f"-------------------------------------------------------------------------------"
            )
            try:

                # Use *file* functions to get details about provided file e.g. root, file name, file size.
                root = nfr.file.nessus_scan_file_root_element(nessus_scan_file)
                file_name = nfr.file.nessus_scan_file_name_with_path(nessus_scan_file)
                file_size = nfr.file.nessus_scan_file_size_human(nessus_scan_file)
                print(f"File name: {file_name}")
                print(f"File size: {file_size}")
                print("")

                # Use *scan* functions to get details about provided scan e.g. report name,
                # number of target/scanned/credentialed hosts, scan time start/end/elapsed and more.
                scan_file_source = nfr.scan.scan_file_source(root)
                print(f" Source of file: {scan_file_source}")
                report_hosts = nfr.scan.report_hosts(root)
                print(f" Report hosts: {report_hosts}")
                report_name = nfr.scan.report_name(root)
                policy_name = nfr.scan.policy_name(root)
                print(f" Report name: {report_name}")
                print(f" Policy name: {policy_name}")
                number_of_target_hosts = nfr.scan.number_of_target_hosts(root)
                print(f" Number of target: {number_of_target_hosts}")
                number_of_scanned_hosts = nfr.scan.number_of_scanned_hosts(root)
                print(f" Number of scanned: {number_of_scanned_hosts}")
                number_of_scanned_hosts_with_credentialed_checks_yes = (
                    nfr.scan.number_of_scanned_hosts_with_credentialed_checks_yes(root)
                )
                print(
                    f" Number of credentialed hosts: {number_of_scanned_hosts_with_credentialed_checks_yes}"
                )

                scan_time_start = nfr.scan.scan_time_start(root)
                scan_time_end = nfr.scan.scan_time_end(root)
                scan_time_elapsed = nfr.scan.scan_time_elapsed(root)
                print(
                    f" Scan time START - END (ELAPSED): {scan_time_start} - {scan_time_end} ({scan_time_elapsed})"
                )
                print("")

                # Use *host* functions to get details about hosts from provided scan e.g. report hosts names,
                # operating system, hosts scan time start/end/elapsed, number of Critical/High/Medium/Low/None findings
                # and more.
                for report_host in nfr.scan.report_hosts(root):
                    report_host_name = nfr.host.report_host_name(report_host)
                    report_host_os = nfr.host.detected_os(report_host)
                    report_host_scan_time_start = nfr.host.host_time_start(report_host)
                    report_host_scan_time_end = nfr.host.host_time_end(report_host)
                    report_host_scan_time_elapsed = nfr.host.host_time_elapsed(
                        report_host
                    )
                    report_host_critical = nfr.host.number_of_plugins_per_risk_factor(
                        report_host, "Critical"
                    )
                    report_host_high = nfr.host.number_of_plugins_per_risk_factor(
                        report_host, "High"
                    )
                    report_host_medium = nfr.host.number_of_plugins_per_risk_factor(
                        report_host, "Medium"
                    )
                    report_host_low = nfr.host.number_of_plugins_per_risk_factor(
                        report_host, "Low"
                    )
                    report_host_none = nfr.host.number_of_plugins_per_risk_factor(
                        report_host, "None"
                    )
                    print(f"  Report host name: {report_host_name}")
                    print(f"  Report host OS: {report_host_os}")
                    print(
                        f"  Host scan time START - END (ELAPSED): "
                        f"{report_host_scan_time_start} - {report_host_scan_time_end} "
                        f"({report_host_scan_time_elapsed})"
                    )
                    print(
                        f"  Critical/High/Medium/Low/None findings: {report_host_critical}/{report_host_high}/"
                        f"{report_host_medium}/{report_host_low}/{report_host_none}"
                    )
                    print("")

                    # Use *plugin* functions to get details about plugins reported in provided scan e.g. plugins ID,
                    # plugins risk factor, plugins name.
                    print("\tPlugin ID\t\tRisk Factor\t\t\t\tPlugin Name")
                    report_items_per_host = nfr.host.report_items(report_host)
                    for report_item in report_items_per_host:
                        plugin_id = int(
                            nfr.plugin.report_item_value(report_item, "pluginID")
                        )
                        risk_factor = nfr.plugin.report_item_value(
                            report_item, "risk_factor"
                        )
                        plugin_name = nfr.plugin.report_item_value(
                            report_item, "pluginName"
                        )
                        plugin_cves = nfr.plugin.report_item_values(report_item, "cve")
                        print(
                            "\t",
                            plugin_id,
                            "  \t\t\t",
                            risk_factor,
                            "  \t\t\t",
                            plugin_name,
                            "  \t\t\t",
                            plugin_cves,
                        )

                    print()
                    # If you want to get output for interesting you plugin
                    # e.g. "Nessus Scan Information" use below function
                    pido_19506 = nfr.plugin.plugin_output(root, report_host, "19506")
                    print(f"Nessus Scan Information Plugin Output:\n{pido_19506}")

                    # If you know that interesting you plugin occurs more than ones for particular host
                    # e.g. "Netstat Portscanner (SSH)" use below function
                    pidos_14272 = nfr.plugin.plugin_outputs(root, report_host, "14272")
                    print(
                        f"All findings for Netstat Portscanner (SSH): \n{pidos_14272}"
                    )

                    netbios_network_name = nfr.host.netbios_network_name(
                        root, report_host
                    )
                    print(f"Netbios network name {netbios_network_name}")

            except Exception as e:
                print(f"\nUps... ERROR occurred. \n\n {str(e)}")
                traceback.print_exc()
                print(
                    f"ERROR Parsing [{str(row_index+1)}/{str(len(list_of_source_files))}] nessus files"
                )

        else:
            print(
                f"Ups.. {nessus_scan_file} does not exist in current directory: {os.getcwd()}"
            )

    end_time = time.time()
    elapsed_time = end_time - start_time
    elapsed_time_parsed = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
    print(
        "\n/===================================================="
        "======================================================="
    )
    print(f'[x] Parsing ended on {time.strftime("%c", time.localtime(end_time))}\n')
    print(f"Elapsed time: {elapsed_time_parsed}")


def main():

    app_name = nfr.__about__.__title__
    app_version = nfr.__about__.__version__
    app_version_release_date = nfr.__about__.__release_date__

    print(
        f"This is example script for {app_name} {app_version} {app_version_release_date}\n"
    )

    nfr_example_simple()


main()
