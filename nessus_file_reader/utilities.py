# -*- coding: utf-8 -*-
"""
nessus file reader (NFR) by LimberDuck (pronounced *ˈlɪm.bɚ dʌk*) is a python module
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

import re
import ipaddress
from xml.etree.ElementTree import parse
import os
import requests
from packaging import version
from nessus_file_reader._version import __version__ as current_version
from nessus_file_reader import __about__


def ip_range_split(ip_range):
    """
    Function takes ip range and resolve it to list of particular IPs
    :param ip_range: ip range
    :return: list of IPs
    """
    ip_addresses = []
    if re.match(
        "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}", ip_range
    ):
        address_part = ip_range.split("-")
        first_address = ipaddress.IPv4Address(address_part[0])
        last_address = ipaddress.IPv4Address(address_part[1])

        while first_address <= last_address:
            ip_addresses.append(first_address)
            first_address += 1

    elif re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}", ip_range):
        ip_network_hosts = ipaddress.ip_network(ip_range).hosts()
        ip_network_hosts_list = list(ip_network_hosts)

        for ip in ip_network_hosts_list:
            # print(ip)
            ip_addresses.append(ip)

    return ip_addresses


def nessus_scan_file_structure(file):
    """
    Function returns the root element for tree of given nessus file with scan results.
    :param file: given nessus file

    """

    nessus_scan_file_parsed = parse(file)
    root = nessus_scan_file_parsed.getroot()

    root_level = len(root)
    root_level_all = len(root)
    for child_level_1 in root:
        print(f"{child_level_1.tag} [{root_level}/{root_level_all}]")

        child_level_1_len = len(child_level_1)
        child_level_1_all = len(child_level_1) - 1
        root_level -= 1
        # print(f'{root_level}')
        for child_level_2 in child_level_1:
            child_level_1_len -= 1
            # print(f'{root_level} {child_level_1_len}')
            if child_level_1_len:
                print(
                    f"├── {child_level_2.tag} [{child_level_1_len}/{child_level_1_all}]"
                )
            else:
                print(
                    f"└── {child_level_2.tag} [{child_level_1_len}/{child_level_1_all}]"
                )

            child_level_2_len = len(child_level_2)
            child_level_2_len_all = len(child_level_2) - 1

            for child_level_3 in child_level_2:
                child_level_2_len -= 1
                child_level_3_len = len(child_level_3)
                child_level_3_len_all = len(child_level_3) - 1
                # print(f'{root_level} {child_level_1_len} {child_level_2_len}')

                if child_level_1_len and child_level_2_len:
                    print(
                        f"│   ├── {child_level_3.tag} [{child_level_2_len}/{child_level_2_len_all}]"
                    )
                elif child_level_1_len and not child_level_2_len:
                    print(
                        f"│   └── {child_level_3.tag} [{child_level_2_len}/{child_level_2_len_all}]"
                    )
                elif not root_level and not child_level_1_len and child_level_2_len:
                    print(
                        f"    ├── {child_level_3.tag} [{child_level_2_len}/{child_level_2_len_all}]"
                    )
                elif not root_level and not child_level_1_len and not child_level_2_len:
                    print(
                        f"    └── {child_level_3.tag} [{child_level_2_len}/{child_level_2_len_all}]"
                    )
                elif root_level and not child_level_1_len and child_level_2_len:
                    print(
                        f"│   ├── {child_level_3.tag} [{child_level_2_len}/{child_level_2_len_all}]"
                    )
                elif root_level and not child_level_1_len and not child_level_2_len:
                    print(
                        f"│   └── {child_level_3.tag} [{child_level_2_len}/{child_level_2_len_all}]"
                    )
                else:
                    print(f"?3 {child_level_3.tag}")

                for child_level_4 in child_level_3:
                    child_level_3_len -= 1
                    # print(f'{root_level} {child_level_1_len} {child_level_2_len} {child_level_3_len}')

                    if child_level_1_len and child_level_2_len and child_level_3_len:
                        print(
                            f"│   │   ├── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]"
                        )
                    elif (
                        child_level_1_len
                        and child_level_2_len
                        and not child_level_3_len
                    ):
                        print(
                            f"│   │   └── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]"
                        )
                    elif (
                        child_level_1_len
                        and not child_level_2_len
                        and child_level_3_len
                    ):
                        print(
                            f"│       ├── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]"
                        )
                    elif (
                        child_level_1_len
                        and not child_level_2_len
                        and not child_level_3_len
                    ):
                        print(
                            f"│       └── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]"
                        )
                    elif (
                        not root_level
                        and not child_level_1_len
                        and child_level_2_len
                        and child_level_3_len
                    ):
                        print(
                            f"    │   ├── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]"
                        )
                    elif (
                        not root_level
                        and not child_level_1_len
                        and child_level_2_len
                        and not child_level_3_len
                    ):
                        print(
                            f"    │   └── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]"
                        )
                    elif (
                        not root_level
                        and not child_level_1_len
                        and not child_level_2_len
                        and child_level_3_len
                    ):
                        print(
                            f"        ├── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]"
                        )
                    elif (
                        not root_level
                        and not child_level_1_len
                        and not child_level_2_len
                        and not child_level_3_len
                    ):
                        print(
                            f"        └── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]"
                        )
                    elif (
                        root_level
                        and not child_level_1_len
                        and child_level_2_len
                        and child_level_3_len
                    ):
                        print(
                            f"│   │   ├── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]"
                        )
                    elif (
                        root_level
                        and not child_level_1_len
                        and child_level_2_len
                        and not child_level_3_len
                    ):
                        print(
                            f"│   │   └── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]"
                        )
                    elif (
                        root_level
                        and not child_level_1_len
                        and not child_level_2_len
                        and child_level_3_len
                    ):
                        print(
                            f"│       ├── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]"
                        )
                    elif (
                        root_level
                        and not child_level_1_len
                        and not child_level_2_len
                        and not child_level_3_len
                    ):
                        print(
                            f"│       └── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]"
                        )
                    else:
                        print(f"?4 {child_level_4.tag}")

                    child_level_4_len = len(child_level_4)
                    child_level_4_lena_all = len(child_level_4) - 1
                    for child_level_5 in child_level_4:
                        child_level_4_len -= 1
                        # print(f'{root_level} {child_level_1_len} {child_level_2_len} {child_level_3_len} {child_level_4_len}')

                        if (
                            child_level_1_len
                            and child_level_2_len
                            and child_level_3_len
                            and child_level_4_len
                        ):
                            print(
                                f"│   │   │   ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            child_level_1_len
                            and child_level_2_len
                            and child_level_3_len
                            and not child_level_4_len
                        ):
                            print(
                                f"│   │   │   └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            child_level_1_len
                            and child_level_2_len
                            and not child_level_3_len
                            and child_level_4_len
                        ):
                            print(
                                f"│   │       ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            child_level_1_len
                            and child_level_2_len
                            and not child_level_3_len
                            and not child_level_4_len
                        ):
                            print(
                                f"│   │       └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            child_level_1_len
                            and not child_level_2_len
                            and child_level_3_len
                            and child_level_4_len
                        ):
                            print(
                                f"│       │   ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            child_level_1_len
                            and not child_level_2_len
                            and child_level_3_len
                            and not child_level_4_len
                        ):
                            print(
                                f"│       │   └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            child_level_1_len
                            and not child_level_2_len
                            and not child_level_3_len
                            and child_level_4_len
                        ):
                            print(
                                f"│           ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            child_level_1_len
                            and not child_level_2_len
                            and not child_level_3_len
                            and not child_level_4_len
                        ):
                            print(
                                f"│           └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            not child_level_1_len
                            and child_level_2_len
                            and child_level_3_len
                            and child_level_4_len
                        ):
                            print(
                                f"    │   │   ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            not child_level_1_len
                            and child_level_2_len
                            and child_level_3_len
                            and not child_level_4_len
                        ):
                            print(
                                f"    │   │   └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            not child_level_1_len
                            and child_level_2_len
                            and not child_level_3_len
                            and child_level_4_len
                        ):
                            print(
                                f"    │       ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            not child_level_1_len
                            and child_level_2_len
                            and not child_level_3_len
                            and not child_level_4_len
                        ):
                            print(
                                f"    │       └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            not child_level_1_len
                            and not child_level_2_len
                            and child_level_3_len
                            and child_level_4_len
                        ):
                            print(
                                f"        │   ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            not child_level_1_len
                            and not child_level_2_len
                            and child_level_3_len
                            and not child_level_4_len
                        ):
                            print(
                                f"        │   └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            not child_level_1_len
                            and not child_level_2_len
                            and not child_level_3_len
                            and child_level_4_len
                        ):
                            print(
                                f"            ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        elif (
                            not child_level_1_len
                            and not child_level_2_len
                            and not child_level_3_len
                            and not child_level_4_len
                        ):
                            print(
                                f"            └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]"
                            )
                        else:
                            print(f"?5 {child_level_5.tag} [{child_level_4_len}]")


def nessus_scan_file_split(input_file_path: str, batch_size: int) -> None:
    """
    Splits a .nessus XML file into multiple files, each containing a specified number of ReportHost entries.
    Preserves the original XML formatting, including entities like &apos; and &quot;.

    :param input_file_path: Path to the input .nessus file.
    :param output_file_prefix: Prefix for the output files.
    :param batch_size: Number of ReportHost entries per split file.
    """
    with open(input_file_path, "r", encoding="utf-8") as file:
        xml_content = file.read()

    # Extract the Policy section
    policy_start = xml_content.find("<Policy>")
    policy_end = xml_content.find("</Policy>") + len("</Policy>")
    policy_element = xml_content[policy_start:policy_end]

    # Extract the Report section
    report_start = xml_content.find("<Report ")
    report_end = xml_content.find("</Report>")
    report_element = xml_content[report_start:report_end]
    report_hosts = report_element.split("<ReportHost ")[1:]

    # Extract the Report name
    report_name_start = report_element.find('name="')
    report_name_end = report_element.find('"', report_name_start + len('name="'))
    report_name = report_element[report_name_start : report_name_end + 1]
    report_name_line = f'<Report {report_name} xmlns:cm="http://www.nessus.org/cm">'

    # Split ReportHost elements into batches
    for i in range(0, len(report_hosts), batch_size):
        batch = report_hosts[i : i + batch_size]

        # Construct the new XML content
        new_xml = xml_content[:report_start]
        new_xml += report_name_line + "\n"
        new_xml += "".join("<ReportHost " + host for host in batch)
        new_xml += "</Report>\n</NessusClientData_v2>\n"

        # Insert the Policy section
        new_xml = new_xml[:policy_start] + policy_element + new_xml[policy_end:]

        # Write the new XML content to a file
        output_file_prefix = os.path.splitext(input_file_path)[0]
        output_file = f"{output_file_prefix}_part{i // batch_size + 1}.nessus"
        print(output_file)
        with open(output_file, "w", encoding="utf-8") as out_file:
            out_file.write(new_xml)


def check_for_update():

    PACKAGE_NAME = __about__.__package_name__

    try:
        response = requests.get(
            f"https://pypi.org/pypi/{PACKAGE_NAME}/json", timeout=1.5
        )
        response.raise_for_status()
        latest = response.json()["info"]["version"]
        read_more = (
            f"> Read more:\n"
            f"> https://limberduck.org/en/latest/tools/{PACKAGE_NAME}\n"
            f"> https://github.com/LimberDuck/{PACKAGE_NAME}\n"
            f"> https://github.com/LimberDuck/{PACKAGE_NAME}/releases"
        )
        if version.parse(latest) > version.parse(current_version):
            print(
                f"\n> A new version of {PACKAGE_NAME} is available: {latest} (you have {current_version})"
            )
            print(f"> Update with: pip install -U {PACKAGE_NAME}\n")
            print(read_more)
        elif version.parse(latest) == version.parse(current_version):
            print(
                f"\n> You are using the latest version of {PACKAGE_NAME}: {current_version}\n"
            )
            print(read_more)
        else:
            print(
                f"\n> You are using a pre-release version of {PACKAGE_NAME}: {current_version}"
            )
            print(f"> Latest released version of {PACKAGE_NAME}: {latest}\n")
            print(read_more)
    except requests.exceptions.ConnectionError as e:
        print("> Could not check for updates: Connection error.\n")
        print(e)
    except Exception as e:
        print("> Could not check for updates:\n")
        print(e)
