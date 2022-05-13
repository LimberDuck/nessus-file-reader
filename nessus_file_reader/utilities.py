# -*- coding: utf-8 -*-
u"""
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

import re
import ipaddress
from xml.etree.ElementTree import parse

def ip_range_split(ip_range):
    """
    Function takes ip range and resolve it to list of particular IPs
    :param ip_range: ip range
    :return: list of IPs
    """
    ip_addresses = []
    if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', ip_range):
        address_part = ip_range.split('-')
        first_address = ipaddress.IPv4Address(address_part[0])
        last_address = ipaddress.IPv4Address(address_part[1])

        while first_address <= last_address:
            ip_addresses.append(first_address)
            first_address += 1

    elif re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}', ip_range):
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
        print(f'{child_level_1.tag} [{root_level}/{root_level_all}]')

        child_level_1_len = len(child_level_1)
        child_level_1_all = len(child_level_1)-1
        root_level -= 1
        # print(f'{root_level}')
        for child_level_2 in child_level_1:
            child_level_1_len -= 1
            # print(f'{root_level} {child_level_1_len}')
            if child_level_1_len:
                print(f"├── {child_level_2.tag} [{child_level_1_len}/{child_level_1_all}]")
            else:
                print(f"└── {child_level_2.tag} [{child_level_1_len}/{child_level_1_all}]")

            child_level_2_len = len(child_level_2)
            child_level_2_len_all = len(child_level_2)-1

            for child_level_3 in child_level_2:
                child_level_2_len -= 1
                child_level_3_len = len(child_level_3)
                child_level_3_len_all = len(child_level_3)-1
                # print(f'{root_level} {child_level_1_len} {child_level_2_len}')

                if child_level_1_len and child_level_2_len:
                    print(f"│   ├── {child_level_3.tag} [{child_level_2_len}/{child_level_2_len_all}]")
                elif child_level_1_len and not child_level_2_len:
                    print(f"│   └── {child_level_3.tag} [{child_level_2_len}/{child_level_2_len_all}]")
                elif not root_level and not child_level_1_len and child_level_2_len:
                    print(f"    ├── {child_level_3.tag} [{child_level_2_len}/{child_level_2_len_all}]")
                elif not root_level and  not child_level_1_len and not child_level_2_len:
                    print(f"    └── {child_level_3.tag} [{child_level_2_len}/{child_level_2_len_all}]")
                elif root_level and not child_level_1_len and child_level_2_len:
                    print(f"│   ├── {child_level_3.tag} [{child_level_2_len}/{child_level_2_len_all}]")
                elif root_level and not child_level_1_len and not child_level_2_len:
                    print(f"│   └── {child_level_3.tag} [{child_level_2_len}/{child_level_2_len_all}]")
                else:
                    print(f"?3 {child_level_3.tag}")

                for child_level_4 in child_level_3:
                    child_level_3_len -= 1
                    # print(f'{root_level} {child_level_1_len} {child_level_2_len} {child_level_3_len}')

                    if child_level_1_len and child_level_2_len and child_level_3_len:
                        print(f"│   │   ├── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]")
                    elif child_level_1_len and child_level_2_len and not child_level_3_len:
                        print(f"│   │   └── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]")
                    elif child_level_1_len and not child_level_2_len and child_level_3_len:
                        print(f"│       ├── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]")
                    elif child_level_1_len and not child_level_2_len and not child_level_3_len:
                        print(f"│       └── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]")
                    elif not root_level and not child_level_1_len and child_level_2_len and child_level_3_len:
                        print(f"    │   ├── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]")
                    elif not root_level and not child_level_1_len and child_level_2_len and not child_level_3_len:
                        print(f"    │   └── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]")
                    elif not root_level and not child_level_1_len and not child_level_2_len and child_level_3_len:
                        print(f"        ├── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]")
                    elif not root_level and not child_level_1_len and not child_level_2_len and not child_level_3_len:
                        print(f"        └── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]")
                    elif root_level and not child_level_1_len and child_level_2_len and child_level_3_len:
                        print(f"│   │   ├── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]")
                    elif root_level and  not child_level_1_len and child_level_2_len and not child_level_3_len:
                        print(f"│   │   └── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]")
                    elif root_level and  not child_level_1_len and not child_level_2_len and child_level_3_len:
                        print(f"│       ├── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]")
                    elif root_level and not child_level_1_len and not child_level_2_len and not child_level_3_len:
                        print(f"│       └── {child_level_4.tag} [{child_level_3_len}/{child_level_3_len_all}]")
                    else:
                        print(f"?4 {child_level_4.tag}")

                    child_level_4_len = len(child_level_4)
                    child_level_4_lena_all = len(child_level_4)-1
                    for child_level_5 in child_level_4:
                        child_level_4_len -= 1
                        # print(f'{root_level} {child_level_1_len} {child_level_2_len} {child_level_3_len} {child_level_4_len}')

                        if child_level_1_len and child_level_2_len and child_level_3_len and child_level_4_len:
                            print(f"│   │   │   ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif child_level_1_len and child_level_2_len and child_level_3_len and not child_level_4_len:
                            print(f"│   │   │   └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif child_level_1_len and child_level_2_len and not child_level_3_len and child_level_4_len:
                            print(f"│   │       ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif child_level_1_len and child_level_2_len and not child_level_3_len and not child_level_4_len:
                            print(f"│   │       └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif child_level_1_len and not child_level_2_len and child_level_3_len and child_level_4_len:
                            print(f"│       │   ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif child_level_1_len and not child_level_2_len and child_level_3_len and not child_level_4_len:
                            print(f"│       │   └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif child_level_1_len and not child_level_2_len and not child_level_3_len and child_level_4_len:
                            print(f"│           ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif child_level_1_len and not child_level_2_len and not child_level_3_len and not child_level_4_len:
                            print(f"│           └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif not child_level_1_len and child_level_2_len and child_level_3_len and child_level_4_len:
                            print(f"    │   │   ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif not child_level_1_len and child_level_2_len and child_level_3_len and not child_level_4_len:
                            print(f"    │   │   └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif not child_level_1_len and child_level_2_len and not child_level_3_len and child_level_4_len:
                            print(f"    │       ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif not child_level_1_len and child_level_2_len and not child_level_3_len and not child_level_4_len:
                            print(f"    │       └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif not child_level_1_len and not child_level_2_len and child_level_3_len and child_level_4_len:
                            print(f"        │   ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif not child_level_1_len and not child_level_2_len and child_level_3_len and not child_level_4_len:
                            print(f"        │   └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif not child_level_1_len and not child_level_2_len and not child_level_3_len and child_level_4_len:
                            print(f"            ├── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        elif not child_level_1_len and not child_level_2_len and not child_level_3_len and not child_level_4_len:
                            print(f"            └── {child_level_5.tag} [{child_level_4_len}/{child_level_4_lena_all}]")
                        else:
                            print(f"?5 {child_level_5.tag} [{child_level_4_len}]")