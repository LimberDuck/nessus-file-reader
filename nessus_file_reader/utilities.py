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
