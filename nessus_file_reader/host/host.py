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
import datetime
from nessus_file_reader.plugin import plugin


def report_host_name(report_host):
    """
    Function returns name of given report host.
    :param report_host: report host element
    :return: name of given report host
    """
    name = report_host.get("name")
    return name


def host_property_value(report_host, property_name):
    """
    Function returns value of given property for given target, e.g. hostname.
    :param report_host: report host element
    :param property_name: exact property name
    :return: property value
    """
    property_exist = report_host[0].find("tag/[@name='" + property_name + "']")

    if property_exist is not None:
        property_value = property_exist.text
    else:
        property_value = None
    return property_value


def resolved_hostname(report_host):
    """
    Function returns hostname for given target. If hostname contains FQDN only hostname will be returned.
    :param report_host: report host element
    :return: hostname for given target
    """
    hostname = host_property_value(report_host, "hostname")
    if hostname is not None:
        hostname = hostname.lower()
    else:
        hostname = ""
    return hostname.split(".")[0]


def resolved_ip(report_host):
    """
    Function returns ip for given target.
    :param report_host: report host element
    :return: ip for given target
    """
    host_ip = host_property_value(report_host, "host-ip")
    return host_ip


def resolved_fqdn(report_host):
    """
    Function returns fqdn for given target.
    :param report_host:  report host element
    :return:  fqdn for given target
    """
    host_fqdn = host_property_value(report_host, "host-fqdn")
    if host_fqdn is not None:
        host_fqdn = host_fqdn.lower()
    return host_fqdn


def netbios_network_name(root, report_host):
    """
    Function returns information about NetBIOS Computer Name, Workgroup / Domain name for given target.
    :param root: root element of scan file tree
    :param report_host: report host element
    :return: os for given target
    """
    pido_10150 = plugin.plugin_output(root, report_host, "10150")
    pido_10150_split = pido_10150.split("\n")

    netbios_computer_name = ""
    netbios_domain_name = ""
    for netbios_data_split_entry in pido_10150_split:
        if "Computer name" in netbios_data_split_entry:
            netbios_computer_name = (
                netbios_data_split_entry.split("=")[0].strip().lower()
            )

        if "Workgroup / Domain name" in netbios_data_split_entry:
            netbios_domain_name = netbios_data_split_entry.split("=")[0].strip().lower()

    return {
        "netbios_computer_name": netbios_computer_name,
        "netbios_domain_name": netbios_domain_name,
    }


def detected_os(report_host):
    """
    Function returns information about Operating System for given target.
    :param report_host: report host element
    :return: os for given target
    """
    operating_system = host_property_value(report_host, "operating-system")
    if operating_system is not None:
        if "&quot;" in operating_system:
            operating_system = str(operating_system).strip("[&quot;").strip("&quot;]")
        else:
            operating_system = str(operating_system).strip('["').strip('"]')
    else:
        operating_system = ""
    return operating_system


def scanner_ip(root, report_host):
    """
    Function returns scanner ip for given target based on Plugin ID 19506.
    :param root: root element of scan file tree
    :param report_host: report host element
    :return: ip address of scanner
    """
    ip = None
    pido_19506 = plugin.plugin_output(root, report_host, "19506")
    for line in pido_19506.split("\n"):
        if re.findall("Scanner IP :", line):
            ip = re.sub("Scanner IP : ", "", line)
    return ip


def login_used(report_host):
    """
    Function returns login name used during scan for given target.
    :param report_host: report host element
    :return: login name
    """
    login = None

    for tag in report_host[0].findall("tag"):
        tag_name = tag.get("name")
        if re.findall("login-used", tag_name):
            if tag_name is not None:
                login = tag.text
    return login


def credentialed_checks(root, report_host):
    """
    Function returns confirmation if credentialed checks have been enabled during scan for given target based on
    Plugin ID 19506.
    :param root: root element of scan file tree
    :param report_host: report host element
    :return:
        'yes' + login used - if credentialed checks have been enabled
        'no' - if credentialed checks have not been enabled
    """
    credentialed = None
    pido_19506 = plugin.plugin_output(root, report_host, "19506")
    if (
        "No output recorded." in pido_19506
        or "Check Audit Trail" in pido_19506
        or "19506 not enabled." in pido_19506
    ):
        credentialed = "no"
    else:
        for line in pido_19506.split("\n"):
            if re.findall("Credentialed checks :", line):
                credentialed = re.sub("Credentialed checks : ", "", line)
                credentialed = re.sub("&apos;", "", credentialed)

    return credentialed


def credentialed_checks_db(root, report_host):
    """
    Function returns confirmation if credentialed checks have been enabled during scan for given target based on
    Plugin IDs 91825 and 91827.
    :param root: root element of scan file tree
    :param report_host: report host element
    :return:
        'yes' + info about source - if credentialed checks have been enabled
        'no' - if credentialed checks have not been enabled
    """
    credentialed = None
    # "91825: Oracle DB Login Possible"
    pido_91825 = plugin.plugin_output(root, report_host, "91825")
    if (
        "No output recorded." in pido_91825
        or "Check Audit Trail" in pido_91825
        or "91825 not enabled." in pido_91825
    ):
        credentialed = "no"
    elif re.findall(
        "Credentialed checks have been enabled for Oracle RDBMS server", pido_91825
    ):
        credentialed = "yes, based on plugin id 91825"

    # "91827: Microsoft SQL Server Login Possible"
    pido_91827 = plugin.plugin_output(root, report_host, "91827")
    if (
        "No output recorded." in pido_91827
        or "Check Audit Trail" in pido_91827
        or "91827 not enabled." in pido_91827
    ):
        credentialed = "no"
    elif re.findall(
        "Credentialed checks have been enabled for MSSQL server", pido_91827
    ):
        credentialed = "yes, based on plugin id 91827"

    return credentialed


def number_of_plugins(report_host):
    """
    Function returns number of reported plugins for given target.
    :param report_host: report host element
    :return: number of reported plugins
    """
    number_of_plugins_counter = len(report_host.findall("ReportItem"))
    return number_of_plugins_counter


def number_of_plugins_per_risk_factor(report_host, risk_factor_level):
    """
    Function returns number of all plugins reported during scan for given risk factor for given target.
    :param report_host: report host element
    :param risk_factor_level:
        'Critical'
        'High'
        'Medium'
        'Low'
        'None'
    :return: number of plugins for given risk factor
    """
    risk_factor_counter = 0
    for report_item in report_host.findall("ReportItem"):
        risk_factor = report_item.find("risk_factor")
        if risk_factor is not None:
            if risk_factor.text == risk_factor_level:
                risk_factor_counter += 1
    return risk_factor_counter


def number_of_compliance_plugins(report_host):
    """
    Function returns number of reported compliance plugins for given target.
    :param report_host: report host element
    :return: number of reported compliance plugins
    """
    compliance_plugin_counter = 0
    for report_item in report_host.findall("ReportItem"):
        compliance = report_item.find("compliance")
        if compliance is not None:
            if compliance.text == "true":
                compliance_plugin_counter += 1
    return compliance_plugin_counter


def number_of_compliance_plugins_per_result(report_host, compliance_result):
    """
    Function returns number of all compliance plugins reported during scan for given compliance result for given target.
    :param report_host: report host element
    :param compliance_result:
        'PASSED'
        'FAILED'
        'WARNING'
    :return:  number of compliance plugins for given compliance result
    """
    compliance_counter = 0
    for report_item in report_host.findall("ReportItem"):
        compliance = report_item.find(
            "cm:compliance-result", namespaces={"cm": "http://www.nessus.org/cm"}
        )
        if compliance is not None:
            if compliance.text == compliance_result:
                compliance_counter += 1
    return compliance_counter


def report_items(report_host):
    """
    Function returns all items for given target.
    :param report_host: report host element
    :return: list of report items
    """
    items = report_host.findall("ReportItem")
    return items


def host_time_start(report_host):
    """
    Function returns scan start time for given target.
    :param report_host: report host element
    :return: formatted date and time when scan has been started
    """
    host_start_time = host_property_value(report_host, "HOST_START")
    if host_start_time is not None:
        host_start_time_formatted = datetime.datetime.strptime(
            host_start_time, "%a %b %d %H:%M:%S %Y"
        )
    else:
        host_start_time_formatted = None
    return host_start_time_formatted


def host_time_end(report_host):
    """
    Function returns scan end time for given target.
    :param report_host: report host element
    :return: formatted date and time when scan has been ended
    """
    host_end_time = host_property_value(report_host, "HOST_END")
    if host_end_time is not None:
        host_end_time_formatted = datetime.datetime.strptime(
            host_end_time, "%a %b %d %H:%M:%S %Y"
        )
    else:
        host_end_time_formatted = None

    return host_end_time_formatted


def host_time_elapsed(report_host):
    """
    Function returns scan time elapsed in format HH:MM:SS for given target.
    :param report_host: report host element
    :return: scan time elapsed in format HH:MM:SS.
    """
    host_time_start_value = host_time_start(report_host)
    host_time_end_value = host_time_end(report_host)
    if host_time_end_value is not None:
        elapsed_time = host_time_end_value - host_time_start_value
        elapsed_time = str(elapsed_time)
    else:
        elapsed_time = None

    return elapsed_time
