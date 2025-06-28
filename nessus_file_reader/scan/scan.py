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
from nessus_file_reader import utilities


def report_name(root):
    """
    Function returns scan report name.
    :param root: root element of scan file tree
    :return: scan report name
    """
    name = root.find("Report").get("name")
    return name


def policy_name(root):
    """
    Function returns policy name used during scan.
    :param root: root element of scan file tree
    :return: policy name
    """
    if root.find("Policy"):
        name = root.find("Policy").find("policyName")
        if name is not None:
            name = name.text
        else:
            name = None
    else:
        name = None
    return name


def server_preference_value(root, preference_name):
    """
    Function returns value for given server preference.
    :param root: root element of scan file tree
    :param preference_name: preference name
    :return:
        preference value - if preference exist
        None - if preference does not exist
    """

    if root.find("Policy"):
        status = 0
        preference_value = None
        for preference in root.find("Policy/Preferences/ServerPreferences").findall(
            "preference"
        ):
            preference_name_in_report = preference.findtext("name")
            if preference_name_in_report == preference_name:
                preference_value = preference.findtext("value")
                status = 1
        if status == 0:
            preference_value = None
    else:
        preference_value = None

    return preference_value


def scan_file_source(root):
    """
    Function returns information about source of file, Tenable.sc Tenable.io or Nessus.
    :param root: root element of scan file tree
    :return:
        'Tenable.sc' if Tenable.sc is source of nessus file
        'Tenable.io' if Tenable.io is source of nessus file
        'Nessus' if Nessus is source of nessus file
    """
    tenableio_site_id = server_preference_value(root, "tenableio.site_id")
    sc_version = server_preference_value(root, "sc_version")

    if tenableio_site_id is not None:
        source = "Tenable.io"
    elif sc_version is not None:
        source = "Tenable.sc"
    else:
        source = "Nessus"
    return source


def policy_max_hosts(root):
    """
    Function returns Max simultaneous checks per host value specified in policy used during scan.
    :param root: root element of scan file tree
    :return: max host value or None
    """
    max_hosts = server_preference_value(root, "max_hosts")
    return max_hosts


def policy_max_checks(root):
    """
    Function returns Max simultaneous hosts per scan value specified in policy used during scan.
    :param root: root element of scan file tree
    :return: max checks value or None
    """
    max_checks = server_preference_value(root, "max_checks")
    return max_checks


def policy_checks_read_timeout(root):
    """
    Function returns Network timeout (in seconds) value specified in policy used during scan.
    :param root: root element of scan file tree
    :return: network timeout value or None
    """
    checks_read_timeout = server_preference_value(root, "checks_read_timeout")
    return checks_read_timeout


def reverse_lookup(root):
    """
    Function returns information if option Settings > Report > Output > 'Designate hosts by their DNS name' has been
    turned on in policy used during scan.
    :param root: root element of scan file tree
    :return:
        'yes' if reverse_lookup has been enabled
        'no' if reverse_lookup has not been enabled
    """
    reverse_lookup_value = server_preference_value(root, "reverse_lookup")
    return reverse_lookup_value


def plugin_set(root):
    """
    Function returns list of plugins selected in policy used during scan.
    :param root: root element of scan file tree
    :return: list of plugins selected in policy or None
    """
    plugin_set_list = server_preference_value(root, "plugin_set")
    if plugin_set_list:
        plugin_set_list = plugin_set_list[:-1].split(";")
    else:
        plugin_set_list = None
    return plugin_set_list


def plugin_set_number(root):
    """
    Function returns number of plugins selected in policy used during scan.
    :param root: root element of scan file tree
    :return: number of plugins selected in policy
    """
    plugin_set_list = plugin_set(root)
    if plugin_set_list is not None:
        plugin_set_len = len(plugin_set_list)
    else:
        plugin_set_len = None
    return plugin_set_len


def plugin_preference_value(root, full_preference_name):
    """
    Function returns value for given full preference name of plugin.
    :param root: root element of scan file tree
    :param full_preference_name: full preference name of plugin
    :return: preference value or None
    """
    preference = root.find(
        "Policy/Preferences/PluginsPreferences/item/[fullName='"
        + full_preference_name
        + "']/selectedValue"
    )
    if preference is not None:
        preference_value = preference.text
    else:
        preference_value = None
    return preference_value


def policy_db_sid(root):
    """
    Function returns Database SID specified in policy used during scan.
    :param root: root element of scan file tree
    :return: Database SID name or None
    """
    sid = plugin_preference_value(root, "Database settings[entry]:Database SID :")
    return sid


def policy_db_port(root):
    """
    Function returns Database port specified in policy used during scan.
    :param root: root element of scan file tree
    :return: Database port or None
    """
    port = plugin_preference_value(
        root, "Database settings[entry]:Database port to use :"
    )
    return port


def policy_login_specified(root):
    """
    Function returns login specified in policy used during scan.
    Currently covered: smb, ssh, database, VMware vCenter SOAP API
    :param root: root element of scan file tree
    :return: login name or None
    """

    login_vmware_vcenter_soap_api = plugin_preference_value(
        root, "VMware vCenter SOAP API Settings[entry]:VMware vCenter user name :"
    )
    login_database = plugin_preference_value(root, "Database settings[entry]:Login :")
    login_smb = plugin_preference_value(
        root, "Login configurations[entry]:SMB account :"
    )
    login_ssh = plugin_preference_value(root, "SSH settings[entry]:SSH user name :")

    if login_vmware_vcenter_soap_api:
        login_specified = login_vmware_vcenter_soap_api
    elif login_database:
        login_specified = login_database
    elif login_smb:
        domain_smb_domain = plugin_preference_value(
            root, "Login configurations[entry]:SMB domain (optional) :"
        )
        if domain_smb_domain:
            login_specified = domain_smb_domain + "\\" + login_smb
        else:
            login_specified = login_smb
    elif login_ssh:
        login_specified = login_ssh
    else:
        login_specified = None

    return login_specified


def list_of_target_hosts_raw(root):
    """
    Function returns list of target hosts specified in scan.
    :param root: root element of scan file tree
    :return: list of targets
    """
    target_hosts = root.find(
        "Policy/Preferences/ServerPreferences/preference/[name='TARGET']/value"
    )
    if target_hosts is not None:
        target_hosts = target_hosts.text
        target_hosts_splitted = target_hosts.split(",")
        target_hosts_final_list = [element.lower() for element in target_hosts_splitted]
    else:
        target_hosts_final_list = None
    return target_hosts_final_list


def list_of_target_hosts(root):
    """
    Function returns list of target hosts specified in scan.
    If nessus files comes from Tenable.sc and has [IP] in target it's removed
    If nessus files comes from Tenable.sc and has IP range in target it's resolved to particular IP addresses
    :param root: root element of scan file tree
    :return: list of targets
    """
    target_hosts = root.find(
        "Policy/Preferences/ServerPreferences/preference/[name='TARGET']/value"
    )
    target_hosts_final_list = []
    if target_hosts is not None:
        target_hosts = target_hosts.text
        target_hosts_splitted = target_hosts.split(",")
        target_hosts_splitted_lower = [
            element.lower() for element in target_hosts_splitted
        ]
        # if nessus file comes from Tenable.sc remove '[ip]' from target
        target_hosts_splitted_lower_clear = [
            element.split("[", 1)[0] for element in target_hosts_splitted_lower
        ]
        # if nessus file comes from Tenable.sc convert IP ranges in target into separate IP addresses
        for target in target_hosts_splitted_lower_clear:
            if re.match(
                "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}",
                target,
            ):
                address_range = utilities.ip_range_split(target)
                for address in address_range:
                    target_hosts_final_list.append(str(address))
            elif re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}", target):
                address_range = utilities.ip_range_split(target)
                for address in address_range:
                    target_hosts_final_list.append(str(address))
            else:
                target_hosts_final_list.append(target)
    else:
        target_hosts_final_list = None
    return target_hosts_final_list


def list_of_target_hosts_sc_fqdn_ip(root):
    """
    Function returns list of target hosts as dictionary of fqdn and ip. Works only if nessus file comes from Tenable.sc.
    :param root: root element of scan file tree
    :return: dictionary of fqdn and ip
    """
    target_list = []
    target_hosts = root.find(
        "Policy/Preferences/ServerPreferences/preference/[name='TARGET']/value"
    )
    if target_hosts is not None:
        target_hosts = target_hosts.text
        target_hosts_splitted = target_hosts.split(",")
        for target in target_hosts_splitted:
            target_splitted = target[:-1].split("[")
            if len(target_splitted) == 2:
                target_list.append(
                    {"target_fqdn": target_splitted[0], "target_ip": target_splitted[1]}
                )
    else:
        target_list = None
    return target_list


def report_hosts(root):
    """
    Function returns list of report hosts available in given file.
    :param root: root element of scan file tree
    :return: list report hosts
    """
    hosts = root.find("Report").findall("ReportHost")
    return hosts


def list_of_scanned_hosts(root):
    """
    Functions returns list of names of scanned hosts.
    :param root: root element of scan file tree
    :return: list of names of scanned hosts
    """
    report_hosts_names = list()
    for report_host in report_hosts(root):
        report_host_name = report_host.get("name")
        report_hosts_names.append(report_host_name)
    return report_hosts_names


def list_of_not_scanned_hosts(root):
    """
    Function returns list of not scanned hosts.
    :param root: root element of scan file tree
    :return: list of not scanned hosts or empty list
    """
    target_hosts = list_of_target_hosts(root)
    scanned_hosts = list_of_scanned_hosts(root)
    if target_hosts:
        not_scanned_hosts = list(set(target_hosts) - set(scanned_hosts))
    else:
        not_scanned_hosts = None
    return not_scanned_hosts


def number_of_target_hosts(root):
    """
    Function returns number of target hosts.
    :param root: root element of scan file tree
    :return: number of target hosts
    """
    target_hosts = list_of_target_hosts(root)
    if target_hosts is not None:
        number_of_targets = len(target_hosts)
    else:
        number_of_targets = None
    return number_of_targets


def number_of_target_hosts_without_duplicates(root):
    """
    Function returns number of actual target hosts (without duplicated entries).
    :param root: root element of scan file tree
    :return: number of actual target hosts
    """
    target_hosts = list_of_target_hosts(root)

    if target_hosts:
        actual_number_of_targets = len(set(target_hosts))
    else:
        actual_number_of_targets = None

    return actual_number_of_targets


def number_of_scanned_hosts(root):
    """
    Function returns number of scanned hosts.
    :param root: root element of scan file tree
    :return: number of scanned hosts
    """
    number = len(list_of_scanned_hosts(root))
    return number


def number_of_not_scanned_hosts(root):
    """
    Function returns number of not scanned hosts.
    :param root: root element of scan file tree
    :return: number of not scanned hosts
    """
    not_scanned_hosts = list_of_not_scanned_hosts(root)
    if not_scanned_hosts:
        number_of_not_scanned_hosts = len(not_scanned_hosts)
    else:
        number_of_not_scanned_hosts = None
    return number_of_not_scanned_hosts


def number_of_scanned_hosts_with_credentialed_checks_yes(root):
    """
    Function returns number of scanned hosts with credentialed checks yes.
    :param root: root element of scan file tree
    :return: number of scanned hosts with credentialed checks yes
    """
    number_of_report_hosts_with_credentialed_checks = 0

    for report_host in report_hosts(root):
        pido_19506 = plugin.plugin_output(root, report_host, "19506")
        if (
            "no output recorded" in pido_19506
            or "check Audit Trail" in pido_19506
            or "not enabled." in pido_19506
            or "info about used plugins not available" in pido_19506
        ):
            number_of_report_hosts_with_credentialed_checks = None
        else:
            for line in pido_19506.split("\n"):
                if re.findall("Credentialed checks :", line):
                    if re.findall("yes", line):
                        number_of_report_hosts_with_credentialed_checks += 1

    return number_of_report_hosts_with_credentialed_checks


def number_of_scanned_dbs_with_credentialed_checks_yes(root):
    """
    Function returns number of scanned dbs with credentialed checks yes.
    :param root: root element of scan file tree
    :return: number of scanned dbs with credentialed checks yes
    """
    number_of_scanned_dbs_with_credentialed_checks = 0

    for report_host in report_hosts(root):

        # "91825: Oracle DB Login Possible"
        pido_91825 = plugin.plugin_output(root, report_host, "91825")
        if re.findall(
            "Credentialed checks have been enabled for Oracle RDBMS server", pido_91825
        ):
            number_of_scanned_dbs_with_credentialed_checks += 1

        # "91827: Oracle DB Login Possible"
        pido_91827 = plugin.plugin_output(root, report_host, "91827")
        if re.findall(
            "Credentialed checks have been enabled for MSSQL server", pido_91827
        ):
            number_of_scanned_dbs_with_credentialed_checks += 1

    return number_of_scanned_dbs_with_credentialed_checks


def scan_time_start(root):
    """
    Function returns scan time start.
    :param root: root element of scan file tree
    :return: date and time when scan has been started
    """

    min_date_start_check = root.find(
        "Report/ReportHost[1]/HostProperties/tag/[@name='HOST_START']"
    )

    if min_date_start_check is not None:
        min_date_start = min_date_start_check.text
        min_date_start_parsed = datetime.datetime.strptime(
            min_date_start, "%a %b %d %H:%M:%S %Y"
        )

        max_date_end = root.find(
            "Report/ReportHost[1]/HostProperties/tag/[@name='HOST_END']"
        ).text
        max_date_end_parsed = datetime.datetime.strptime(
            max_date_end, "%a %b %d %H:%M:%S %Y"
        )

        for reportHost in root.find("Report").findall("ReportHost"):
            host_end_time_find = reportHost[0].find("tag/[@name='HOST_END']")
            if host_end_time_find is not None:
                host_end_time = host_end_time_find.text
            host_start_time = reportHost[0].find("tag/[@name='HOST_START']").text

            host_end_time_parsed = datetime.datetime.strptime(
                host_end_time, "%a %b %d %H:%M:%S %Y"
            )
            host_start_time_parsed = datetime.datetime.strptime(
                host_start_time, "%a %b %d %H:%M:%S %Y"
            )

            if min_date_start_parsed > host_start_time_parsed:
                min_date_start_parsed = host_start_time_parsed

            if max_date_end_parsed < host_end_time_parsed:
                max_date_end_parsed = host_end_time_parsed
    else:
        min_date_start_parsed = None
    return min_date_start_parsed


def scan_time_end(root):
    """
    Function returns scan time end.
    :param root: root element of scan file tree
    :return: date and time when scan has been ended
    """

    min_date_start_check = root.find(
        "Report/ReportHost[1]/HostProperties/tag/[@name='HOST_START']"
    )

    if min_date_start_check is not None:
        min_date_start = min_date_start_check.text
        min_date_start_parsed = datetime.datetime.strptime(
            min_date_start, "%a %b %d %H:%M:%S %Y"
        )

        max_date_end = root.find(
            "Report/ReportHost[1]/HostProperties/tag/[@name='HOST_END']"
        ).text
        max_date_end_parsed = datetime.datetime.strptime(
            max_date_end, "%a %b %d %H:%M:%S %Y"
        )

        for reportHost in root.find("Report").findall("ReportHost"):
            host_end_time_find = reportHost[0].find("tag/[@name='HOST_END']")
            if host_end_time_find is not None:
                host_end_time = host_end_time_find.text
            host_start_time = reportHost[0].find("tag/[@name='HOST_START']").text

            host_end_time_parsed = datetime.datetime.strptime(
                host_end_time, "%a %b %d %H:%M:%S %Y"
            )
            host_start_time_parsed = datetime.datetime.strptime(
                host_start_time, "%a %b %d %H:%M:%S %Y"
            )

            if min_date_start_parsed > host_start_time_parsed:
                min_date_start_parsed = host_start_time_parsed

            if max_date_end_parsed < host_end_time_parsed:
                max_date_end_parsed = host_end_time_parsed
    else:
        max_date_end_parsed = None
    return max_date_end_parsed


def scan_time_elapsed(root):
    """
    Function returns scan time elapsed in format HH:MM:SS
    :param root: root element of scan file tree
    :return: scan time elapsed in format HH:MM:SS
    """

    min_date_start_check = root.find(
        "Report/ReportHost[1]/HostProperties/tag/[@name='HOST_START']"
    )

    if min_date_start_check is not None:
        min_date_start = min_date_start_check.text
        min_date_start_parsed = datetime.datetime.strptime(
            min_date_start, "%a %b %d %H:%M:%S %Y"
        )
        max_date_end = root.find(
            "Report/ReportHost[1]/HostProperties/tag/[@name='HOST_END']"
        ).text
        max_date_end_parsed = datetime.datetime.strptime(
            max_date_end, "%a %b %d %H:%M:%S %Y"
        )

        for reportHost in root.find("Report").findall("ReportHost"):
            host_end_time_find = reportHost[0].find("tag/[@name='HOST_END']")
            if host_end_time_find is not None:
                host_end_time = host_end_time_find.text
            host_start_time = reportHost[0].find("tag/[@name='HOST_START']").text

            host_end_time_parsed = datetime.datetime.strptime(
                host_end_time, "%a %b %d %H:%M:%S %Y"
            )
            host_start_time_parsed = datetime.datetime.strptime(
                host_start_time, "%a %b %d %H:%M:%S %Y"
            )

            if min_date_start_parsed > host_start_time_parsed:
                min_date_start_parsed = host_start_time_parsed

            if max_date_end_parsed < host_end_time_parsed:
                max_date_end_parsed = host_end_time_parsed

        whole_scan_duration = max_date_end_parsed - min_date_start_parsed
        whole_scan_duration_parsed = str(whole_scan_duration)

    else:
        whole_scan_duration_parsed = None
    return whole_scan_duration_parsed
