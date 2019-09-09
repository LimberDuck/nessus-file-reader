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
import datetime
from nessus_file_reader.scan import scan


def plugin_output(root, report_host, plugin_id):
    """
    Function returns plugin output for given plugin id. If particular plugin occurs in report more than once, plugin
    output of last occurrence is returned.
    :param root: root element of scan file tree
    :param report_host: scanned host
    :param plugin_id: plugin id
    :return:
        plugin_output - content of plugin output is returned if plugin occurs in report and has an output.
        'No  output recorded.' - information if plugin occurs in report but does not contain any output.
        'Check Audit Trail.' - information if plugin has been used during scan but does not appear in report at all.
        '{plugin_id} not enabled.' - information if plugin has not been enabled in policy for scan.

    """
    plugin_id = str(plugin_id)
    plugin_output_content = list()
    status = 0

    if plugin_id in scan.plugin_set(root):
        for report_item in report_host.findall("ReportItem"):
            plugin_id_from_report = report_item.get('pluginID')
            if plugin_id_from_report == plugin_id:
                plugin_output_item = report_item.find('plugin_output')
                if plugin_output_item is None:
                    plugin_output_content = 'No output recorded.'
                else:
                    plugin_output_content = plugin_output_item.text
                status = 1
        if status == 0:
            plugin_output_content = 'Check Audit Trail.'
    else:
        plugin_output_content = f'{plugin_id} not enabled.'
    return plugin_output_content


def plugin_outputs(root, report_host, plugin_id):
    """
    Function returns plugin output for given plugin id. If particular plugin occurs in report more than once, plugin
    outputs are concatenated and return as one.
    :param root: root element of scan file tree
    :param report_host: scanned host
    :param plugin_id: plugin id
    :return:
        plugin_output - content of plugin output is returned if plugin occurs in report and has an output.
        'No output recorded.' - information if plugin occurs in report but does not contain any output.
        'Check Audit Trail.' - information if plugin has been used during scan but does not appear in report at all.
        '{plugin_id} not enabled.' - information if plugin has not been enabled in policy for scan.

    """
    plugin_id = str(plugin_id)
    plugin_output_content = list()
    status = 0

    if plugin_id in scan.plugin_set(root):
        for report_item in report_host.findall("ReportItem"):
            plugin_id_from_report = report_item.get('pluginID')
            if plugin_id_from_report == plugin_id:
                plugin_output_item = report_item.find('plugin_output')
                if plugin_output_item is None:
                    plugin_output_content.append('No output recorded.')
                else:
                    plugin_output_content.append(plugin_output_item.text)
                status = 1
        if status == 0:
            plugin_output_content.append('Check Audit Trail.')

        if len(plugin_output_content) == 1:
            plugin_output_content = plugin_output_content[0]
        else:
            plugin_output_content = '\n'.join(plugin_output_content)
    else:
        plugin_output_content = f'{plugin_id} not enabled.'

    return plugin_output_content


def compliance_plugin(report_item):
    """
    Function checks if given report item is compliance plugin.
    :param report_item: particular report item for scanned host
    :return:
        True if report item is compliance
        False if report item is not compliance
    """
    compliance = report_item_value(report_item, 'compliance')
    plugin_type_compliance = False
    if compliance is not None:
        if compliance == 'true':
            plugin_type_compliance = True
    else:
        plugin_type_compliance = False

    return plugin_type_compliance


def report_item_value(report_item, report_item_name):
    """
    Function returns value of given report item e.g. pluginName
    :param report_item: particular report item for scanned host
    :param report_item_name: exact report item name for scanned host
    :return: value of given report item
    """
    report_item_content_value = report_item.get(report_item_name)

    if report_item_content_value is None:
        report_item_content = report_item.find(report_item_name)
        if report_item_content is not None:
            report_item_content_value = report_item_content.text
    return report_item_content_value


def report_item_values(report_item, report_item_name):
    """
    Function returns list of all values of given report item e.g. list of CVE numbers
    :param report_item: particular report item for scanned host
    :param report_item_name: exact report item name for scanned host
    :return: value of given report item
    """
    report_item_values_list = []
    report_item_content_values = report_item.findall(report_item_name)
    for report_item_content_value in report_item_content_values:
        report_item_values_list.append(report_item_content_value.text)
    return report_item_values_list


def compliance_check_item_value(report_item, compliance_check_item_name):
    """
    Function returns value of given compliance check item e.g. cm:compliance-check-name
    :param report_item: particular report item for scanned host
    :param compliance_check_item_name: exact compliance check item name for scanned host
    :return: value of given compliance check item name
    """
    compliance_check_item_content_value = None
    compliance = report_item.find('compliance')
    if compliance is not None:
        if compliance.text == 'true':
            compliance_check_item_content = \
                report_item.find(compliance_check_item_name, namespaces={'cm': 'http://www.nessus.org/cm'})
            if compliance_check_item_content is not None:
                compliance_check_item_content_value = compliance_check_item_content.text
    return compliance_check_item_content_value


def plugin_date(date):
    """
    Function convert given plugin date e.g. plugin_publication_date
    :param date: date from plugin
    :return: formatted date
    """
    date_dash = re.search("\d{4}-\d{2}-\d{2}", date)
    date_slash = re.search("\d{4}/\d{2}/\d{2}", date)

    if date_dash:
        date_formatted = datetime.datetime.strptime(date, "%Y-%m-%d").date()
    elif date_slash:
        date_formatted = datetime.datetime.strptime(date, "%Y/%m/%d").date()
    else:
        date_formatted = None
    return date_formatted
