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

import os
from xml.etree.ElementTree import parse


def nessus_scan_file_name_with_path(file):
    """
    Function returns a normalized absolute version of the path.
    :param file: given nessus file
    :return: normalized absolute version of the given file path.
    """
    nessus_scan_file_name = os.path.abspath(file)
    return nessus_scan_file_name


def nessus_scan_file_size(file):
    """
    Function returns the size in bytes of path.
    :param file: given nessus file
    :return: size in bytes of path.
    """
    file_size = os.path.getsize(file)
    return file_size


def nessus_scan_file_size_human(file):
    """
    Function convert nessus file size from bytes to size more convenient to read by human.
    :param file: given nessus file
    :return: size in human readable form
    """
    size = nessus_scan_file_size(file)
    suffix = "B"
    for unit in [" b", " Ki", " Mi", " Gi", " Ti", " Pi", " Ei", " Zi"]:
        if abs(size) < 1024.0:
            return "%3.1f%s%s" % (size, unit, suffix)
        size /= 1024.0
    return "%.1f%s%s" % (size, "Yi", suffix)


def nessus_scan_file_root_element(file):
    """
    Function returns the root element for tree of given nessus file with scan results.
    :param file: given nessus file
    :return: root element for this tree.
    """

    nessus_scan_file_parsed = parse(file)
    root = nessus_scan_file_parsed.getroot()
    return root
