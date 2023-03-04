# nessus file reader

**nessus file reader** by LimberDuck (pronounced *ˈlɪm.bɚ dʌk*) is a CLI tool 
and python module created to quickly parse nessus files containing the results 
of scans performed by using Nessus and Tenable.sc by (C) Tenable, Inc. This module will let 
you get data through functions grouped into categories like `file`, `scan`, `host` 
and `plugin` to get specific information from the provided nessus scan files.

[![Latest Release version](https://img.shields.io/github/v/release/LimberDuck/nessus-file-reader?label=Latest%20release)](https://github.com/LimberDuck/nessus-file-reader/releases)
[![GitHub Release Date](https://img.shields.io/github/release-date/limberduck/nessus-file-reader?label=released&logo=GitHub)](https://github.com/LimberDuck/nessus-file-reader/releases)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/nessus-file-reader?logo=PyPI)](https://pypistats.org/packages/nessus-file-reader)

[![License](https://img.shields.io/github/license/LimberDuck/nessus-file-reader.svg)](https://github.com/LimberDuck/nessus-file-reader/blob/master/LICENSE)
[![Repo size](https://img.shields.io/github/repo-size/LimberDuck/nessus-file-reader.svg)](https://github.com/LimberDuck/nessus-file-reader)
[![Code size](https://img.shields.io/github/languages/code-size/LimberDuck/nessus-file-reader.svg)](https://github.com/LimberDuck/nessus-file-reader)
[![Supported platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg)](https://github.com/LimberDuck/nessus-file-reader)

![](https://user-images.githubusercontent.com/9287709/222918443-5c88c441-e7b7-4298-93a2-a730fd8ff081.png)

## Main features

* read data from nessus files containing results of scans performed by using Nessus and Tenable.sc by (C) Tenable, Inc.
* use it in CLI to check quickly e.g. quality of your scan
* use it as python module

> Check code [examples].


## Installation

> **Note:**
> It's advisable to use python virtual environment for below instructions. Read more about python virtual environment in [The Hitchhiker’s Guide to Python!](https://docs.python-guide.org/dev/virtualenvs/)
> 
>Read about [virtualenvwrapper in The Hitchhiker’s Guide to Python!](https://docs.python-guide.org/dev/virtualenvs/#virtualenvwrapper): [virtualenvwrapper](https://virtualenvwrapper.readthedocs.io) provides a set of commands which makes working with virtual environments much more pleasant.


Install **nessus file reader**
    
`pip install nessus-file-reader`

> To upgrade to newer version run:
> 
> `pip install -U nessus-file-reader`


## How to

### Use nfr in CLI

1. Run **nessus file reader**

   `nfr`

2. Check help for commands
   
   `nfr [command] --help` e.g. `nfr file --help`

#### File command

Run `nfr file --help` to see options related to nessus file.

##### File size

Check size of given file:
```commandline
nfr file --size test_files/scan_avrx9t.nessus
nessus file reader by LimberDuck 0.4.2
test_files/scan_avrx9t.nessus 2.4 MiB
```

more than one file:
```commandline
nfr file --size test_files/scan_avrx9t.nessus test_files/scan_ihc1js.nessus
nessus file reader by LimberDuck 0.4.2
test_files/scan_avrx9t.nessus 2.4 MiB
test_files/scan_ihc1js.nessus 5.0 MiB
```

all files in given directory and it's subdirectories:
```commandline
nfr file --size test_files  
nessus file reader by LimberDuck 0.4.2                                                      
test_files/scan_avrx9t.nessus 2.4 MiB
test_files/scan_ihc1js.nessus 5.0 MiB
test_files/test_subdirectory/scan_ihc1js.nessus 878.3 KiB
```

##### File structure

Check structure of given file:

```commandline
nfr file --structure test_files/scan_avrx9t.nessus
nessus file reader by LimberDuck 0.4.2
test_files/scan_avrx9t.nessus
Policy [2/2]
├── policyName [3/3]
├── Preferences [2/3]
│   ├── ServerPreferences [1/1]
│   │   ├── preference [54/54]
│   │   │   ├── name [1/1]
│   │   │   └── value [0/1]
│   │   ├── preference [53/54]
...
│   └── PluginsPreferences [0/1]
│       ├── item [506/506]
│       │   ├── pluginName [6/6]
│       │   ├── pluginId [5/6]
│       │   ├── fullName [4/6]
│       │   ├── preferenceName [3/6]
│       │   ├── preferenceType [2/6]
│       │   ├── preferenceValues [1/6]
│       │   └── selectedValue [0/6]
│       ├── item [505/506]
...
├── FamilySelection [1/3]
│   ├── FamilyItem [53/53]
│   │   ├── FamilyName [1/1]
│   │   └── Status [0/1]
│   ├── FamilyItem [52/53]
│   │   ├── FamilyName [1/1]
│   │   └── Status [0/1]
...
└── IndividualPluginSelection [0/3]
│   ├── PluginItem [6/6]
│   │   ├── PluginId [3/3]
│   │   ├── PluginName [2/3]
│   │   ├── Family [1/3]
│   │   └── Status [0/3]
...
Report [1/2]
└── ReportHost [0/0]
    ├── HostProperties [409/409]
    │   ├── tag [354/354]
    │   ├── tag [353/354]
...
    ├── ReportItem [408/409]
    │   ├── agent [12/12]
    │   ├── description [11/12]
    │   ├── fname [10/12]
    │   ├── plugin_modification_date [9/12]
    │   ├── plugin_name [8/12]
    │   ├── plugin_publication_date [7/12]
    │   ├── plugin_type [6/12]
    │   ├── risk_factor [5/12]
    │   ├── script_version [4/12]
    │   ├── see_also [3/12]
    │   ├── solution [2/12]
    │   ├── synopsis [1/12]
    │   └── plugin_output [0/12]
...
```

Check whole example structure [examples/scan_avrx9t_structure.txt](examples/scan_avrx9t_structure.txt).

#### Scan command

Run `nfr scan --help` to see options related to content of nessus file on scan level.

##### Scan summary

See scan summary of given file/-s or all files in given directory and it's subdirectories:

```commandline
nfr scan --scan-summary scan_avrx9t.nessus
nessus file reader by LimberDuck 0.4.2
File name           Report name     TH    SH    CC    C    H    M    L    N
------------------  ------------  ----  ----  ----  ---  ---  ---  ---  ---
scan_avrx9t.nessus  test scan        1     1     1   48  182  126   15   38
```

```commandline
nfr scan --scan-summary-legend                              
nessus file reader by LimberDuck 0.4.2
Legend for scan summary:
File name - nessus file name
Report name - report name for given nessus file name
TH - number of target hosts
SH - number of scanned hosts
CC - number of hosts scanned with credentials (Credentialed checks yes in Plugin ID 19506)
C - number of plugins with Critical risk factor for whole scan
H - number of plugins with High risk factor for whole scan
M - number of plugins with Medium risk factor for whole scan
L - number of plugins with Low risk factor for whole scan
N - number of plugins with None risk factor for whole scan
```

##### Policy scan summary

See policy scan summary of given file/-s or all files in given directory and it's subdirectories:

```commandline
nfr scan --policy-summary scan_ihc1js.nessus scan_avrx9t.nessus
nessus file reader by LimberDuck 0.4.2
File name           Policy name      Max hosts    Max checks    Checks timeout    Plugins number
------------------  -------------  -----------  ------------  ----------------  ----------------
scan_ihc1js.nessus  Advanced Scan          100             5                 5            103203
scan_avrx9t.nessus  Test                   100             5                 5            103949

```

##### Scan file source

See scan file source like Nessus, Tenable.sc, Tenable.io of given file/-s or all files in given directory and it's subdirectories:

```commandline
nfr scan --scan-file-source scan_ihc1js.nessus scan_avrx9t.nessus
nessus file reader by LimberDuck 0.4.2
File name           Source
------------------  ----------
scan_ihc1js.nessus  Tenable.sc
scan_avrx9t.nessus  Nessus
```

### Use nfr as python module

1. Import `nessus-file-reader` module.
   
```python
import nessus_file_reader as nfr
```

2. Use `file` functions to get details about provided file e.g. root, file name, file size.
   
```python
import nessus_file_reader as nfr

nessus_scan_file = './your_nessus_file.nessus'
root = nfr.file.nessus_scan_file_root_element(nessus_scan_file)
file_name = nfr.file.nessus_scan_file_name_with_path(nessus_scan_file)
file_size = nfr.file.nessus_scan_file_size_human(nessus_scan_file)
print(f'File name: {file_name}')
print(f'File size: {file_size}')
```

3. Use `scan` functions to get details about provided scan e.g. report name, number of target/scanned/credentialed hosts, scan time start/end/elapsed and more.

```python
import nessus_file_reader as nfr
nessus_scan_file = './your_nessus_file.nessus'
root = nfr.file.nessus_scan_file_root_element(nessus_scan_file)

report_name = nfr.scan.report_name(root)
number_of_target_hosts = nfr.scan.number_of_target_hosts(root)
number_of_scanned_hosts = nfr.scan.number_of_scanned_hosts(root)
number_of_scanned_hosts_with_credentialed_checks_yes = nfr.scan.number_of_scanned_hosts_with_credentialed_checks_yes(root)
scan_time_start = nfr.scan.scan_time_start(root)
scan_time_end = nfr.scan.scan_time_end(root)
scan_time_elapsed = nfr.scan.scan_time_elapsed(root)
print(f' Report name: {report_name}')
print(f' Number of target/scanned/credentialed hosts: {number_of_target_hosts}/{number_of_scanned_hosts}/{number_of_scanned_hosts_with_credentialed_checks_yes}')
print(f' Scan time START - END (ELAPSED): {scan_time_start} - {scan_time_end} ({scan_time_elapsed})')
```

4. Use `host` functions to get details about hosts from provided scan e.g. report hosts names, operating system, hosts scan time start/end/elapsed, number of Critical/High/Medium/Low/None findings and more.

```python
import nessus_file_reader as nfr
nessus_scan_file = './your_nessus_file.nessus'
root = nfr.file.nessus_scan_file_root_element(nessus_scan_file)

for report_host in nfr.scan.report_hosts(root):
   report_host_name = nfr.host.report_host_name(report_host)
   report_host_os = nfr.host.detected_os(report_host)
   report_host_scan_time_start = nfr.host.host_time_start(report_host)
   report_host_scan_time_end = nfr.host.host_time_end(report_host)
   report_host_scan_time_elapsed = nfr.host.host_time_elapsed(report_host)
   report_host_critical = nfr.host.number_of_plugins_per_risk_factor(report_host, 'Critical')
   report_host_high = nfr.host.number_of_plugins_per_risk_factor(report_host, 'High')
   report_host_medium = nfr.host.number_of_plugins_per_risk_factor(report_host, 'Medium')
   report_host_low = nfr.host.number_of_plugins_per_risk_factor(report_host, 'Low')
   report_host_none = nfr.host.number_of_plugins_per_risk_factor(report_host, 'None')
   print(f'  Report host name: {report_host_name}')
   print(f'  Report host OS: {report_host_os}')
   print(f'  Host scan time START - END (ELAPSED): {report_host_scan_time_start} - {report_host_scan_time_end} ({report_host_scan_time_elapsed})')
   print(f'  Critical/High/Medium/Low/None findings: {report_host_critical}/{report_host_high}/{report_host_medium}/{report_host_low}/{report_host_none}')
```

5. Use `plugin` functions to get details about plugins reported in provided scan e.g. plugins ID, plugins risk factor, plugins name.

```python
import nessus_file_reader as nfr
nessus_scan_file = './your_nessus_file.nessus'
root = nfr.file.nessus_scan_file_root_element(nessus_scan_file)

for report_host in nfr.scan.report_hosts(root):
   report_items_per_host = nfr.host.report_items(report_host)
   for report_item in report_items_per_host:
      plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
      risk_factor = nfr.plugin.report_item_value(report_item, 'risk_factor')
      plugin_name = nfr.plugin.report_item_value(report_item, 'pluginName')
      print('\t', plugin_id, '  \t\t\t', risk_factor, '  \t\t\t', plugin_name)
```

6. If you want to get output for interesting you plugin e.g. "Nessus Scan Information" use below function

```python
import nessus_file_reader as nfr
nessus_scan_file = './your_nessus_file.nessus'
root = nfr.file.nessus_scan_file_root_element(nessus_scan_file)

for report_host in nfr.scan.report_hosts(root):
   pido_19506 = nfr.plugin.plugin_output(root, report_host, '19506')
   print(f'Nessus Scan Information Plugin Output:\n{pido_19506}')
```

7. If you know that interesting you plugin occurs more than ones for particular host e.g. "Netstat Portscanner (SSH)" use below function

```python
import nessus_file_reader as nfr
nessus_scan_file = './your_nessus_file.nessus'
root = nfr.file.nessus_scan_file_root_element(nessus_scan_file)

for report_host in nfr.scan.report_hosts(root):
   pidos_14272 = nfr.plugin.plugin_outputs(root, report_host, '14272')
   print(f'All findings for Netstat Portscanner (SSH): \n{pidos_14272}')
```

## Meta

### Change log

See [CHANGELOG].

### Licence

GNU GPLv3: [LICENSE].

### Authors

[Damian Krawczyk] created **[nessus file reader]** by [LimberDuck].

[nessus file reader]: https://limberduck.org/en/latest/tools/nessus-file-reader
[Damian Krawczyk]: https://damiankrawczyk.com
[LimberDuck]: https://limberduck.org
[CHANGELOG]: https://github.com/LimberDuck/nessus-file-reader/blob/master/CHANGELOG.md
[LICENSE]: https://github.com/LimberDuck/nessus-file-reader/blob/master/LICENSE
[examples]: https://github.com/LimberDuck/nessus-file-reader/tree/master/examples
