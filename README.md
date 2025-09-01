# nessus file reader (NFR)

**nessus file reader (NFR) by LimberDuck** (pronounced *ˈlɪm.bɚ dʌk*) is a CLI tool 
and python module created to quickly parse nessus files containing the results 
of scans performed using Nessus and Tenable.sc by (C) Tenable, Inc. This module will let 
you get data through functions grouped into categories like `file`, `scan`, `host` 
and `plugin` to get specific information from the provided nessus scan files.

[![pepy - Downloads](https://img.shields.io/pepy/dt/nessus-file-reader?logo=PyPI)](https://pepy.tech/projects/nessus-file-reader) [![PyPI Downloads](https://static.pepy.tech/badge/nessus-file-reader/month)](https://pepy.tech/projects/nessus-file-reader)
[![Latest Release version](https://img.shields.io/github/v/release/LimberDuck/nessus-file-reader?label=Latest%20release)](https://github.com/LimberDuck/nessus-file-reader/releases)
[![GitHub Release Date](https://img.shields.io/github/release-date/limberduck/nessus-file-reader?label=released&logo=GitHub)](https://github.com/LimberDuck/nessus-file-reader/releases)
[![License](https://img.shields.io/github/license/LimberDuck/nessus-file-reader.svg)](https://github.com/LimberDuck/nessus-file-reader/blob/master/LICENSE)
[![Repo size](https://img.shields.io/github/repo-size/LimberDuck/nessus-file-reader.svg)](https://github.com/LimberDuck/nessus-file-reader)
[![Code size](https://img.shields.io/github/languages/code-size/LimberDuck/nessus-file-reader.svg)](https://github.com/LimberDuck/nessus-file-reader)
[![Supported platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg)](https://github.com/LimberDuck/nessus-file-reader)
<!-- [![PyPI - Downloads](https://img.shields.io/pypi/dm/nessus-file-reader?logo=PyPI)](https://pypistats.org/packages/nessus-file-reader) -->

> [!NOTE]
> **Visit [LimberDuck.org][LimberDuck] to find out more!**

![](https://limberduck.org/en/latest/_images/nfr.png)

## Main features

* read data from nessus files containing results of scans performed by using Nessus and Tenable.sc by (C) Tenable, Inc.
* use it in CLI to check quickly e.g. quality of your scan, split large scan results
* use it as python module

> [!TIP]
> Check code [examples].


## Installation

> [!NOTE]
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
nessus file reader (NFR) by LimberDuck 0.4.2
test_files/scan_avrx9t.nessus 2.4 MiB
```

more than one file:
```commandline
nfr file --size test_files/scan_avrx9t.nessus test_files/scan_ihc1js.nessus
nessus file reader (NFR) by LimberDuck 0.4.2
test_files/scan_avrx9t.nessus 2.4 MiB
test_files/scan_ihc1js.nessus 5.0 MiB
```

all files in given directory and it's subdirectories:
```commandline
nfr file --size test_files  
nessus file reader (NFR) by LimberDuck 0.4.2                                                      
test_files/scan_avrx9t.nessus 2.4 MiB
test_files/scan_ihc1js.nessus 5.0 MiB
test_files/test_subdirectory/scan_ihc1js.nessus 878.3 KiB
```

##### File structure

Check structure of given file:

```commandline
nfr file --structure test_files/scan_avrx9t.nessus
nessus file reader (NFR) by LimberDuck 0.4.2
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

##### File split

Split the file with Nessus scan results into smaller files.

```commandline
nfr file --split 100 ./directory ./directory2
nessus file reader (NFR) by LimberDuck 0.5.0
./directory/192_168_8_0_24_3mf2o4.nessus
./directory/192_168_8_0_24_3mf2o4_part1.nessus
./directory/192_168_8_0_24_3mf2o4_part2.nessus
./directory/192_168_8_0_24_3mf2o4_part3.nessus
./directory/subdirectory/My_Advanced_Scan_for_192_168_8_0_24_rg2ny9.nessus
./directory/subdirectory/My_Advanced_Scan_for_192_168_8_0_24_rg2ny9_part1.nessus
./directory2/192_168_8_0_24_3mf2o4.nessus
./directory2/192_168_8_0_24_3mf2o4_part1.nessus
./directory2/192_168_8_0_24_3mf2o4_part2.nessus
./directory2/192_168_8_0_24_3mf2o4_part3.nessus
```

#### Scan command

Run `nfr scan --help` to see options related to content of nessus file on scan level.

##### Scan summary

See scan summary of given file/-s or all files in given directory and it's subdirectories:

```commandline
nfr scan --scan-summary scan_avrx9t.nessus
nessus file reader (NFR) by LimberDuck 0.4.2
File name           Report name     TH    SH    CC    C    H    M    L    N
------------------  ------------  ----  ----  ----  ---  ---  ---  ---  ---
scan_avrx9t.nessus  test scan        1     1     1   48  182  126   15   38
```

```commandline
nfr scan --scan-summary-legend                              
nessus file reader (NFR) by LimberDuck 0.4.2
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

##### Plugin severity

Compare severity scores assigned to plugin like Severity, Risk Factor, CVSSv2, CVSSv3, CVSSv4, VPR, EPSS.

```
nfr scan --plugin-severity-legend                         
nessus file reader (NFR) by LimberDuck 0.6.0
Legend for plugin severity:
File name - nessus file name
Report host name - target name used during scan
PID - Plugin ID reported in scan
S - Severity number (0-4) of plugin
SL - Severity label of plugin (e.g. Critical, High, Medium, Low, None)
RF - Risk factor of plugin (e.g. Critical, High, Medium, Low, None)
CVSSv2 - CVSSv2 base score of plugin
CVSSv2L - CVSSv2 base score label of plugin
CVSSv3 - CVSSv3 base score of plugin
CVSSv3L - CVSSv3 base score label of plugin
CVSSv4 - CVSSv4 base score of plugin
CVSSv4L - CVSSv4 base score label of plugin
VPR - Vulnerability Priority Rating score of plugin
VPRL - Vulnerability Priority Rating label of plugin
EPSS - Exploit Prediction Scoring System score of plugin
EPSS% - Exploit Prediction Scoring System score of plugin in percentage
```

Just point the name or path to nessus file with scan results.

```
nfr scan --plugin-severity 192_168_1_1_1022nb.nessus 
nessus file reader (NFR) by LimberDuck 0.6.0
File name                  Report host name       PID    S  SL      RF        CVSSv2  CVSSv2L      CVSSv3  CVSSv3L    CVSSv4    CVSSv4L      VPR  VPRL      EPSS  EPSS%
-------------------------  ------------------  ------  ---  ------  ------  --------  ---------  --------  ---------  --------  ---------  -----  ------  ------  -------
192_168_1_1_1022nb.nessus  192.168.1.10         12217    2  Medium  Medium       5    Medium          5.3  Medium
192_168_1_1_1022nb.nessus  192.168.1.10         42263    2  Medium  Medium       5.8  Medium          6.5  Medium
192_168_1_1_1022nb.nessus  192.168.1.10         50686    2  Medium  Medium       5.8  Medium          6.5  Medium                            4.9  Medium  0.0596  6.0%
192_168_1_1_1022nb.nessus  192.168.1.10         10114    1  Low     Low          2.1  Low                                                    2.2  Low     0.0037  0.4%
192_168_1_1_1022nb.nessus  192.168.1.10         10663    1  Low     Low          3.3  Low
192_168_1_1_1022nb.nessus  192.168.1.10         70658    1  Low     Low          2.6  Low             3.7  Low                               1.4  Low     0.0307  3.1%
192_168_1_1_1022nb.nessus  192.168.1.10         71049    1  Low     Low          2.6  Low
192_168_1_1_1022nb.nessus  192.168.1.10        153953    1  Low     Low          2.6  Low             3.7  Low
192_168_1_1_1022nb.nessus  192.168.1.10         10107    0  Info    None
192_168_1_1_1022nb.nessus  192.168.1.10         10267    0  Info    None
```

Use `-f` or `--filter` to check only one Plugin ID among all scan results. Read more about [JMESPath](https://jmespath.org).

```
nfr scan --plugin-severity *.nessus -f "[?PID == '50686']"
nessus file reader (NFR) by LimberDuck 0.6.0
File name                          Report host name      PID    S  SL      RF        CVSSv2  CVSSv2L      CVSSv3  CVSSv3L    CVSSv4    CVSSv4L      VPR  VPRL      EPSS  EPSS%
---------------------------------  ------------------  -----  ---  ------  ------  --------  ---------  --------  ---------  --------  ---------  -----  ------  ------  -------
192_168_1_1_1022nb-1.nessus          192.168.1.10        50686    2  Medium  Medium       5.8  Medium          6.5  Medium                            4.9  Medium  0.0596  6.0%
192_168_1_1_1022nb-2.nessus          192.168.1.10        50686    2  Medium  Medium       5.8  Medium          6.5  Medium                            4.9  Medium  0.0596  6.0%
```

Use `-f` or `--filter` to check only these plugins which have VPR assigned. Read more about [JMESPath](https://jmespath.org).

```
nfr scan --plugin-severity 192_168_1_1_1022nb.nessus -f "[?VPR != null]"   
nessus file reader (NFR) by LimberDuck 0.6.0
File name                  Report host name      PID    S  SL      RF        CVSSv2  CVSSv2L      CVSSv3  CVSSv3L    CVSSv4    CVSSv4L      VPR  VPRL      EPSS  EPSS%
-------------------------  ------------------  -----  ---  ------  ------  --------  ---------  --------  ---------  --------  ---------  -----  ------  ------  -------
192_168_1_1_1022nb.nessus  192.168.1.10        50686    2  Medium  Medium       5.8  Medium          6.5  Medium                            4.9  Medium  0.0596  6.0%
192_168_1_1_1022nb.nessus  192.168.1.10        10114    1  Low     Low          2.1  Low                                                    2.2  Low     0.0037  0.4%
192_168_1_1_1022nb.nessus  192.168.1.10        70658    1  Low     Low          2.6  Low             3.7  Low                               1.4  Low     0.0307  3.1%
```

Use `-f` or `--filter` to check only these plugins which have, e.g., CVSSv3 score greater than `4.0`. Read more about [JMESPath](https://jmespath.org).

```
nfr scan --plugin-severity 192_168_1_1_1022nb.nessus -f "[?CVSSv3 > '4.0']"
nessus file reader (NFR) by LimberDuck 0.6.0
File name                  Report host name      PID    S  SL      RF        CVSSv2  CVSSv2L      CVSSv3  CVSSv3L    CVSSv4    CVSSv4L      VPR  VPRL      EPSS  EPSS%
-------------------------  ------------------  -----  ---  ------  ------  --------  ---------  --------  ---------  --------  ---------  -----  ------  ------  -------
192_168_1_1_1022nb.nessus  192.168.1.10        12217    2  Medium  Medium       5    Medium          5.3  Medium
192_168_1_1_1022nb.nessus  192.168.1.10        42263    2  Medium  Medium       5.8  Medium          6.5  Medium
192_168_1_1_1022nb.nessus  192.168.1.10        50686    2  Medium  Medium       5.8  Medium          6.5  Medium                            4.9  Medium  0.0596  6.0%
```


##### Policy scan summary

See policy scan summary of given file/-s or all files in given directory and it's subdirectories:

```commandline
nfr scan --policy-summary scan_ihc1js.nessus scan_avrx9t.nessus
nessus file reader (NFR) by LimberDuck 0.4.2
File name           Policy name      Max hosts    Max checks    Checks timeout    Plugins number
------------------  -------------  -----------  ------------  ----------------  ----------------
scan_ihc1js.nessus  Advanced Scan          100             5                 5            103203
scan_avrx9t.nessus  Test                   100             5                 5            103949

```

##### Scan file source

See scan file source like Nessus, Tenable.sc, Tenable.io of given file/-s or all files in given directory and it's subdirectories:

```commandline
nfr scan --scan-file-source scan_ihc1js.nessus scan_avrx9t.nessus
nessus file reader (NFR) by LimberDuck 0.4.2
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

[Damian Krawczyk] created **[nessus file reader (NFR)]** by [LimberDuck].

[nessus file reader (NFR)]: https://limberduck.org/en/latest/tools/nessus-file-reader
[Damian Krawczyk]: https://damiankrawczyk.com
[LimberDuck]: https://limberduck.org
[CHANGELOG]: https://github.com/LimberDuck/nessus-file-reader/blob/master/CHANGELOG.md
[LICENSE]: https://github.com/LimberDuck/nessus-file-reader/blob/master/LICENSE
[examples]: https://github.com/LimberDuck/nessus-file-reader/tree/master/examples