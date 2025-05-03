# Change Log

This document records all notable changes to [nessus file reader by LimberDuck][1].

Visit [LimberDuck.org][2] to find out more!

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2025-05-03

### Added

- Splitting the file with Nessus scan results into smaller files.

## [0.4.3] - 2025-02-19

### Changed

- code formatted with [black](https://black.readthedocs.io)
- requirements update
  - from:
    - click>=8.1.3
    - tabulate>=0.8.9
  - to:
    - click>=8.1.8
    - tabulate>=0.9.0

- tests for python
  - added: 3.10, 3.11, 3.12, 3.13
  - removed: 3.7

## [0.4.2] - 2023-03-04

### Changed

- [README.md](README.md) updated with example `nfr` commadline usage.
- `nfr scan --scan-summary` has simplified column names, to save space on the screen:
  - `nessus_scan_file` -> `File name`
  - `report_name` -> `Report name`
  - `number_of_target_hosts` -> `TH`
  - `number_of_scanned_hosts` -> `SH`
  - `number_of_scanned_hosts_with_credentialed_checks_yes` -> `CC`
- `nfr scan --scan-summary` has 5 new columns
  - `C`, `H`, `M`, `L`, `N`, accordingly number of plugins with Critical, High, Medium, Low and None risk factor for whole scan  
- `nfr scan --scan-summary-legend` command to see columns description
- `nfr scan --policy-name` option changed to `--policy-summary`
- `nfr scan --policy-summary` informs about Policy name and settings like Max hosts, Max checks, Check timeout, 
Plugins number used during the scan.
- `nfr scan --source-of-file` option changed to `--scan-file-source`

### Fixed

- `detected_os()` function in `host.py` handles situation if there is no Operating System detected 
(reported by [ricardosupo](https://github.com/ricardosupo) in issue 
[#8](https://github.com/LimberDuck/nessus-file-reader/issues/8#issue-1236020632)).
- `nfr` CLI handles `FileNotFoundError` when you give nessus files or directory which doesn't exist.

## [0.4.1] - 2022-05-13

### Fixed

- requirements installation fixed

## [0.4.0] - 2022-05-13

### Added

- **commandline interface** - from now on this package will provide you possibility to run `nfr` in commandline. After installation type `nfr` or `nfr --help` to find out more.
- **Tenable.io files support** - initial support to pars nessus files coming from Tenable.io


## [0.3.0] - 2020-07-25

### Added

- new function host.netbios_network_name - to get NetBIOS Computer Name, Workgroup / Domain name for given target. 

### Changed

- possibility to pars network address with mask in target

## [0.2.0] - 2019-09-09

### Added

- new function plugin.report_item_values - to get list of values for all items with given name e.g. 'cve'


## [0.1.0] - 2019-06-23

- Initial release

[0.5.0]: https://github.com/LimberDuck/nessus-file-reader/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/LimberDuck/nessus-file-reader/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/LimberDuck/nessus-file-reader/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/LimberDuck/nessus-file-reader/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/LimberDuck/nessus-file-reader/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/LimberDuck/nessus-file-reader/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/LimberDuck/nessus-file-reader/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/LimberDuck/nessus-file-reader/releases/tag/v0.1.0

[1]: https://github.com/LimberDuck/nessus-file-reader
[2]: https://limberduck.org