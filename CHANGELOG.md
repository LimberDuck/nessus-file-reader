# Change Log

This document records all notable changes to [nessus file reader by LimberDuck][1].

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.4.0]: https://github.com/LimberDuck/nessus-file-reader/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/LimberDuck/nessus-file-reader/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/LimberDuck/nessus-file-reader/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/LimberDuck/nessus-file-reader/releases/tag/v0.1.0

[1]: https://github.com/LimberDuck/nessus-file-reader