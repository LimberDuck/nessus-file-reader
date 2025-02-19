from nessus_file_reader._version import __version__
import click
import nessus_file_reader as nfr
from nessus_file_reader import utilities
import os
import glob
import tabulate


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo("Version {}".format(__version__))
    ctx.exit()


_file_arguments = [
    click.argument(
        "files",
        nargs=-1,
        type=click.Path(),
    )
]


def add_options(options):
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func

    return _add_options


def add_arguments(arguments):
    def _add_arguments(func):
        for argument in reversed(arguments):
            func = argument(func)
        return func

    return _add_arguments


@click.group()
@click.option(
    "--version", is_flag=True, callback=print_version, expose_value=False, is_eager=True
)
def cli():
    pass


@cli.command()
@add_arguments(_file_arguments)
@click.option("--size", is_flag=True, help="file size")
@click.option("--structure", is_flag=True, help="file structure")
def file(files, size, structure):
    """Options related to nessus file."""

    for file in files:

        if size:
            try:
                if os.path.isdir(file):
                    os_separator = os.path.sep
                    extension = "*.nessus"
                    list_of_source_files = glob.glob(
                        file + os_separator + "**" + os_separator + extension,
                        recursive=True,
                    )
                else:
                    list_of_source_files = [file]
                # print('')
                for row_index, nessus_scan_file in enumerate(list_of_source_files):
                    file_name_with_path = nfr.file.nessus_scan_file_name_with_path(
                        nessus_scan_file
                    )
                    file_size = nfr.file.nessus_scan_file_size_human(
                        file_name_with_path
                    )
                    print(nessus_scan_file, file_size)
            except FileNotFoundError as e:
                print(e.strerror)

        elif structure:
            try:
                if os.path.isdir(file):
                    os_separator = os.path.sep
                    extension = "*.nessus"
                    list_of_source_files = glob.glob(
                        file + os_separator + "**" + os_separator + extension,
                        recursive=True,
                    )
                else:
                    list_of_source_files = [file]
                for row_index, nessus_scan_file in enumerate(list_of_source_files):

                    print(nessus_scan_file)
                    utilities.nessus_scan_file_structure(nessus_scan_file)
            except FileNotFoundError as e:
                print(e.strerror)
        else:
            print("No parameters specified")


@cli.command()
@add_arguments(_file_arguments)
@click.option("--scan-summary", is_flag=True, help="Scan summary")
@click.option("--scan-summary-legend", is_flag=True, help="Show scan summary legend")
@click.option("--policy-summary", is_flag=True, help="Policy summary")
@click.option(
    "--scan-file-source",
    is_flag=True,
    help="Source of scan file e.g. Nessus, Tenable.sc, Tenable.io",
)
def scan(files, scan_summary, scan_summary_legend, scan_file_source, policy_summary):
    """Options related to content of nessus file on scan level."""

    if files:
        try:
            summary_data = []
            scan_file_source_data = []
            policy_summary_data = []
            for file in files:
                if os.path.isdir(file):
                    os_separator = os.path.sep
                    extension = "*.nessus"
                    list_of_source_files = glob.glob(
                        file + os_separator + "**" + os_separator + extension,
                        recursive=True,
                    )
                else:
                    list_of_source_files = [file]

                for row_index, nessus_scan_file in enumerate(list_of_source_files):

                    file_name_with_path = nfr.file.nessus_scan_file_name_with_path(
                        nessus_scan_file
                    )
                    file_size = nfr.file.nessus_scan_file_size_human(nessus_scan_file)
                    # print(nessus_scan_file, file_size)
                    root = nfr.file.nessus_scan_file_root_element(file_name_with_path)
                    if policy_summary:
                        policy_name = nfr.scan.policy_name(root)
                        policy_max_hosts = nfr.scan.policy_max_hosts(root)
                        policy_max_checks = nfr.scan.policy_max_checks(root)
                        policy_checks_read_timeout = (
                            nfr.scan.policy_checks_read_timeout(root)
                        )
                        plugin_set_number = nfr.scan.plugin_set_number(root)
                        policy_summary_data.append(
                            {
                                "File name": nessus_scan_file,
                                "Policy name": policy_name,
                                "Max hosts": policy_max_hosts,
                                "Max checks": policy_max_checks,
                                "Checks timeout": policy_checks_read_timeout,
                                "Plugins number": plugin_set_number,
                            }
                        )

                    if scan_file_source:
                        scan_file_source_info = nfr.scan.scan_file_source(root)
                        scan_file_source_data.append(
                            {
                                "File name": nessus_scan_file,
                                "Source": scan_file_source_info,
                            }
                        )

                    if scan_summary:

                        report_name = nfr.scan.report_name(root)
                        number_of_target_hosts = nfr.scan.number_of_target_hosts(root)
                        number_of_scanned_hosts = nfr.scan.number_of_scanned_hosts(root)
                        number_of_scanned_hosts_with_credentialed_checks_yes = nfr.scan.number_of_scanned_hosts_with_credentialed_checks_yes(
                            root
                        )

                        report_host_critical = 0
                        report_host_high = 0
                        report_host_medium = 0
                        report_host_low = 0
                        report_host_none = 0

                        for report_host in nfr.scan.report_hosts(root):
                            report_host_critical += (
                                nfr.host.number_of_plugins_per_risk_factor(
                                    report_host, "Critical"
                                )
                            )
                            report_host_high += (
                                nfr.host.number_of_plugins_per_risk_factor(
                                    report_host, "High"
                                )
                            )
                            report_host_medium += (
                                nfr.host.number_of_plugins_per_risk_factor(
                                    report_host, "Medium"
                                )
                            )
                            report_host_low += (
                                nfr.host.number_of_plugins_per_risk_factor(
                                    report_host, "Low"
                                )
                            )
                            report_host_none += (
                                nfr.host.number_of_plugins_per_risk_factor(
                                    report_host, "None"
                                )
                            )

                        summary_data.append(
                            {
                                "File name": nessus_scan_file,
                                "Report name": report_name,
                                "TH": number_of_target_hosts,
                                "SH": number_of_scanned_hosts,
                                "CC": number_of_scanned_hosts_with_credentialed_checks_yes,
                                "C": report_host_critical,
                                "H": report_host_high,
                                "M": report_host_medium,
                                "L": report_host_low,
                                "N": report_host_none,
                            }
                        )

            if scan_summary:
                header = summary_data[0].keys()
                rows = [x.values() for x in summary_data]
                print(tabulate.tabulate(rows, header))

            if scan_file_source:
                header = scan_file_source_data[0].keys()
                rows = [x.values() for x in scan_file_source_data]
                print(tabulate.tabulate(rows, header))

            if policy_summary:
                header = policy_summary_data[0].keys()
                rows = [x.values() for x in policy_summary_data]
                print(tabulate.tabulate(rows, header))

        except FileNotFoundError as e:
            print(e.strerror)

    if scan_summary_legend:
        print("Legend for scan summary:")
        print("File name - nessus file name")
        print("Report name - report name for given nessus file name")
        print("TH - number of target hosts")
        print("SH - number of scanned hosts")
        print(
            "CC - number of hosts scanned with credentials (Credentialed checks yes in Plugin ID 19506)"
        )
        print("C - number of plugins with Critical risk factor for whole scan")
        print("H - number of plugins with High risk factor for whole scan")
        print("M - number of plugins with Medium risk factor for whole scan")
        print("L - number of plugins with Low risk factor for whole scan")
        print("N - number of plugins with None risk factor for whole scan")


def main():
    name = "nessus file reader by LimberDuck"
    print("{} {}".format(name, __version__))
    cli()


if __name__ == "__main__":
    main()
