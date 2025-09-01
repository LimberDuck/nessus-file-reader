from nessus_file_reader._version import __version__
import click
import nessus_file_reader as nfr
from nessus_file_reader import utilities, __about__
import os
import glob
import tabulate
import jmespath


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


PACKAGE_NAME = __about__.__package_name__


@click.group(
    invoke_without_command=True,
    help="NFR - CLI tool and python module to pars nessus files",
    epilog=f"Additional information:\n\n"
    f"https://limberduck.org/en/latest/tools/{PACKAGE_NAME}\n"
    f"https://github.com/LimberDuck/{PACKAGE_NAME}\n"
    f"https://github.com/LimberDuck/{PACKAGE_NAME}/releases\n",
)
@click.option(
    "--version",
    "-v",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
)
@click.option(
    "--update-check",
    "-u",
    is_flag=True,
    help="Check if a new version is available and exit.",
)
@click.pass_context
def cli(ctx, update_check):
    if ctx.invoked_subcommand is None and not update_check:
        click.echo(ctx.get_help())
        ctx.exit(0)
    if ctx.invoked_subcommand is None and update_check:
        utilities.check_for_update()


@cli.command()
@add_arguments(_file_arguments)
@click.option("--size", is_flag=True, help="file size")
@click.option("--structure", is_flag=True, help="file structure")
@click.option(
    "--split", type=int, help="file split into batches per number of ReportHost"
)
def file(files, size, structure, split):
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
        elif split:
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
                    utilities.nessus_scan_file_split(nessus_scan_file, split)
            except FileNotFoundError as e:
                print(e.strerror)
        else:
            print("No parameters specified")


@cli.command()
@add_arguments(_file_arguments)
@click.option("--scan-summary", is_flag=True, help="Scan summary")
@click.option("--scan-summary-legend", is_flag=True, help="Show scan summary legend")
@click.option("--plugin-severity", is_flag=True, help="Plugin severity")
@click.option(
    "--plugin-severity-legend", is_flag=True, help="Show plugin severity legend"
)
@click.option("--policy-summary", is_flag=True, help="Policy summary")
@click.option(
    "--scan-file-source",
    is_flag=True,
    help="Source of scan file e.g. Nessus, Tenable.sc, Tenable.io",
)
@click.option(
    "--filter",
    "-f",
    help="filter data with JMESPath. See https://jmespath.org/ for more information and examples. "
    "Works with --plugin-severity only. ",
)
def scan(
    files,
    scan_summary,
    scan_summary_legend,
    plugin_severity,
    plugin_severity_legend,
    scan_file_source,
    policy_summary,
    filter,
):
    """Options related to content of nessus file on scan level."""

    if files:
        try:
            summary_data = []
            scan_file_source_data = []
            policy_summary_data = []
            plugin_severity_data = []
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

                    if plugin_severity:

                        for report_host in nfr.scan.report_hosts(root):
                            report_host_name = nfr.host.report_host_name(report_host)
                            report_items_per_host = nfr.host.report_items(report_host)
                            for report_item in report_items_per_host:
                                plugin_id = nfr.plugin.report_item_value(
                                    report_item, "pluginID"
                                )
                                severity = nfr.plugin.report_item_value(
                                    report_item, "severity"
                                )
                                severity_label = nfr.plugin.severity_number_to_label(
                                    severity
                                )
                                risk_factor = nfr.plugin.report_item_value(
                                    report_item, "risk_factor"
                                )
                                cvssv2_base_score = nfr.plugin.report_item_value(
                                    report_item, "cvss_base_score"
                                )
                                cvssv2_base_score_label = (
                                    nfr.plugin.cvssv2_score_to_severity(
                                        cvssv2_base_score
                                    )
                                )
                                cvssv3_base_score = nfr.plugin.report_item_value(
                                    report_item, "cvss3_base_score"
                                )
                                cvssv3_base_score_label = (
                                    nfr.plugin.cvssv3_score_to_severity(
                                        cvssv3_base_score
                                    )
                                )
                                cvssv4_base_score = nfr.plugin.report_item_value(
                                    report_item, "cvss4_base_score"
                                )
                                cvssv4_base_score_label = (
                                    nfr.plugin.cvssv4_score_to_severity(
                                        cvssv4_base_score
                                    )
                                )
                                vpr_score = nfr.plugin.report_item_value(
                                    report_item, "vpr_score"
                                )
                                vpr_score_label = nfr.plugin.vpr_score_to_severity(
                                    vpr_score
                                )
                                epss_score = nfr.plugin.report_item_value(
                                    report_item, "epss_score"
                                )
                                epss_score_label = (
                                    nfr.plugin.epss_score_decimal_to_percent(epss_score)
                                )

                                plugin_severity_data.append(
                                    {
                                        "File name": nessus_scan_file,
                                        "Report host name": report_host_name,
                                        "PID": plugin_id,
                                        "S": severity,
                                        "SL": severity_label,
                                        "RF": risk_factor,
                                        "CVSSv2": cvssv2_base_score,
                                        "CVSSv2L": cvssv2_base_score_label,
                                        "CVSSv3": cvssv3_base_score,
                                        "CVSSv3L": cvssv3_base_score_label,
                                        "CVSSv4": cvssv4_base_score,
                                        "CVSSv4L": cvssv4_base_score_label,
                                        "VPR": vpr_score,
                                        "VPRL": vpr_score_label,
                                        "EPSS": epss_score,
                                        "EPSS%": epss_score_label,
                                    }
                                )

            if scan_summary:
                header = summary_data[0].keys()
                rows = [x.values() for x in summary_data]
                print(tabulate.tabulate(rows, header))

            if plugin_severity:

                default_filter = "@"

                if filter:
                    expression = jmespath.compile(filter)
                else:
                    expression = jmespath.compile(default_filter)

                plugin_severity_data = expression.search(plugin_severity_data)

                plugin_severity_data.sort(
                    key=lambda x: (x["Report host name"], -int(x["S"]), int(x["PID"]))
                )

                header = plugin_severity_data[0].keys()
                rows = [x.values() for x in plugin_severity_data]

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

    if plugin_severity_legend:
        print("Legend for plugin severity:")
        print("File name - nessus file name")
        print("Report host name - target name used during scan")
        print("PID - Plugin ID reported in scan")
        print("S - Severity number (0-4) of plugin")
        print("SL - Severity label of plugin (e.g. Critical, High, Medium, Low, None)")
        print("RF - Risk factor of plugin (e.g. Critical, High, Medium, Low, None)")
        print("CVSSv2 - CVSSv2 base score of plugin")
        print("CVSSv2L - CVSSv2 base score label of plugin")
        print("CVSSv3 - CVSSv3 base score of plugin")
        print("CVSSv3L - CVSSv3 base score label of plugin")
        print("CVSSv4 - CVSSv4 base score of plugin")
        print("CVSSv4L - CVSSv4 base score label of plugin")
        print("VPR - Vulnerability Priority Rating score of plugin")
        print("VPRL - Vulnerability Priority Rating label of plugin")
        print("EPSS - Exploit Prediction Scoring System score of plugin")
        print("EPSS% - Exploit Prediction Scoring System score of plugin in percentage")


def main():
    name = "nessus file reader (NFR) by LimberDuck"
    print("{} {}".format(name, __version__))
    cli()


if __name__ == "__main__":
    main()
