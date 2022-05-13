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
    click.echo('Version {}'.format(__version__))
    ctx.exit()


_file_arguments = [
    click.argument('files', nargs=-1, type=click.Path(),
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
@click.option('--version', is_flag=True, callback=print_version,
              expose_value=False, is_eager=True)


def cli():
    pass


@cli.command()
@add_arguments(_file_arguments)
@click.option("--size", is_flag=True,
              help="file size")
@click.option("--structure", is_flag=True,
              help="file structure")
def file(files, size, structure):

    """options related to nessus file"""

    for file in files:

        if size:
            try:
                if os.path.isdir(file):
                    os_separator = os.path.sep
                    extension = '*.nessus'
                    list_of_source_files = glob.glob(file + os_separator + '**' + os_separator + extension,
                                                     recursive=True)
                else:
                    list_of_source_files = [file]
                # print('')
                for row_index, nessus_scan_file in enumerate(list_of_source_files):
                    file_name_with_path = nfr.file.nessus_scan_file_name_with_path(nessus_scan_file)
                    file_size = nfr.file.nessus_scan_file_size_human(file_name_with_path)
                    print(nessus_scan_file, file_size)
            except FileNotFoundError as e:
                print(e)

        elif structure:

            if os.path.isdir(file):
                os_separator = os.path.sep
                extension = '*.nessus'
                list_of_source_files = glob.glob(file + os_separator + '**' + os_separator + extension,
                                                 recursive=True)
            else:
                list_of_source_files = [file]
            for row_index, nessus_scan_file in enumerate(list_of_source_files):

                print(nessus_scan_file)
                utilities.nessus_scan_file_structure(nessus_scan_file)
        else:
            print("No parameters specified")

@cli.command()
@add_arguments(_file_arguments)
@click.option("--scan-summary", is_flag=True, help="Scan summary")
@click.option("--source-of-file", is_flag=True, help="Source of file")
@click.option("--policy-name", is_flag=True, help="Policy name")

def scan(files, scan_summary, source_of_file, policy_name):

    """options related to content on scan level"""

    if files:
        summary_data = []
        for file in files:
            if os.path.isdir(file):
                os_separator = os.path.sep
                extension = '*.nessus'
                list_of_source_files = glob.glob(file + os_separator + '**' + os_separator + extension,
                                                 recursive=True)
            else:
                list_of_source_files = [file]

            for row_index, nessus_scan_file in enumerate(list_of_source_files):

                file_name_with_path = nfr.file.nessus_scan_file_name_with_path(nessus_scan_file)
                file_size = nfr.file.nessus_scan_file_size_human(nessus_scan_file)
                # print(nessus_scan_file, file_size)
                root = nfr.file.nessus_scan_file_root_element(file_name_with_path)
                if policy_name:
                    print(nfr.scan.policy_name(root))

                if source_of_file:
                    source_of_file_info = nfr.scan.scan_file_source(root)
                    print(source_of_file_info)

                if scan_summary:

                    report_name = nfr.scan.report_name(root)
                    number_of_target_hosts = nfr.scan.number_of_target_hosts(root)
                    number_of_scanned_hosts = nfr.scan.number_of_scanned_hosts(root)
                    number_of_scanned_hosts_with_credentialed_checks_yes = \
                        nfr.scan.number_of_scanned_hosts_with_credentialed_checks_yes(root)

                    summary_data.append({'nessus_scan_file': nessus_scan_file,
                                        'report_name': report_name,
                                        'number_of_target_hosts': number_of_target_hosts,
                                        'number_of_scanned_hosts': number_of_scanned_hosts,
                                        'number_of_scanned_hosts_with_credentialed_checks_yes': number_of_scanned_hosts_with_credentialed_checks_yes})

        if scan_summary:
            header = summary_data[0].keys()
            rows = [x.values() for x in summary_data]
            print(tabulate.tabulate(rows, header))


def main():
    name = "nessus file reader by LimberDuck"
    print("{} {}".format(name, __version__))
    cli()

if __name__ == '__main__':
    main()
