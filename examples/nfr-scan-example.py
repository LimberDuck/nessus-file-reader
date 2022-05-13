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