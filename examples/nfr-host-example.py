import nessus_file_reader as nfr

nessus_scan_file = "./your_nessus_file.nessus"
root = nfr.file.nessus_scan_file_root_element(nessus_scan_file)

for report_host in nfr.scan.report_hosts(root):
    report_host_name = nfr.host.report_host_name(report_host)
    report_host_os = nfr.host.detected_os(report_host)
    report_host_scan_time_start = nfr.host.host_time_start(report_host)
    report_host_scan_time_end = nfr.host.host_time_end(report_host)
    report_host_scan_time_elapsed = nfr.host.host_time_elapsed(report_host)
    report_host_critical = nfr.host.number_of_plugins_per_risk_factor(
        report_host, "Critical"
    )
    report_host_high = nfr.host.number_of_plugins_per_risk_factor(report_host, "High")
    report_host_medium = nfr.host.number_of_plugins_per_risk_factor(
        report_host, "Medium"
    )
    report_host_low = nfr.host.number_of_plugins_per_risk_factor(report_host, "Low")
    report_host_none = nfr.host.number_of_plugins_per_risk_factor(report_host, "None")
    print(f"  Report host name: {report_host_name}")
    print(f"  Report host OS: {report_host_os}")
    print(
        f"  Host scan time START - END (ELAPSED): {report_host_scan_time_start} - {report_host_scan_time_end} ({report_host_scan_time_elapsed})"
    )
    print(
        f"  Critical/High/Medium/Low/None findings: {report_host_critical}/{report_host_high}/{report_host_medium}/{report_host_low}/{report_host_none}"
    )
