import nessus_file_reader as nfr

nessus_scan_file = "./your_nessus_file.nessus"
root = nfr.file.nessus_scan_file_root_element(nessus_scan_file)

for report_host in nfr.scan.report_hosts(root):
    pidos_14272 = nfr.plugin.plugin_outputs(root, report_host, "14272")
    print(f"All findings for Netstat Portscanner (SSH): \n{pidos_14272}")
