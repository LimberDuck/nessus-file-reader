import nessus_file_reader as nfr

nessus_scan_file = "./your_nessus_file.nessus"
root = nfr.file.nessus_scan_file_root_element(nessus_scan_file)

for report_host in nfr.scan.report_hosts(root):
    pido_19506 = nfr.plugin.plugin_output(root, report_host, "19506")
    print(f"Nessus Scan Information Plugin Output:\n{pido_19506}")
