import nessus_file_reader as nfr

nessus_scan_file = "./your_nessus_file.nessus"
root = nfr.file.nessus_scan_file_root_element(nessus_scan_file)
file_name = nfr.file.nessus_scan_file_name_with_path(nessus_scan_file)
file_size = nfr.file.nessus_scan_file_size_human(nessus_scan_file)
print(f"File name: {file_name}")
print(f"File size: {file_size}")
