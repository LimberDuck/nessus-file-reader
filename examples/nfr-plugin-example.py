import nessus_file_reader as nfr

nessus_scan_file = "./your_nessus_file.nessus"
root = nfr.file.nessus_scan_file_root_element(nessus_scan_file)

for report_host in nfr.scan.report_hosts(root):
    report_items_per_host = nfr.host.report_items(report_host)
    for report_item in report_items_per_host:
        plugin_id = int(nfr.plugin.report_item_value(report_item, "pluginID"))
        risk_factor = nfr.plugin.report_item_value(report_item, "risk_factor")
        see_also = nfr.plugin.report_item_value(report_item, "see_also")
        description = nfr.plugin.report_item_value(report_item, "description")
        plugin_name = nfr.plugin.report_item_value(report_item, "pluginName")
        print("\t", plugin_id, "  \t\t\t", risk_factor, "  \t\t\t", plugin_name)
        print(see_also)
        print(description)
