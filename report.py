import texttable
import json
import sys
from collections import defaultdict, Counter

def scanners_table(scan_data):
    entries = []
    domain_to_rtt = {}
    for domain in scan_data:
        entry = [domain]
        for info in scan_data[domain]:
            if type(info) is bool:
                entry.append(str(scan_data[domain][info]))
            else:
                entry.append(scan_data[domain][info])

            # Compile RTT values
            if info == 'rtt_range':
                domain_to_rtt[domain] = info
                
        entries.append(entry)

    table_headers = [["Domain", "Geo Locations", "HSTS", "HTTP Server", "Insecure HTTP Server", "IPv4 Addresses", "IPv6 Addresses", "RDNS Names", "Redirect to HTTPS", "Root CA", "RTT Range", "Scan Time", 'TLS Versions']]
    table_rows = table_headers + entries

    # table for ALL INFO
    table = texttable.Texttable()
    table.set_deco(texttable.Texttable.HEADER)
    table.set_cols_dtype(['t'] * 13) # automatic
    table.set_max_width(0)
    table.add_rows(table_rows)
    
    return table.draw()

def rtt_table(scan_data):
    domain_to_rtt = {}
    for domain in scan_data:
        for info in scan_data[domain]:
            # Compile RTT values
            if info == 'rtt_range':
                domain_to_rtt[domain] = info
    
    # table for sorted RTT
    table_headers = [["Domain", "RTT"]]
    sorted_domain_to_RTT = dict(sorted(domain_to_rtt.items(), key=lambda item: item[1]))
    entries = []
    for domain in sorted_domain_to_RTT:
        entry = [domain, sorted_domain_to_RTT[domain]]
        entries.append(entry)

    table = texttable.Texttable()    
    table_rows = table_headers + entries
    table.set_cols_dtype(['t'] * 2)
    table.set_max_width(0)
    table.add_rows(table_rows)
    return table.draw()

def root_table(scan_data):

    root_ca_counts = defaultdict(int)

    for domain in scan_data:
        for info in scan_data[domain]:
            # Compile Root CA's
            if info == 'root_ca':
                root_ca_counts[scan_data[domain][info]] += 1

    
    # table for sorted RTT
    table_headers = [["Domain", "Root_CA"]]
    sorted_root_ca = dict(sorted(root_ca_counts.items(), key=lambda item: item[1], reverse=True))
    entries = []
    for domain in sorted_root_ca:
        entry = [domain, sorted_root_ca[domain]]
        entries.append(entry)

    table = texttable.Texttable()    
    table_rows = table_headers + entries
    table.set_cols_dtype(['t'] * 2)
    table.set_max_width(0)
    table.add_rows(table_rows)
    return table.draw()
    
def server_table(scan_data):
    http_server_counts = defaultdict(int)

    for domain in scan_data:
        for info in scan_data[domain]:
            # Compile HTTP Server's
            if info == 'http_server':
                http_server_counts[scan_data[domain][info]] += 1

    
    # table for sorted RTT
    table_headers = [["Domain", "HTTP_Server"]]
    sorted_http_servers = dict(sorted(http_server_counts.items(), key=lambda item: item[1], reverse=True))
    entries = []
    for domain in sorted_http_servers:
        entry = [domain, sorted_http_servers[domain]]
        entries.append(entry)

    table = texttable.Texttable()    
    table_rows = table_headers + entries
    table.set_cols_dtype(['t'] * 2)
    table.set_max_width(0)
    table.add_rows(table_rows)
    return table.draw()

def percent_table(scan_data):
    num_domains = 0
    tls_versions_counts = defaultdict(int)
    insecure_http_count = 0
    redirect_to_https_count = 0
    hsts_count = 0
    ipv6_count = 0

    for domain in scan_data:
        num_domains += 1
        for info in scan_data[domain]:
            # Compile information
            if info == 'tls_versions':
                for tls_version in scan_data[domain][info]:
                    tls_versions_counts[tls_version] += 1
            if info == 'insecure_http' and scan_data[domain][info]:
                insecure_http_count += 1
            if info == 'redirect_to_https' and scan_data[domain][info]:
                redirect_to_https_count += 1
            if info == 'hsts' and scan_data[domain][info]:
                hsts_count += 1
            if info == 'ipv6_address' and scan_data[domain][info]:
                ipv6_count += 1

    table_headers = [["SSLv1", "SSLv2", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3", "Insecure HTTP", "Redirect to HTTPS", "HSTS", "IPv6 Addresses"]]

    insecure_percent = 100 * insecure_http_count / num_domains
    redirect_percent = 100 * redirect_to_https_count / num_domains
    hsts_percent = 100 * hsts_count / num_domains
    ipv6_percent = 100 * ipv6_count / num_domains
    tls_percents = []

    tls_versions = ["SSLv1", "SSLv2", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    for tls_version in tls_versions:
        tls_percents.append(100 * tls_versions_counts[tls_version] / num_domains)

    entries = []
    entries.append(tls_percents + [insecure_percent, redirect_percent, hsts_percent, ipv6_percent])

    table_rows = table_headers + entries
    table = texttable.Texttable()
    table_rows = table_headers + entries  
    table.set_cols_dtype(['f'] * 10)
    table.set_max_width(0)
    table.add_rows(table_rows)
    return table.draw()

def main():
    input_json = sys.argv[1]
    output_text = sys.argv[2]

    with open(input_json, 'r') as f:
        scan_data = json.load(f)

    with open(output_text, 'w') as f:
        f.write("Table 1: Scanner Information\n")
        f.write(str(scanners_table(scan_data)))
        f.write(str("\n\nTable 2: RTT Times\n"))
        f.write(str(rtt_table(scan_data)))
        f.write(str("\n\nTable 3: Occurrences of Each Root Certificate Authority\n"))
        f.write(str(root_table(scan_data)))
        f.write(str("\n\nTable 4: Occurrences of Each Web Server\n"))
        f.write(str(server_table(scan_data)))
        f.write(str("\n\nTable 5: Percent of Scanned Domains\n"))
        f.write(str(percent_table(scan_data)))

if __name__ == "__main__":
    main()