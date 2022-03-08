import sys
import json
import time
import re
import subprocess

def get_ipv4(domain):
    result = subprocess.check_output(["nslookup", domain], \
    timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
    # https://www.geeksforgeeks.org/extract-ip-address-from-file-using-python/ source of ipv4 regex pattern
    ipv4_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    addresses = []
    for i in result.split():
        if ipv4_pattern.search(i):
            addresses.append(i)
    return addresses[2:]

def main():
    domains_text = sys.argv[1]
    output_json = sys.argv[2]

    with open(domains_text, 'r') as f:
        data = f.read()

    domains = dict.fromkeys(data.split('\n'))
    for i in domains:
        domains[i] = dict()

    for i in domains:
        domains[i]["scan_time"] = time.mktime(time.localtime())
        domains[i]["ipv4_address"] = get_ipv4(i)

    with open(output_json, 'w') as f:
        json.dump(domains, f, sort_keys=True, indent=4)

if __name__ == "__main__":
    main()