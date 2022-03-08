import sys
import json
import time
import re
import socket
import subprocess

# https://stackoverflow.com/a/81899 source for ip address checking
def get_ipv4(domain):
    result = subprocess.check_output(["nslookup", "-type=A", domain], \
    timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
    addresses = []
    for i in result.split():
        try:
            socket.inet_pton(socket.AF_INET, i)
            addresses.append(i)
        except socket.error:
            pass
    return addresses[1:]

def get_ipv6(domain):
    result = subprocess.check_output(["nslookup", "-type=AAAA", domain], \
    timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
    addresses = []
    for i in result.split():
        try:
            socket.inet_pton(socket.AF_INET6, i)
            addresses.append(i)
        except socket.error:
            pass
    return addresses

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
        domains[i]["ipv6_address"] = get_ipv6(i)

    with open(output_json, 'w') as f:
        json.dump(domains, f, sort_keys=True, indent=4)

if __name__ == "__main__":
    main()