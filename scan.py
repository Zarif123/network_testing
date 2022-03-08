import sys, json
import time
import subprocess

#def get_ipv4(domain):


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
        #domains[i]["ipv4_address"] = 

    with open(output_json, 'w') as f:
        json.dump(domains, f, sort_keys=True, indent=4)

if __name__ == "__main__":
    main()