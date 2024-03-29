import sys
import json
import time
import socket
import subprocess
import requests
import maxminddb
import re

null = None
requests.packages.urllib3.disable_warnings()

# https://stackoverflow.com/a/81899 source for ip address checking
def get_ipv4(domain):
    try:
        result = subprocess.check_output(["nslookup", "-type=A", domain], \
        timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
    except subprocess.TimeoutExpired:
        return null
    addresses = []
    for i in result.split():
        try:
            socket.inet_pton(socket.AF_INET, i)
            addresses.append(i)
        except socket.error:
            pass
    return addresses[1:]

def get_ipv6(domain):
    try:
        result = subprocess.check_output(["nslookup", "-type=AAAA", domain], \
        timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
    except subprocess.TimeoutExpired:
        return null
    addresses = []
    for i in result.split():
        try:
            socket.inet_pton(socket.AF_INET6, i)
            addresses.append(i)
        except socket.error:
            pass
    return addresses

def get_server(domain):
    r = requests.get(f"http://{domain}", headers={'User-Agent': "Mozilla/5.0"}, verify=False)
    if 'Server' in r.headers.keys():
        http_server = r.headers['Server']
    else:
        http_server = null
    return http_server

def get_rdns_names(addresses):
    try:
        all_rdns = []
        for address in addresses:
            result = subprocess.check_output(["nslookup", "-type=PTR", address], \
            timeout=2, stderr=subprocess.STDOUT).decode("utf-8")

            nameserver_inds = [r.start() for r in re.finditer('nameserver = ', result)]
            rdns_inds = list(map(lambda ind: ind + len('nameserver = '), nameserver_inds))
            
            rdns = [result[rdns_i:] for rdns_i in rdns_inds]
            rdns = [res[:res.find("\n")] for res in rdns]

            all_rdns += rdns

        return all_rdns

    except:
        return []


def get_geo(ip):
    if ip == null:
        return null
    locations = []
    with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
        for i in range(len(ip)):
            location = reader.get(ip[i])
            city = location['city']['names']['en'] if 'city' in location.keys() else ""
            state = location['subdivisions'][0]['names']['en'] if 'subdivisions' in location.keys() else ""
            country = location['country']['names']['en'] if 'country' in location.keys() else ""
            locations.append(f"{city}, {state}, {country}")

    return locations

def get_insecure_http(domain):
    try:
        result = subprocess.check_output(["nmap", domain], \
        timeout=30, stderr=subprocess.STDOUT).decode("utf-8")
    except subprocess.TimeoutExpired:
        return null

    result = result[result.find("PORT"):]
    result = result[:result.find("\n\n")]
    entries = result.split("\n")[1:]

    for entry in entries:
        port_no = int(entry[:entry.find("/")])
        if port_no == 80:
            state = entry.split()[1]
            return state == "open"

    return False

def get_root(domain):
    try:
        echo = subprocess.Popen(("echo"), stdout=subprocess.PIPE)
        result = subprocess.check_output(["openssl", "s_client", "-connect", f"{domain}:443"], \
        timeout=30, stderr=subprocess.STDOUT, stdin=echo.stdout).decode("utf-8")
    except subprocess.TimeoutExpired:
        return null
    result = result[result.find("Certificate chain"):]
    result = result[:result.find("---")]
    result = result[result.rfind("O ="):]
    result = result[:result.find(",")]
    result = result[result.find("O =")+4:]
    return result

def get_rrt_range(addresses):
    try:
        all_rtt = []
        for address in addresses:

            result = subprocess.run(["sh", "-c", f"time echo -e \'x1dclose\x0d\' | telnet {address} 443"], \
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            output = result.stderr.decode('utf-8')
            output = output[output.find("real"):]
            output = output[:output.find("\n")]
  
            real_time = output.split()[1]
            real_time = float(real_time[real_time.find("m")+1:real_time.find("s")])
            real_time = int(real_time * 1000)

            all_rtt.append(real_time)

        return [min(all_rtt), max(all_rtt)]

    except subprocess.TimeoutExpired:
        return null

def get_tls_versions(domain):
    # TLS v1.0-1.2
    tls_versions = []

    try:
        result = subprocess.run(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", domain], \
        timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        return null

    output = result.stdout.decode('utf-8')
    tls_inds = [r.start() for r in re.finditer('TLSv', output)]

    for i in tls_inds:
        curr_output = output[i:]
        curr_output = curr_output[:curr_output.find(":")]
        if curr_output: tls_versions.append(curr_output)

    # TLS v1.3
    try:
        echo = subprocess.Popen(("echo"), stdout=subprocess.PIPE)
        result = subprocess.run(["openssl", "s_client", "-tls1_3", "-connect", f"{domain}:443"], \
        timeout=30, stdin=echo.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        return null
    
    result = result.stdout.decode('utf-8') 
    result = result[result.find("TLSv"):]
    result = result[:result.find(",")]
    if result: tls_versions.append(result)

    return tls_versions

def get_redirect_to_https(domain):
    r = requests.get(f"http://{domain}:80", headers={'User-Agent': "Mozilla/5.0"}, verify=False)
    url = r.url
    history = r.history
    status_code = r.status_code

    old_status_codes = list(map(lambda res: res.status_code, history))
    filtered_history = list(filter(lambda res: res >= 300 and res < 400, old_status_codes)) 
    protocol = url[:url.find(":")]

    return protocol == 'https' and filtered_history and status_code >= 200 and status_code < 300

def get_hsts(domain):
    r = requests.get(f"http://{domain}:80", headers={'User-Agent': "Mozilla/5.0"}, verify=False)
    return 'Strict-Transport-Security' in r.headers.keys()

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
        domains[i]["http_server"] = get_server(i)
        domains[i]["insecure_http"] = get_insecure_http(i)
        domains[i]["root_ca"] = get_root(i)
        domains[i]["geo_locations"] = get_geo(domains[i]["ipv4_address"])
        domains[i]["rdns_names"] = get_rdns_names(domains[i]["ipv4_address"])
        domains[i]["rtt_range"] = get_rrt_range(domains[i]["ipv4_address"])
        domains[i]["tls_versions"] = get_tls_versions(i)
        domains[i]["redirect_to_https"] = get_redirect_to_https(i)
        domains[i]["hsts"] = get_hsts(i)

    with open(output_json, 'w') as f:
        json.dump(domains, f, sort_keys=True, indent=4)

if __name__ == "__main__":
    main()