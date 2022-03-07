import sys, json
domains_text = sys.argv[1]
output_json = sys.argv[2]

with open(domains_text, 'r') as f:
    data = f.read()

domains = data.split('\n')

with open(output_json, 'w') as f:
    json.dump(domains, f, sort_keys=True, indent=4)