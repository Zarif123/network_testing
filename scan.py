import sys, json
file = sys.argv[1]
with open(file, 'r') as f:
    data = f.read()
sites = data.split('\n')
sites_json = json.dumps(sites, sort_keys=True, indent=4)
print(sites_json)