import texttable
import json
import sys


def main():
    input_json = sys.argv[1]
    output_text = sys.argv[2]

    with open(input_json, 'r') as f:
        scan_data = json.load(f)

    with open(output_text, 'w') as f:
        f.write(str(scan_data))

if __name__ == "__main__":
    main()