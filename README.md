# IPinfo

## Retrieve IP information using IPinfo.io
Get IP owner, org, ASN, and country from IPinfo.io

## Quick Run
```
git clone https://github.com/venominfosec/ipinfo
cd ipinfo && pip3 install -r requirements.txt
python3 ipinfo.py --file assets_to_resolve.txt
```

## Output
| Asset       | ResolvedAsset | ASN     | Owner         | Country | InScope |
|-------------|---------------|---------|---------------|---------|---------|
| 8.8.8.8     | 8.8.8.8       | AS15169 | Google LLC    | US      | False   |
| example.com | 93.184.216.34 | AS15133 | Edgecast Inc. | US      | True    |
| 8.8.8.0/24  | 8.8.8.0       | AS15169 | Google LLC    | SA      | False   |


## Usage
```
python3 ipinfo.py --help
usage: ipinfo.py [-h] --file FILE [--scope SCOPE] [--output OUTPUT] [--key KEY] [--debug]

Retrieve IP information using IPinfo.io

options:
  -h, --help       show this help message and exit

Input Options:
  All files should have one entry per line, CIDRs will use the first IP in the range, hostnames will be resolved

  --file FILE      IPs, hosts, or CIDRs to retrieve
  --scope SCOPE    Scope file to determine if results are within scope

Optional Options:
  --output OUTPUT  CSV output file, default=ipinfo_results.csv
  --key KEY        IPinfo API key to use, default is no key
  --debug          Print tracebacks as they occur
```
