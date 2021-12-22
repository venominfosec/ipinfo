# IPinfo
By Alex Poorman

## Purpose
Get IP owner, org, ASN, and country from IPinfo.io

## Quick Run
```
python ipinfo.py -f list_of_ips_one_per_line.txt -o CustomOutput.csv
```

## Usage
```
root@kali:~# python ipinfo.py -h
usage: ipinfo.py [-h] -f FILE [-o OUTPUT] [-v] [-vv] [-k KEY]

Retrive IP information using IPinfo.io

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Argument is a file with list of CIDRs, one per line
  -o OUTPUT, --output OUTPUT
                        CSV output file, default = input_file-results.csv
  -v, --verbose         Verbose mode
  -vv, --very-verbose   Print results as they are retrieved
  -k KEY, --key KEY     IPinfo key to use

```

## Dependencies

All dependencies should be default Python modules
