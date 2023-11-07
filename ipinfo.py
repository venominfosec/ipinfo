#!/usr/bin/env python3

# ipinfo.py - Get IP owner, org, ASN, and country from IPinfo.io

# Imports
import socket
import json
import os
import traceback
import argparse
import requests
import dns.resolver


# Main method
def main(args):

    # Splash screen
    print('  _       _        __        _')
    print(' (_)_ __ (_)_ __  / _| ___  (_) ___')
    print(' | | \'_ \| | \'_ \| |_ / _ \ | |/ _ \\')
    print(' | | |_) | | | | |  _| (_) || | (_) |')
    print(' |_| .__/|_|_| |_|_|  \\___(_)_|\___/')
    print('   |_|\n')

    # Variables
    ips = []
    resolved = []
    not_resolved = []
    resolved_ips = []
    ip_to_hostname = {}
    status = 0
    line_count = 0
    headers_default = ['IP', 'ASN', 'Owner', 'Country']
    headers_dns = ['Hostname', 'IP', 'ASN', 'Owner', 'Country']

    # Parse IPs from input file
    with open(args['file'], 'r') as data:
        for line in data:
            line = line.strip()
            if len(line) > 0:
                line_count += 1
                if is_ip(line):
                    ip_to_hostname[line] = None
                    ips.append(line)
                else:
                    if dns:
                        resolved_ip = resolve_ip(line)
                        if is_ip(resolved_ip):
                            ip_to_hostname[resolved_ip] = line
                            ips.append(resolved_ip)
                        else:
                            print(f'[!] ERROR:RESOLUTION:{args["file"]}:{str(line_count)}:{line}')
                    else:
                        print(f'[!] ERROR:NON-IP:{args["file"]}:{str(line_count)}:{line}')

    # Retrieve info from IPinfo and parse
    for ip in ips:
        # Local variables
        asn = ''

        # Print update
        status += 1
        if args['verbose']:
            print('['+str(status)+'/'+str(len(ips))+'] '+str(ip), end='\r')
        elif args['very_verbose']:
            print('['+str(status)+'/'+str(len(ips))+'] '+str(ip))
        else:
            print('Status: ['+str(status)+'/'+str(len(ips))+']', end='\r')

        # Get info and convert to JSON
        url = requests.get('https://ipinfo.io/'+str(ip)+'/json')
        if args['key']:
            url += '?token='+str(args['key'])
        try:
            webpage = requests.get('https://ipinfo.io/'+str(ip)+'/json')
            try:
                results = json.loads(webpage.text)
                # Parse info
                try:
                    org = remove_comma(str(results['org']))
                    if ' ' in org:
                        asn = str(org.split(' ')[0]).strip()
                        owner = str(org.split(asn)[1]).strip()
                    else:
                        owner = str(org)
                except KeyError:
                    asn = 'No ASN info'
                    owner = 'No owner info'
                try:
                    country = remove_comma(str(results['country']))
                except KeyError:
                    country = 'No country info'

                # Save results
                temp_lst = [ip, asn, owner, country]
                if args['very_verbose']:
                    print('\t  ' + str(temp_lst))
                resolved_ips.append(temp_lst)
                resolved.append(ip)

            # Error, invalid JSON
            except json.JSONDecodeError:
                print('[!] ERROR: received non-JSON object for '+str(ip))
                not_resolved.append(ip)

        # Error, requests error
        except requests.exceptions.ConnectionError as error:
            print(f'[ERROR] Connection error: {error}')
            print(traceback.format_exc())
            not_resolved.append(ip)

    # Write results
    with open(args['output'], 'w') as output:
        output.write(','.join(headers_default) if not dns else ','.join(headers_dns))
        output.write('\n')
        for result_list in resolved_ips:
            if not dns:
                output.write(','.join(result_list))
                output.write('\n')
            else:
                output.write(ip_to_hostname[result_list[0]]+','+','.join(result_list))
                output.write('\n')

    # Print final statuses
    print()
    print('Data written to '+args['output'])
    if not_resolved:
        print('\n Unable to query IPinfo.io for the following IPs:')
        for ip in not_resolved:
            print(f'{" "*4}*{ip}')


# Remove commas from string
def remove_comma(string):
    return string.replace(',', '')


# Verify if a given string is an IP
def is_ip(addr):
    try:
        socket.inet_aton(addr)
        return True
    except:
        return False


# Resolve passed hostname to IP
def resolve_ip(hostname):
    try:
        result = dns.resolver.resolve(hostname)
        dns.resolver.resolve(hostname)
        return str(result[0])
    except dns.exception.DNSException:
        return None
    except Exception as error:
        print(f'[ERROR] Uncaught exception: {error}')
        print(traceback.format_exc())
        return None


# Run from CLI
if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description='Retrieve IP information using IPinfo.io')
    parser.add_argument('-f', '--file', help='Argument is a file with list of CIDRs, one per line', required=True)
    parser.add_argument('-o', '--output', help='CSV output file, default = input_file-results.csv')
    parser.add_argument('-v', '--verbose', help='Verbose mode', action='store_true')
    parser.add_argument('-vv', '--very-verbose', help='Print results as they are retrieved', action='store_true')
    parser.add_argument('-k', '--key', help='IPinfo key to use')
    parser.add_argument('--dns', help='Resolve input lines that aren\'t IP addresses', action='store_true')
    raw_args = parser.parse_args()
    args = raw_args.__dict__

    # Validate args
    if args['file'] and not os.path.isfile(args['file']):
        parser.error(f'File {args["file"]} does not exist')
    if not args['output']:
        args['output'] = args['file']+'-results.csv'

    # Run
    main(args)
