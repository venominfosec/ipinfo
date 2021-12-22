#!/usr/bin/env python3

# ipinfo.py - Get IP owner, org, ASN, and country from IPinfo.io

# Imports
import socket
import requests
import json
import sys
import argparse
import dns.resolver


# Main method
def main(input_file, output_file, verbose, api_key, very_verbose, dns):

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
    resolved_ips = ([])
    status = 0
    line_count = 0
    written = False

    # Parse IPs from input file
    with open(input_file,'r') as data:
        for line in data:
            line_count += 1
            if isIP(line.strip()):
                ips.append(line.strip())
            else:
                if dns:
                    resolved_name = resolve_ip(line.strip())
                    if isIP(resolved_name):
                        ips.append(resolved_name)
                    else:
                        print('[!] ERROR::'+input_file+':'+str(line_count)+':'+line.strip())+' - Unable to resolve hostname'
                else:
                    print('[!] ERROR:NON-IP:'+input_file+':'+str(line_count)+':'+line.strip())

    # Retrieve info from IPinfo and parse
    for ip in ips:
        # Local variables
        temp_lst = []
        asn = ''
        owner = ''
        country = ''

        # Print update
        status += 1
        if verbose:
            print('['+str(status)+'/'+str(len(ips))+'] '+str(ip), end='\r')
        elif very_verbose:
            print('['+str(status)+'/'+str(len(ips))+'] '+str(ip))
        else:
            print('Status: ['+str(status)+'/'+str(len(ips))+']', end='\r')

        # Get info and convert to JSON
        webpage = ''
        try:
            if api_key:
                webpage = requests.get('https://ipinfo.io/'+str(ip)+'/json?token='+str(api_key))
            else:
                webpage = requests.get('https://ipinfo.io/'+str(ip)+'/json')
        except requests.exceptions.ConnectionError:
            print('[!] Connection error caught')
        if webpage:
            try:
                results = json.loads(webpage.text)
            except json.JSONDecodeError:
                print('[!] ERROR: recived non-JSON object for '+str(ip))

            # Parse info
            try:
                org = str(results['org'])
            except KeyError:
                org = 'No org info'
            try:
                country = str(results['country'])
            except KeyError:
                country = 'No country info'
            try:
                if org != 'No org info':
                    org = str(org).replace(',','')
                    if ' ' in org:
                        asn = str(org.split(' ')[0]).strip()
                        owner = str(org.split(asn)[1]).strip()
                    else:
                        owner = str(org)
                else:
                    asn = 'No ASN info'
                    owner = 'No owner info'
            except KeyError:
                owner = 'No owner info'

            # Write data to list
            temp_lst = [ip, asn, owner, country]
            if very_verbose:
                print('\t  '+str(temp_lst))
            resolved_ips.append(temp_lst)
            resolved.append(ip)
        else:
            not_resolved.append(ip)

    # Write results to output
    while written == False:
        try:
            with open(output_file,'w') as output:
                output.write('IP,ASN,Owner,Country\n')
                for ip,asn,owner,country in (resolved_ips):
                    output.write(str(ip)+','+str(asn)+','+str(owner).replace('"','').replace(',','')+','+str(country).replace('"','').replace(',','')+'\n')
            written = True
        except PermissionError:
            input('[!] Please close '+str(output_file)+' and hit enter: ')

    # Print final statuses
    print('\nData written to '+output_file)
    if not_resolved:
        print('\n Unable to query IPinfo.io for the following IPs:')
        for ip in not_resolved:
            print('    '+str(ip))


# Verify if a given string is an IP
def isIP(addr):
    try:
        socket.inet_aton(addr)
        return True
    except:
        return False


# Resolve passed hostname to IP
def resolve_ip(hostname):
    try:
        result = dns.resolver.query(hostname)
        dns.resolver.query(hostname)
        return str(result[0])
    except dns.resolver.NXDOMAIN:
        return None
    except TypeError:
        return None
    except dns.exception.Timeout:
        return None
    except dns.resolver.NoNameservers:
        return None
    except dns.resolver.NoAnswer:
        return None
    except dns.name.LabelTooLong:
        return None


# Launch program
if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description='Retrive IP information using IPinfo.io')
    parser.add_argument('-f', '--file', help='Argument is a file with list of CIDRs, one per line', required=True)
    parser.add_argument('-o', '--output', help='CSV output file, default = input_file-results.csv')
    parser.add_argument('-v', '--verbose', help='Verbose mode', action='store_true')
    parser.add_argument('-vv', '--very-verbose', help='Print results as they are retrieved', action='store_true')
    parser.add_argument('-k', '--key', help='IPinfo key to use')
    parser.add_argument('--dns', help='Resolve input lines that aren\'t IP addresses', action='store_true')
    args = parser.parse_args()
    arg_file = args.file
    arg_output = args.output
    arg_verbose = args.verbose
    arg_very_verbose = args.very_verbose
    arg_key = args.key
    arg_dns = args.dns

    # Argument validation
    if arg_file:
        try:
            with open(arg_file,'r') as test_output:
                None
        except IOError:
            print('[!] ERROR: Provided input file "'+str(arg_file)+'" cannot be opened')
            sys.exit()
    if arg_output:
        if '.' not in arg_output:
            arg_output += '.csv'
    else:
        arg_output = arg_file+'-results.csv'

    # launch program
    main(arg_file, arg_output, arg_verbose, arg_key, arg_very_verbose, arg_dns)
