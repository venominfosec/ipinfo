#!/usr/bin/env python3

# ipinfo.py - Retrieve IP information using IPinfo.io

# Imports
import os
import re
import csv
import sys
import json
import socket
import logging
import argparse
import traceback

import netaddr
import requests
import dns.resolver     # pip3 install dnspython


# Configure logging
logging._levelToName[logging.WARNING] = 'WARN'
formatter = logging.Formatter('%(asctime)s\t[%(levelname)s]    %(message)s', '%Y-%m-%d %H:%M:%S')
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(formatter)
logger = logging.getLogger('ipinfo')
logger.addHandler(handler)


class IPinfoResolver:
    """Retrieve IP information using IPinfo.io"""

    def __init__(self, args: dict):
        """Initialize attributes for IPinfoResolver instance"""
        self.__version__ = '2.0.0'
        self.args = args
        self.input = []
        self.scope_raw = []
        self.scope = []
        self.results = []
        self.user_agent = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/123.0.0.0 Safari/537.36')
        self.csv_headers = ['Asset', 'ResolvedAsset', 'ASN', 'Owner', 'Country', 'InScope']
        self.logger = logging.getLogger('ipinfo')
        if self.args['debug']:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

    def run(self):
        """Coordinates input, processing, and output tasks"""
        self.logger.info('Starting IPinfo Resolver')
        self.get_input()
        if self.args['scope']:
            self.get_scope()
        else:
            self.scope = self.input
        self.get_ipinfo_data()
        self.write_results()

    def get_input(self):
        """Get user input for assets to resolve"""
        self.logger.info(f'Parsing input file {self.args["file"]}')
        self.input = self.parse_file(self.args['file'])

    def get_scope(self):
        """Get user input for scope of assets"""
        self.logger.info(f'Parsing scope file {self.args["scope"]}')
        self.scope_raw = self.parse_file(self.args['scope'])
        for entry in self.scope_raw:
            try:
                self.scope.append(entry)
                ip = netaddr.IPNetwork(entry)
                for ip in ip:
                    self.scope.append(str(ip))
            except netaddr.core.AddrFormatError:
                self.scope.append(entry)

    def get_ipinfo_data(self):
        """Coordinate data retrieval from IPinfo.io"""
        self.logger.info(f'Retrieving IPinfo data for {len(self.input)} entries')
        iteration = 0
        for entry in self.input:
            iteration += 1
            if not self.args['debug']:
                print(' ' * 35, f'Status update: [{iteration}/{len(self.input)}]', ' ' * 20, end='\r')
            else:
                self.logger.debug(f'Resolving entry: {entry}')
            self.make_api_request(entry)
        if not self.args['debug']:
            print(' ' * 100, end='\r')

    def make_api_request(self, asset):
        """Make API request to IPinfo.io and parse results"""
        # Determine type of asset and modify as needed
        asset_type = None
        resolve_string = ''
        try:
            socket.inet_aton(asset)
            asset_type = 'ip'
            resolve_string = asset
        except:
            pass
        if not asset_type:
            try:
                netaddr.IPNetwork(asset)
                asset_type = 'cidr'
                ip = netaddr.IPNetwork(asset)
                resolve_string = str(ip[0])
            except netaddr.core.AddrFormatError:
                pass
        if not asset_type:
            asset_type = 'host'
            resolve_string = self.resolve_ip(asset)
        self.logger.debug(f'   Using "{resolve_string}" as resolved asset for "{asset}"')

        # Get info and convert to JSON
        asn = ''
        url = f'https://ipinfo.io/{resolve_string}/json'
        if self.args['key']:
            url += f'?token={self.args["key"]}'
        try:
            headers = {'User-Agent': self.user_agent}
            webpage = requests.get(url, headers=headers)
            results = json.loads(webpage.text)
            # Parse info
            try:
                org = self.remove_comma(str(results['org']))
                if ' ' in org:
                    asn = str(org.split(' ')[0]).strip()
                    owner = str(org.split(asn)[1]).strip()
                else:
                    owner = str(org)
            except KeyError:
                asn = 'None'
                owner = 'None'
            try:
                country = self.remove_comma(str(results['country']))
            except KeyError:
                country = 'None'

            # Save results
            temp_dict = {'Asset': asset,
                         'ResolvedAsset': resolve_string,
                         'ASN': asn,
                         'Owner': owner,
                         'Country': country,
                         'InScope': asset in self.scope
                         }
            self.results.append(temp_dict)

        # Error, requests error
        except requests.exceptions.RequestException as error:
            self.logger.error(f'Requests error: {error}')
            self.logger.debug(traceback.format_exc())
            error_str = f'Error_{str(error).replace(" ","")}'
            temp_dict = {'Asset': asset,
                         'ResolvedAsset': resolve_string,
                         'ASN': error_str,
                         'Owner': error_str,
                         'Country': error_str,
                         'InScope': asset in self.scope
                         }
            self.results.append(temp_dict)
        except json.JSONDecodeError as error:
            self.logger.error(f'{error}: received non-JSON API response for {asset}')
            self.logger.debug(traceback.format_exc())
            error_str = f'Error_{str(error).replace(" ", "")}'
            temp_dict = {'Asset': asset,
                         'ResolvedAsset': resolve_string,
                         'ASN': error_str,
                         'Owner': error_str,
                         'Country': error_str,
                         'InScope': asset in self.scope
                         }
            self.results.append(temp_dict)
        except Exception as error:
            self.logger.error(f'Uncaught error occurred: {error}')
            self.logger.debug(traceback.format_exc())
            error_str = f'Error_{str(error).replace(" ", "")}'
            temp_dict = {'Asset': asset,
                         'ResolvedAsset': resolve_string,
                         'ASN': error_str,
                         'Owner': error_str,
                         'Country': error_str,
                         'InScope': asset in self.scope
                         }
            self.results.append(temp_dict)

    def parse_file(self, file):
        """Parse file for IPs, CIDRs, and hostnames"""
        # Get input
        line_count = 0
        return_list = []
        with open(file, 'r') as data:
            for line in data:
                found = False
                line = line.strip()
                if len(line) > 0:
                    line_count += 1
                    # If IP address
                    try:
                        socket.inet_aton(line)
                        return_list.append(line)
                        found = True
                    except:
                        pass
                    # If CIDR
                    if not found:
                        try:
                            netaddr.IPNetwork(line)
                            return_list.append(line)
                            found = True
                        except netaddr.core.AddrFormatError:
                            pass
                    # If hostname
                    if not found:
                        hostname_regex = re.compile(r"^(?!-)(?!.*-$)(?!.*?\.\.)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.?$")
                        if hostname_regex.match(line) is not None:
                            return_list.append(line)
                            found = True
                    # Something else, invalid
                    if not found:
                        self.logger.warning(f'    Invalid entry in file "{file}", line {str(line_count)}: {line}')
        return return_list

    def write_results(self):
        self.logger.info(f'Writing results to {self.args["output"]}')
        with open(self.args['output'], 'w', newline='', encoding='utf8', errors='ignore') as output:
            writer = csv.DictWriter(output, fieldnames=self.csv_headers, quoting=csv.QUOTE_ALL, escapechar='\\')
            writer.writeheader()
            for result in self.results:
                writer.writerow(result)

    @staticmethod
    def remove_comma(string):
        """Remove commas from string"""
        return string.replace(',', '')

    @staticmethod
    def resolve_ip(hostname):
        """Resolve passed hostname to IP"""
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
    # Defaults
    default_file_name = 'ipinfo_results.csv'

    # Parse arguments
    parser = argparse.ArgumentParser(description='Retrieve IP information using IPinfo.io')

    input_arguments = parser.add_argument_group('Input Options', 'All files should have one entry per line, CIDRs will '
                                                                 'use the first IP in the range, hostnames will be '
                                                                 'resolved')
    input_arguments.add_argument('--file',
                                 help='IPs, hosts, or CIDRs to retrieve',
                                 required=True)
    input_arguments.add_argument('--scope',
                                 help='Scope file to determine if results are within scope')

    optional_arguments = parser.add_argument_group('Optional Options')
    optional_arguments.add_argument('--output',
                                    help=f'CSV output file, default={default_file_name}',
                                    default=default_file_name)
    optional_arguments.add_argument('--key',
                                    help='IPinfo API key to use, default is no key')
    optional_arguments.add_argument('--debug',
                                    help='Print tracebacks as they occur',
                                    action='store_true')
    raw_args = parser.parse_args()

    # Validate args
    if raw_args.file and not os.path.isfile(raw_args.file):
        parser.error(f'Input file {raw_args.file} does not exist')

    # Run
    arguments = raw_args.__dict__
    ipinfo = IPinfoResolver(arguments)
    ipinfo.run()
