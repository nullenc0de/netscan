#!/usr/bin/env python3

import argparse
import json
import sys
import requests
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

def whois_cymru(ip):
    import subprocess
    command = f"whois -h whois.cymru.com \" -v {ip}\""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    stdout, stderr = process.communicate()
    lines = stdout.strip().split('\n')
    if len(lines) > 1:
        fields = lines[1].split('|')
        if len(fields) >= 6:
            return {
                "ip": ip,
                "asn": fields[0].strip(),
                "bgp_prefix": fields[2].strip(),
                "country": fields[3].strip(),
                "registry": fields[4].strip(),
                "allocated": fields[5].strip(),
                "as_name": fields[6].strip() if len(fields) > 6 else "N/A"
            }
    return {"ip": ip}

def networktools_whois(ip):
    url = f"http://networktools.nl/whois/{ip}"
    response = requests.get(url)
    data = {}
    if response.status_code == 200:
        content = response.text
        data["cidr"] = re.findall(r'(?:route|CIDR):\s*([\d.]+/\d+)', content)
        data["netrange"] = re.findall(r'(?:inetnum|NetRange):\s*([\d.]+ - [\d.]+)', content)
        data["org"] = re.search(r'(?:org-name|OrgName|owner|descr):\s*(.+)', content, re.IGNORECASE)
        data["org"] = data["org"].group(1) if data["org"] else "N/A"
    return data

def get_ip_info(ip):
    cymru_data = whois_cymru(ip)
    nt_data = networktools_whois(ip)
    combined_data = {**cymru_data, **nt_data}
    
    if combined_data.get('org') == 'N/A' and combined_data.get('as_name') != 'N/A':
        combined_data['org'] = combined_data['as_name']
    
    combined_data['org'] = clean_org_name(combined_data['org'])
    
    return combined_data

def clean_org_name(org_name):
    suffixes = [', Inc.', ' Inc.', ', LLC', ' LLC', '-ASN1', '-ASN', '-BLOCK-4']
    for suffix in suffixes:
        org_name = org_name.replace(suffix, '')
    return org_name.strip()

def netrange_to_cidr(netrange):
    try:
        start, end = netrange.split(' - ')
        start_int = int(ipaddress.IPv4Address(start))
        end_int = int(ipaddress.IPv4Address(end))
        return [str(cidr) for cidr in ipaddress.summarize_address_range(ipaddress.IPv4Address(start_int), ipaddress.IPv4Address(end_int))]
    except ValueError:
        return []

def is_valid_cidr(cidr):
    try:
        ipaddress.ip_network(cidr)
        return True
    except ValueError:
        return False

def process_ip(ip, org_name=None):
    info = get_ip_info(ip)
    org = info.get('org') or "Unknown Organization"
    
    if org_name is None or org_name.lower() in org.lower():
        cidrs = info.get('cidr', []) + [info.get('bgp_prefix', '')]
        for netrange in info.get('netrange', []):
            cidrs.extend(netrange_to_cidr(netrange))
        valid_cidrs = [cidr for cidr in cidrs if is_valid_cidr(cidr)]
        return [(cidr, org) for cidr in set(valid_cidrs)]
    return []

def find_subnets(ip_list, org_name=None):
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(process_ip, ip, org_name): ip for ip in ip_list}
        for future in as_completed(future_to_ip):
            results.extend(future.result())
    return results

def main():
    parser = argparse.ArgumentParser(description="Find CIDR subnets and organizations")
    parser.add_argument("--search", help="Organization name to search for (optional)")
    parser.add_argument("--raw", action="store_true", help="Output raw JSON data")
    args = parser.parse_args()

    ip_list = [line.strip() for line in sys.stdin]
    
    if not ip_list:
        print("Please provide IP addresses via stdin.")
        sys.exit(1)

    if args.raw:
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(get_ip_info, ip_list))
        print(json.dumps(results, indent=2))
    else:
        results = find_subnets(ip_list, args.search)
        
        # Group results by organization
        org_grouped = defaultdict(set)
        for cidr, org in results:
            org_grouped[org].add(cidr)
        
        # Sort organizations and print results
        for org in sorted(org_grouped.keys()):
            cidrs = sorted(org_grouped[org], key=lambda x: ipaddress.ip_network(x).num_addresses)
            for cidr in cidrs:
                print(f"{cidr} ({org})")

if __name__ == "__main__":
    main()
