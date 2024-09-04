#!/usr/bin/env python3

import argparse
import json
import sys
import re
import ipaddress
import asyncio
import aiohttp
from collections import defaultdict
from functools import lru_cache
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

MAX_CONCURRENT = 50
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

async def whois_cymru(ip, semaphore):
    async with semaphore:
        try:
            reader, writer = await asyncio.open_connection('whois.cymru.com', 43)
            query = f" -v {ip}\n".encode()
            writer.write(query)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), timeout=5)
            writer.close()
            await writer.wait_closed()
            
            lines = response.decode().strip().split('\n')
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
        except Exception as e:
            print(f"Error querying CYMRU for {ip}: {str(e)}", file=sys.stderr)
        return None

async def arin_whois(ip, semaphore):
    async with semaphore:
        for attempt in range(MAX_RETRIES):
            try:
                reader, writer = await asyncio.open_connection('whois.arin.net', 43)
                query = f"{ip}\n".encode()
                writer.write(query)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), timeout=10)
                writer.close()
                await writer.wait_closed()
                
                content = response.decode()
                data = {}
                data["cidr"] = re.findall(r'CIDR:\s*([\d.]+/\d+)', content)
                data["netrange"] = re.findall(r'NetRange:\s*([\d.]+ - [\d.]+)', content)
                
                org_patterns = [
                    r'OrgName:\s*(.+)',
                    r'Organization:\s*(.+)',
                    r'CustName:\s*(.+)',
                    r'NetName:\s*(.+)',
                ]
                org_matches = []
                for pattern in org_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    org_matches.extend(matches)
                
                if org_matches:
                    org_matches = list(set(org_matches))
                    data["org"] = max(org_matches, key=len).strip()
                else:
                    data["org"] = "Unknown Organization"
                
                return data
            except Exception as e:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY)
                else:
                    print(f"Error querying ARIN WHOIS for {ip}: {str(e)}", file=sys.stderr)
        return {}

def ipwhois_lookup(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        return {
            "ip": ip,
            "asn": result.get('asn', 'N/A'),
            "bgp_prefix": result.get('network', {}).get('cidr', 'N/A'),
            "country": result.get('asn_country_code', 'N/A'),
            "org": result.get('network', {}).get('name', 'N/A')
        }
    except IPDefinedError:
        return {"ip": ip, "org": "Private IP"}
    except Exception as e:
        print(f"Error in ipwhois lookup for {ip}: {str(e)}", file=sys.stderr)
        return None

@lru_cache(maxsize=1024)
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

async def process_ip(ip, org_name, semaphore):
    try:
        cymru_data = await whois_cymru(ip, semaphore)
        arin_data = await arin_whois(ip, semaphore)
        
        if cymru_data is None and not arin_data:
            ipwhois_data = ipwhois_lookup(ip)
        else:
            ipwhois_data = {}
        
        combined_data = {**cymru_data, **arin_data, **ipwhois_data} if cymru_data else {**arin_data, **ipwhois_data}
        
        if combined_data.get('org') == 'Unknown Organization' and combined_data.get('as_name') != 'N/A':
            combined_data['org'] = combined_data['as_name']
        
        combined_data['org'] = clean_org_name(combined_data.get('org', 'Unknown Organization'))
        
        org = combined_data.get('org', 'Unknown Organization')
        
        if org_name is None or org_name.lower() in org.lower():
            cidrs = combined_data.get('cidr', []) + [combined_data.get('bgp_prefix', '')]
            for netrange in combined_data.get('netrange', []):
                cidrs.extend(netrange_to_cidr(netrange))
            valid_cidrs = [cidr for cidr in cidrs if is_valid_cidr(cidr)]
            return [(cidr, org) for cidr in set(valid_cidrs)]
    except Exception as e:
        print(f"Error processing {ip}: {str(e)}", file=sys.stderr)
    return []

async def find_subnets(ip_list, org_name=None):
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    tasks = [process_ip(ip, org_name, semaphore) for ip in ip_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [item for sublist in results if isinstance(sublist, list) for item in sublist]

async def main():
    parser = argparse.ArgumentParser(description="Find CIDR subnets and organizations")
    parser.add_argument("--search", help="Organization name to search for (optional)")
    parser.add_argument("--raw", action="store_true", help="Output raw JSON data")
    args = parser.parse_args()

    ip_list = [line.strip() for line in sys.stdin]
    
    if not ip_list:
        print("Please provide IP addresses via stdin.")
        sys.exit(1)

    if args.raw:
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        tasks = [process_ip(ip, None, semaphore) for ip in ip_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        print(json.dumps([item for sublist in results if isinstance(sublist, list) for item in sublist], indent=2))
    else:
        results = await find_subnets(ip_list, args.search)
        
        org_grouped = defaultdict(set)
        for cidr, org in results:
            org_grouped[org].add(cidr)
        
        for org in sorted(org_grouped.keys()):
            cidrs = sorted(org_grouped[org], key=lambda x: ipaddress.ip_network(x).num_addresses)
            for cidr in cidrs:
                print(f"{cidr} ({org})")

if __name__ == "__main__":
    asyncio.run(main())
