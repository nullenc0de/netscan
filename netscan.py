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
        except (asyncio.TimeoutError, OSError):
            pass
        return None

async def query_rdap(session, ip, base_url, semaphore):
    async with semaphore:
        try:
            url = f"{base_url}{ip}"
            headers = {"Accept": "application/rdap+json"}
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    return {}
                data = await response.json()
                result = {}
                result["cidr"] = []
                if "cidr0_cidrs" in data:
                    for cidr in data["cidr0_cidrs"]:
                        result["cidr"].append(f"{cidr['v4prefix']}/{cidr['length']}")
                result["netrange"] = [f"{data.get('startAddress', '')} - {data.get('endAddress', '')}"]
                
                if "entities" in data:
                    for entity in data["entities"]:
                        if "registrant" in entity.get("roles", []):
                            result["org"] = entity.get("handle", "Unknown Organization")
                            break
                    else:
                        result["org"] = data.get("name", "Unknown Organization")
                else:
                    result["org"] = data.get("name", "Unknown Organization")
                
                result["raw_data"] = data  # Include the raw data
                return result
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return {}

async def query_rir(session, ip, semaphore):
    rir_apis = [
        "https://rdap.arin.net/registry/ip/",
        "https://rdap.db.ripe.net/ip/",
        "https://rdap.apnic.net/ip/",
        "https://rdap.lacnic.net/rdap/ip/",
        "https://rdap.afrinic.net/rdap/ip/"
    ]
    
    for base_url in rir_apis:
        try:
            data = await query_rdap(session, ip, base_url, semaphore)
            if data:
                return data
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
    
    return {}

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

async def process_ip(session, ip, org_name, semaphore, verbose=False):
    try:
        if verbose:
            print(f"Processing IP: {ip}", file=sys.stderr)
        cymru_data = await whois_cymru(ip, semaphore)
        rir_data = await query_rir(session, ip, semaphore)
        
        combined_data = {**cymru_data, **rir_data} if cymru_data else rir_data
        
        if verbose:
            print(f"Combined data: {combined_data}", file=sys.stderr)
        
        results = []
        
        all_cidrs = sorted(
            combined_data.get('cidr', []) + [combined_data.get('bgp_prefix', '')] + netrange_to_cidr(combined_data.get('netrange', [''])[0]),
            key=lambda x: int(x.split('/')[-1]) if is_valid_cidr(x) else 0,
            reverse=True
        )
        all_cidrs = [cidr for cidr in all_cidrs if is_valid_cidr(cidr)]
        
        if verbose:
            print(f"All CIDRs: {all_cidrs}", file=sys.stderr)
        
        for cidr in all_cidrs:
            org = None
            if cidr == all_cidrs[0]:  # Most specific CIDR
                org = next((entity['vcardArray'][1][1][3] for entity in combined_data.get('raw_data', {}).get('entities', []) 
                            if 'registrant' in entity.get('roles', [])), None)
                if not org:
                    org = combined_data.get('org', "Unknown Organization")
            elif cidr == combined_data.get('bgp_prefix'):
                as_name = clean_org_name(combined_data.get('as_name', ''))
                country = combined_data.get('country', '')
                org = f"{as_name} ({country})" if as_name and country else as_name or country or "Unknown Organization"
            else:  # Broader CIDRs
                as_name = clean_org_name(cymru_data.get('as_name') or combined_data.get('org', ''))
                country = combined_data.get('country', '')
                org = f"{as_name} ({country})" if as_name and country else as_name or country or "Unknown Organization"
            
            if org:
                results.append((cidr, org))
                if verbose:
                    print(f"Added result: {cidr} ({org})", file=sys.stderr)
        
        return results
    except Exception as e:
        if verbose:
            print(f"Error processing {ip}: {str(e)}", file=sys.stderr)
    return []

async def find_subnets(ip_list, org_name=None, verbose=False):
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    async with aiohttp.ClientSession() as session:
        tasks = [process_ip(session, ip, org_name, semaphore, verbose) for ip in ip_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    if org_name:
        return [(cidr, org) for sublist in results if isinstance(sublist, list) for cidr, org in sublist if org_name.lower() in org.lower()]
    else:
        return [item for sublist in results if isinstance(sublist, list) for item in sublist]

async def main():
    parser = argparse.ArgumentParser(description="Find CIDR subnets and organizations")
    parser.add_argument("--search", help="Organization name to search for (optional)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    ip_list = [line.strip() for line in sys.stdin]
    
    if not ip_list:
        print("Please provide IP addresses via stdin.")
        sys.exit(1)

    if args.verbose:
        print(f"Processing IP list: {ip_list}", file=sys.stderr)

    results = await find_subnets(ip_list, args.search, args.verbose)
    
    if args.verbose:
        print(f"Final results: {results}", file=sys.stderr)
    
    org_grouped = defaultdict(set)
    for cidr, org in results:
        org_grouped[org].add(cidr)
    
    for org in sorted(org_grouped.keys()):
        cidrs = sorted(org_grouped[org], key=lambda x: ipaddress.ip_network(x).num_addresses)
        for cidr in cidrs:
            print(f"{cidr} ({org})")

if __name__ == "__main__":
    asyncio.run(main())
