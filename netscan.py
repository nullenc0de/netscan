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
                    r'CustName:\s*(.+)',
                    r'Customer:\s*(.+)',
                    r'OrgName:\s*(.+)',
                    r'Organization:\s*(.+)',
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

async def networktools_whois(session, ip, semaphore):
    async with semaphore:
        for attempt in range(MAX_RETRIES):
            try:
                url = f"http://networktools.nl/whois/{ip}"
                async with session.get(url, timeout=10) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP status {response.status}")
                    content = await response.text()
                    data = {}
                    data["cidr"] = re.findall(r'(?:route|CIDR):\s*([\d.]+/\d+)', content)
                    data["netrange"] = re.findall(r'(?:inetnum|NetRange):\s*([\d.]+ - [\d.]+)', content)
                    
                    org_patterns = [
                        r'CustName:\s*(.+)',
                        r'Customer:\s*(.+)',
                        r'(?:org-name|OrgName|owner|descr):\s*(.+)',
                        r'(?:Organization):\s*(.+)',
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
                    print(f"Error querying networktools.nl for {ip}: {str(e)}", file=sys.stderr)
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

async def process_ip(session, ip, org_name, semaphore, verbose=False):
    try:
        if verbose:
            print(f"Processing IP: {ip}", file=sys.stderr)
        cymru_data = await whois_cymru(ip, semaphore)
        arin_data = await arin_whois(ip, semaphore)
        networktools_data = await networktools_whois(session, ip, semaphore)
        
        if cymru_data is None and not arin_data and not networktools_data:
            ipwhois_data = ipwhois_lookup(ip)
        else:
            ipwhois_data = {}
        
        combined_data = {**cymru_data, **arin_data, **networktools_data, **ipwhois_data}
        
        if verbose:
            print(f"Combined data: {combined_data}", file=sys.stderr)
        
        results = []
        
        all_cidrs = sorted(
            combined_data.get('cidr', []) + [combined_data.get('bgp_prefix', '')],
            key=lambda x: int(x.split('/')[-1]) if is_valid_cidr(x) else 0,
            reverse=True
        )
        
        if verbose:
            print(f"All CIDRs: {all_cidrs}", file=sys.stderr)
        
        for cidr in all_cidrs:
            if is_valid_cidr(cidr):
                if cidr == all_cidrs[0]:  # Most specific CIDR
                    org = clean_org_name(networktools_data.get('org') or arin_data.get('org') or "Unknown Organization")
                elif cidr == combined_data.get('bgp_prefix'):
                    org = f"{clean_org_name(combined_data.get('as_name') or 'Unknown Organization')}, {combined_data.get('country', 'Unknown')}"
                else:  # Broader CIDRs
                    org = f"{clean_org_name(cymru_data.get('as_name') or arin_data.get('org') or 'Unknown Organization')}, {combined_data.get('country', 'Unknown')}"
                
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
    return [item for sublist in results if isinstance(sublist, list) for item in sublist]

async def main():
    parser = argparse.ArgumentParser(description="Find CIDR subnets and organizations")
    parser.add_argument("--search", help="Organization name to search for (optional)")
    parser.add_argument("--raw", action="store_true", help="Output raw JSON data")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    ip_list = [line.strip() for line in sys.stdin]
    
    if not ip_list:
        print("Please provide IP addresses via stdin.")
        sys.exit(1)

    if args.verbose:
        print(f"Processing IP list: {ip_list}", file=sys.stderr)

    if args.raw:
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        async with aiohttp.ClientSession() as session:
            tasks = [process_ip(session, ip, None, semaphore, args.verbose) for ip in ip_list]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        print(json.dumps([item for sublist in results if isinstance(sublist, list) for item in sublist], indent=2))
    else:
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
