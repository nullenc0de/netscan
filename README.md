# CIDR and Organization Finder

## Overview

The CIDR and Organization Finder is a powerful Python script designed to retrieve CIDR (Classless Inter-Domain Routing) blocks and associated organization information for given IP addresses. It utilizes multiple WHOIS data sources to provide comprehensive and accurate results.

## Features

- Retrieves CIDR blocks and organization names for IP addresses
- Uses multiple WHOIS data sources: CYMRU, ARIN, and IPWhois
- Implements a retry mechanism for resilience against temporary failures
- Provides asynchronous processing for improved performance
- Supports rate limiting to avoid overloading WHOIS servers
- Offers options for searching specific organizations and outputting raw data
- Groups and sorts results by organization and CIDR

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation

1. Clone this repository or download the `ipinfo2.py` script.

2. Install the required Python packages:

   ```
   pip install aiohttp ipwhois
   ```

3. Make the script executable:

   ```
   chmod +x ipinfo2.py
   ```

## Usage

The script reads IP addresses from standard input (stdin) and outputs the results to standard output (stdout). You can pipe the output of other tools into this script.

### Basic Usage

```
cat ip_list.txt | python3 ipinfo2.py
```

or

```
subfinder -silent -d example.com | dnsx -silent -a -resp-only | python3 ipinfo2.py
```

### Options

- `--search`: Search for a specific organization name (case-insensitive partial match)
- `--raw`: Output raw JSON data instead of formatted results

### Examples

1. Basic usage:
   ```
   echo "8.8.8.8" | python3 ipinfo2.py
   ```

2. Search for a specific organization:
   ```
   cat ip_list.txt | python3 ipinfo2.py --search "Google"
   ```

3. Output raw JSON data:
   ```
   cat ip_list.txt | python3 ipinfo2.py --raw
   ```

4. Combine with other tools:
   ```
   subfinder -silent -d example.com | dnsx -silent -a -resp-only | python3 ipinfo2.py
   ```

## Output

The default output format is:

```
CIDR_BLOCK (Organization Name)
```

For example:
```
8.8.8.0/24 (Google LLC)
```

![image](https://github.com/user-attachments/assets/d8096759-dd8d-4bfd-a26b-765831cb0a4f)


When using the `--raw` option, the output will be in JSON format, containing detailed information about each IP address.

## Limitations

- The script relies on external WHOIS services, which may have rate limits or occasional downtime.
- Results may vary depending on the accuracy and completeness of WHOIS data sources.
- Large numbers of IP addresses may take significant time to process due to rate limiting and API restrictions.

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to check [issues page](link-to-your-issues-page) if you want to contribute.

## License

[Specify your license here, e.g., MIT, Apache 2.0, etc.]

## Disclaimer

This tool is for educational and research purposes only. Ensure you comply with all applicable laws and regulations when using this script.
