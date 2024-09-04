# NetScan CLI

NetScan CLI is a command-line tool for retrieving and analyzing IP address information. It provides detailed subnet and organization data for given IP addresses using various online services.

## Features

- Retrieve subnet (CIDR) information for IP addresses
- Identify organizations associated with IP addresses
- Group and sort results by organization
- Support for bulk IP lookups
- Option for raw JSON output

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

### Steps

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/netscan-cli.git
   cd netscan-cli
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Make the script executable:
   ```
   chmod +x netscan.py
   ```

## Usage

### Basic Usage

To use NetScan CLI, pipe a list of IP addresses to the script:

```
cat ip_list.txt | python3 netscan.py
```

This will output the CIDR blocks and associated organizations for each IP address, sorted by organization name.

### Search for a Specific Organization

To search for IP addresses associated with a specific organization:

```
cat ip_list.txt | python3 netscan.py --search "Amazon"
```

### Raw JSON Output

To get the raw JSON data for each IP:

```
cat ip_list.txt | python3 netscan.py --raw
```

## Output Format

The default output format is:

```
CIDR_block (Organization Name)
```

Example:
```
65.8.160.0/21 (Amazon.com)
69.192.139.0/24 (Akamai Technologies)
80.144.0.0/13 (Deutsche Telekom AG)
```

## Contributing

Contributions to NetScan CLI are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- This tool uses data from whois.cymru.com and networktools.nl
- Thanks to all contributors and users of NetScan CLI
