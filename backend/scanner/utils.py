import ipaddress
import os
from typing import List

def parse_targets(target_input: str) -> List[str]:
    """
    Parses the target string which can be a single IP, a CIDR block, or a file path.
    Returns a list of IP addresses as strings.
    """
    hosts = []
    
    # Check if it's a file
    if os.path.isfile(target_input):
        try:
            with open(target_input, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        hosts.extend(parse_targets(line))
            return hosts
        except Exception as e:
            print(f"[!] Error reading file {target_input}: {e}")
            return []
            
    # Check if it's CIDR or single IP
    try:
        network = ipaddress.ip_network(target_input, strict=False)
        # If it's a single host (/32 or /128), hosts() returns an empty iterator sometimes, so we check num_addresses
        if network.num_addresses == 1:
             return [str(network.network_address)]
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        # If it's not a valid IP or CIDR, return it as a single string (maybe it's a hostname)
        return [target_input]
