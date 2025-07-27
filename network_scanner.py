#!/usr/bin/env python3
"""
Network Scanner and Analysis Tool
A comprehensive Python script for network reconnaissance and security assessment.
"""

import nmap
import socket
import subprocess
import sys
import json
from datetime import datetime
import argparse


class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def discover_hosts(self, network_range):
        """Discover active hosts in a network range"""
        print(f"[+] Discovering hosts in {network_range}")
        try:
            self.nm.scan(hosts=network_range, arguments='-sn')
            hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    hostname = self.nm[host].hostname()
                    hosts.append({
                        'ip': host,
                        'hostname': hostname if hostname else 'Unknown',
                        'status': self.nm[host].state()
                    })
            return hosts
        except Exception as e:
            print(f"[-] Error during host discovery: {e}")
            return []

    def port_scan(self, target, port_range="1-1000"):
        """Perform port scan on target"""
        print(f"[+] Scanning ports {port_range} on {target}")
        try:
            self.nm.scan(target, port_range, arguments='-sV -sC')

            results = {}
            for host in self.nm.all_hosts():
                results[host] = {
                    'state': self.nm[host].state(),
                    'protocols': {}
                }

                for protocol in self.nm[host].all_protocols():
                    ports = self.nm[host][protocol].keys()
                    results[host]['protocols'][protocol] = {}

                    for port in ports:
                        port_info = self.nm[host][protocol][port]
                        results[host]['protocols'][protocol][port] = {
                            'state': port_info['state'],
                            'name': port_info.get('name', ''),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }

            return results
        except Exception as e:
            print(f"[-] Error during port scan: {e}")
            return {}

    def service_detection(self, target, ports="22,23,53,80,110,443,993,995"):
        """Detect services on specific ports"""
        print(f"[+] Detecting services on {target} ports: {ports}")
        try:
            self.nm.scan(target, ports, arguments='-sV --version-intensity 5')

            services = {}
            for host in self.nm.all_hosts():
                services[host] = []
                for protocol in self.nm[host].all_protocols():
                    for port in self.nm[host][protocol].keys():
                        port_info = self.nm[host][protocol][port]
                        if port_info['state'] == 'open':
                            services[host].append({
                                'port': port,
                                'protocol': protocol,
                                'service': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'cpe': port_info.get('cpe', '')
                            })

            return services
        except Exception as e:
            print(f"[-] Error during service detection: {e}")
            return {}

    def vulnerability_scan(self, target):
        """Basic vulnerability scanning using nmap scripts"""
        print(f"[+] Running vulnerability scripts on {target}")
        try:
            # Run some basic vulnerability detection scripts
            self.nm.scan(target, arguments='--script vuln,safe,discovery')

            results = {}
            for host in self.nm.all_hosts():
                if 'hostscript' in self.nm[host]:
                    results[host] = self.nm[host]['hostscript']

                # Check for port-specific script results
                for protocol in self.nm[host].all_protocols():
                    for port in self.nm[host][protocol].keys():
                        if 'script' in self.nm[host][protocol][port]:
                            if host not in results:
                                results[host] = []
                            results[host].append({
                                'port': port,
                                'scripts': self.nm[host][protocol][port]['script']
                            })

            return results
        except Exception as e:
            print(f"[-] Error during vulnerability scan: {e}")
            return {}


def check_port(host, port, timeout=3):
    """Check if a specific port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def get_service_banner(host, port, timeout=3):
    """Try to grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b'\r\n')
        banner = sock.recv(1024)
        sock.close()
        return banner.decode('utf-8', errors='ignore').strip()
    except:
        return None


def main():
    parser = argparse.ArgumentParser(
        description='Network Scanner and Analysis Tool')
    parser.add_argument('target', help='Target IP address or network range')
    parser.add_argument('-d', '--discover', action='store_true',
                        help='Discover hosts in network')
    parser.add_argument('-p', '--ports', default='1-1000',
                        help='Port range to scan (default: 1-1000)')
    parser.add_argument('-s', '--services', action='store_true',
                        help='Detect services on common ports')
    parser.add_argument('-v', '--vuln', action='store_true',
                        help='Run vulnerability scan')
    parser.add_argument(
        '-o', '--output', help='Output file for results (JSON format)')

    args = parser.parse_args()

    scanner = NetworkScanner()
    results = {
        'target': args.target,
        'timestamp': datetime.now().isoformat(),
        'scan_results': {}
    }

    print(f"[*] Starting network analysis of {args.target}")
    print(f"[*] Timestamp: {results['timestamp']}")
    print("=" * 60)

    try:
        if args.discover:
            hosts = scanner.discover_hosts(args.target)
            results['scan_results']['host_discovery'] = hosts
            print(f"\n[+] Found {len(hosts)} active hosts:")
            for host in hosts:
                print(
                    f"  {host['ip']} ({host['hostname']}) - {host['status']}")

        if not args.discover or '/' not in args.target:
            # Port scanning
            port_results = scanner.port_scan(args.target, args.ports)
            results['scan_results']['port_scan'] = port_results

            print(f"\n[+] Port scan results for {args.target}:")
            for host, data in port_results.items():
                print(f"\nHost: {host} ({data['state']})")
                for protocol, ports in data['protocols'].items():
                    for port, info in ports.items():
                        if info['state'] == 'open':
                            service_info = f"{info['name']}"
                            if info['product']:
                                service_info += f" ({info['product']}"
                                if info['version']:
                                    service_info += f" {info['version']}"
                                service_info += ")"
                            print(
                                f"  {port}/{protocol} - {info['state']} - {service_info}")

        if args.services:
            service_results = scanner.service_detection(args.target)
            results['scan_results']['service_detection'] = service_results

            print(f"\n[+] Service detection results:")
            for host, services in service_results.items():
                print(f"\nHost: {host}")
                for service in services:
                    print(
                        f"  {service['port']}/{service['protocol']} - {service['service']}")
                    if service['product']:
                        print(
                            f"    Product: {service['product']} {service['version']}")

        if args.vuln:
            vuln_results = scanner.vulnerability_scan(args.target)
            results['scan_results']['vulnerability_scan'] = vuln_results

            print(f"\n[+] Vulnerability scan results:")
            for host, scripts in vuln_results.items():
                print(f"\nHost: {host}")
                if isinstance(scripts, list):
                    for script_result in scripts:
                        print(f"  Port {script_result['port']}:")
                        for script_name, output in script_result['scripts'].items():
                            print(f"    {script_name}: {output}")

        # Save results to file if specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n[+] Results saved to {args.output}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[-] Error during scan: {e}")

    print("\n[*] Scan completed")


if __name__ == "__main__":
    main()
