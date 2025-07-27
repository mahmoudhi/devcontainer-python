#!/bin/bash
# Include commands that you would like to execute after the container is created

echo "=== Network Security Tools DevContainer Setup ==="
echo "Container OS Information:"
uname -a
echo ""

echo "=== Pre-installed Network Tools ==="
echo "✓ nmap - Network discovery and security auditing"
echo "✓ netcat - Network utility for debugging and investigation"
echo "✓ dnsutils - DNS lookup utilities (dig, nslookup)"
echo "✓ net-tools - Network configuration tools"
echo "✓ iproute2 - Advanced IP routing utilities"
echo "✓ traceroute - Network route tracing"
echo "✓ whois - Domain/IP information lookup"
echo "✓ telnet - Telnet client"
echo ""

echo "=== Pre-installed Python Packages ==="
echo "✓ python-nmap - Python wrapper for nmap"
echo "✓ scapy - Packet manipulation library"
echo "✓ requests - HTTP library"
echo "✓ beautifulsoup4 - HTML/XML parsing"
echo "✓ paramiko - SSH client"
echo "✓ netaddr - Network address manipulation"
echo "✓ dnspython - DNS toolkit"
echo ""

echo "=== Quick Network Information ==="
echo "Network interfaces:"
ip addr show | grep -E "^[0-9]+:|inet " | grep -v "127.0.0.1"
echo ""

echo "=== Usage Examples ==="
echo "• Basic port scan: nmap -sS target_ip"
echo "• Service scan: nmap -sV -p- target_ip"
echo "• Network discovery: nmap -sn 192.168.1.0/24"
echo "• DNS lookup: dig example.com"
echo "• Trace route: traceroute target_ip"
echo "• Check open ports: netstat -tulpn"
echo "• Python scanner: python3 network_scanner.py target_ip -p 1-1000 -s"
echo ""

echo "========================================="
echo "Development environment ready!"
echo "========================================="

# Quick verification that key tools are working
echo "=== Tool Verification ==="
echo -n "nmap version: "
nmap --version | head -1
echo -n "Python nmap module: "
python3 -c "import nmap; print('✓ Available')" 2>/dev/null || echo "✗ Not available"
echo ""

echo "Setup complete! Your devcontainer is ready for network security analysis."
echo "📖 See NETWORK_SECURITY_README.md for detailed usage instructions."
