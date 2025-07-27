# Network Security DevContainer

This devcontainer is configured with comprehensive network scanning and security analysis tools. It's designed for ethical hacking, penetration testing, network reconnaissance, and security research.

## 🛠️ Installed Tools

### Network Scanners
- **nmap** - The de facto standard for network discovery and security auditing
- **masscan** - High-speed port scanner for large networks
- **zmap** - Fast single packet network scanner
- **arp-scan** - ARP scanner for local network discovery

### Web Application Security
- **nikto** - Web server scanner for vulnerabilities
- **dirb** - Web content scanner and directory brute-forcer
- **sqlmap** - Automatic SQL injection and database takeover tool

### Network Analysis
- **tcpdump** - Command-line packet analyzer
- **tshark** - Terminal-based Wireshark for packet analysis
- **traceroute** - Network route tracing utility
- **whois** - Domain and IP information lookup
- **netcat** - Swiss army knife for network connections

### Authentication Testing
- **hydra** - Parallel login cracker for various protocols

### Wireless Security
- **aircrack-ng** - WiFi security auditing suite

### Python Libraries
- **python-nmap** - Python wrapper for nmap
- **scapy** - Powerful packet manipulation library
- **requests** - HTTP library for web testing
- **paramiko** - SSH client library
- **netaddr** - Network address manipulation
- **dnspython** - DNS toolkit
- **shodan** - Shodan API client
- **impacket** - Network protocols implementation

## 🚀 Quick Start Examples

### 1. Basic Network Discovery
```bash
# Discover hosts in a network
nmap -sn 192.168.1.0/24

# ARP scan for local network
arp-scan -l
```

### 2. Port Scanning
```bash
# Basic TCP SYN scan
nmap -sS target_ip

# Comprehensive service detection
nmap -sV -sC -O target_ip

# Fast scan of top 1000 ports
nmap --top-ports 1000 target_ip

# Scan specific ports
nmap -p 22,80,443,8080 target_ip
```

### 3. Service Enumeration
```bash
# HTTP service enumeration
nmap --script http-* target_ip

# SMB enumeration
nmap --script smb-* target_ip

# DNS enumeration
nmap --script dns-* target_domain
```

### 4. Web Application Testing
```bash
# Basic web vulnerability scan
nikto -h http://target_ip

# Directory enumeration
dirb http://target_ip

# SQL injection testing
sqlmap -u "http://target_ip/page.php?id=1"
```

### 5. High-Speed Scanning
```bash
# Masscan for large networks
masscan -p1-65535 192.168.1.0/24 --rate=1000

# Zmap for internet-wide scanning
zmap -p 80 -o results.txt
```

## 🐍 Python Network Scanner

Use the included `network_scanner.py` script for automated reconnaissance:

```bash
# Discover hosts in network
python3 network_scanner.py 192.168.1.0/24 -d

# Port scan with service detection
python3 network_scanner.py 192.168.1.100 -p 1-1000 -s

# Vulnerability scan
python3 network_scanner.py 192.168.1.100 -v

# Complete scan with output to file
python3 network_scanner.py 192.168.1.100 -d -s -v -o scan_results.json
```

## 📋 Security Assessment Workflow

### 1. Reconnaissance Phase
```bash
# Step 1: Network discovery
nmap -sn target_network/24

# Step 2: Host enumeration
nmap -sV -sC discovered_hosts

# Step 3: Service fingerprinting
nmap --script version,default discovered_hosts
```

### 2. Vulnerability Assessment
```bash
# Web application assessment
nikto -h http://target
dirb http://target

# Network service testing
nmap --script vuln target_ip

# Authentication testing
hydra -L users.txt -P passwords.txt target_ip ssh
```

### 3. Analysis and Reporting
```bash
# Generate detailed reports
nmap -sV -sC -A -oA full_scan target_ip

# Convert to HTML report
xsltproc full_scan.xml -o report.html
```

## 🔧 Advanced Techniques

### Custom Nmap Scripts
```bash
# Run specific NSE scripts
nmap --script exploit,vuln target_ip

# Custom timing and evasion
nmap -T2 -f -D RND:10 target_ip
```

### Packet Analysis
```bash
# Capture packets
tcpdump -i eth0 -w capture.pcap

# Analyze with tshark
tshark -r capture.pcap -Y "tcp.port==80"
```

### Network Pivoting
```bash
# SSH tunnel for pivoting
ssh -D 8080 user@compromised_host

# Use proxychains with tools
proxychains nmap -sT internal_network/24
```

## ⚠️ Legal and Ethical Guidelines

### ✅ Authorized Use Cases
- Testing your own networks and systems
- Authorized penetration testing with proper documentation
- Educational purposes in controlled environments
- Security research with appropriate permissions

### ❌ Prohibited Activities
- Scanning networks without explicit permission
- Accessing systems you don't own
- Disrupting network services
- Violating terms of service or laws

### 📝 Best Practices
1. **Always get written authorization** before testing
2. **Document your activities** for accountability
3. **Use rate limiting** to avoid disrupting services
4. **Follow responsible disclosure** for vulnerabilities found
5. **Respect privacy and confidentiality**

## 🔍 Useful Resources

- [Nmap Official Documentation](https://nmap.org/docs.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)

## 🆘 Troubleshooting

### Permission Issues
```bash
# Run with sudo for raw socket access
sudo nmap -sS target_ip

# Add user to netdev group
sudo usermod -a -G netdev $USER
```

### Network Connectivity
```bash
# Test basic connectivity
ping target_ip

# Check routing
traceroute target_ip

# Verify DNS resolution
nslookup target_domain
```

## 📞 Support

For issues or questions:
1. Check the tool's documentation
2. Review error messages carefully
3. Verify network connectivity and permissions
4. Test with simpler commands first

Remember: With great power comes great responsibility. Use these tools ethically and legally!
