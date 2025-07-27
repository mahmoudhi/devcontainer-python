#!/bin/bash
# Network Discovery Script for Host Networking Environment
# This script automatically detects and scans the host's network

echo "=== Network Discovery and Port Scanner ==="
echo "Timestamp: $(date)"
echo ""

# Function to get network interfaces and ranges
get_network_info() {
    echo "=== Network Interface Information ==="
    ip addr show | grep -E "^[0-9]+:|inet " | grep -v "127.0.0.1" | grep -v "172\."
    echo ""
}

# Function to detect network ranges
detect_networks() {
    echo "=== Detecting External Network Ranges ==="
    # Only look for networks from routing table, don't probe random ranges
    NETWORKS=($(ip route | grep -oE '192\.168\.[0-9]+\.[0-9]+/[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -3))

    if [ ${#NETWORKS[@]} -eq 0 ]; then
        echo "No external private networks detected in routing table."
        echo "Please specify a network manually if you want to scan:"
        echo "  $0 192.168.1.0/24"
        echo "  $0 10.0.0.0/24"
        echo ""
        echo "⚠️  Only scan networks you own or have explicit permission to test!"
        return 1
    else
        echo "Detected external networks from routing table:"
        for net in "${NETWORKS[@]}"; do
            echo "✓ $net"
        done
    fi

    # Filter out any Docker networks that might have slipped through
    FILTERED_NETWORKS=()
    for net in "${NETWORKS[@]}"; do
        if [[ ! $net =~ ^172\.(1[7-9]|2[0-9]|3[0-1])\. ]]; then
            FILTERED_NETWORKS+=($net)
        fi
    done
    NETWORKS=("${FILTERED_NETWORKS[@]}")

    echo ""
    return 0
}# Function to discover live hosts
discover_hosts() {
    local network=$1
    echo "=== Discovering Live Hosts in $network ==="

    # Use nmap for host discovery
    nmap -sn $network | grep -E "Nmap scan report|MAC Address" | \
    awk '/Nmap scan report/ {ip=$5; gsub(/[()]/,"",ip)} /MAC Address/ {mac=$3; vendor=$4" "$5" "$6; print ip" - "mac" ("vendor")"} /Nmap scan report/ && !/MAC Address/ {print ip" - Host is up"}'

    echo ""
}

# Function to scan ports on discovered hosts
scan_ports() {
    local target=$1
    local port_range=${2:-"1-1000"}

    echo "=== Scanning Top Ports on $target ==="
    nmap -sV --top-ports 100 $target | grep -E "PORT|open"
    echo ""
}

# Function to perform comprehensive scan
comprehensive_scan() {
    local target=$1
    echo "=== Comprehensive Scan of $target ==="
    nmap -sV -sC -O --top-ports 1000 $target
    echo ""
}

# Main execution
main() {
    # Display warning about responsible use
    echo "⚠️  IMPORTANT: Only scan networks you own or have explicit permission to test!"
    echo "   Unauthorized network scanning may violate laws and policies."
    echo ""

    get_network_info
    detect_networks

    if [ ${#NETWORKS[@]} -eq 0 ]; then
        echo "❌ No networks detected automatically."
        echo "Usage examples (only use on networks you own):"
        echo "  $0 192.168.1.0/24    # Scan your home network"
        echo "  $0 scan 192.168.1.100 # Detailed scan of specific IP"
        echo ""
        echo "To see available options: $0 --help"
        exit 1
    fi

    # Confirm before scanning detected networks
    echo "About to scan the following networks:"
    for net in "${NETWORKS[@]}"; do
        echo "  - $net"
    done
    echo ""
    read -p "Continue with scanning? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Scan cancelled by user."
        exit 0
    fi

    # If specific target provided
    if [ "$1" = "scan" ] && [ -n "$2" ]; then
        echo "Performing comprehensive scan of $2..."
        comprehensive_scan $2
        exit 0
    fi

    # If network range provided
    if [ -n "$1" ]; then
        NETWORKS=($1)
    fi

    # Discover hosts in each network
    LIVE_HOSTS=()
    for network in "${NETWORKS[@]}"; do
        discover_hosts $network

        # Extract live host IPs for port scanning (exclude Docker networks)
        HOSTS=$(nmap -sn $network | grep "Nmap scan report" | awk '{print $5}' | sed 's/[()]//g')
        for host in $HOSTS; do
            if [[ $host =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ ! $host =~ ^172\.(1[7-9]|2[0-9]|3[0-1])\. ]]; then
                LIVE_HOSTS+=($host)
            fi
        done
    done

    # Quick port scan on discovered hosts (excluding Docker internal IPs)
    echo "=== Quick Port Scan Summary ==="
    for host in "${LIVE_HOSTS[@]}"; do
        if [ "$host" != "127.0.0.1" ] && [[ ! $host =~ ^172\.(1[7-9]|2[0-9]|3[0-1])\. ]]; then
            echo "Scanning $host..."
            nmap --top-ports 20 $host | grep -E "PORT|open" | head -10
            echo ""
        fi
    done

    echo "=== Scan Complete ==="
    echo "Found ${#LIVE_HOSTS[@]} live hosts"
    echo "For detailed scan of a specific host, run: $0 scan <IP_ADDRESS>"
}

# Check if script is run with parameters
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Network Discovery Script"
    echo ""
    echo "⚠️  LEGAL WARNING: Only use on networks you own or have explicit permission to test!"
    echo "   Unauthorized network scanning may violate laws, policies, and terms of service."
    echo ""
    echo "Usage:"
    echo "  $0                    # Auto-discover and scan networks (with confirmation)"
    echo "  $0 <network/cidr>     # Scan specific network (e.g., 192.168.1.0/24)"
    echo "  $0 scan <ip>          # Comprehensive scan of specific IP"
    echo "  $0 --help             # Show this help"
    echo ""
    echo "Examples (only use on your own networks):"
    echo "  $0 192.168.1.0/24     # Scan home network"
    echo "  $0 10.0.0.0/24        # Scan office network"
    echo "  $0 scan 192.168.1.1   # Detailed scan of router"
    exit 0
fi

# Ensure we have necessary permissions for some scans
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Running as non-root. Some advanced scans may require sudo."
    echo ""
fi

# Run main function
main "$@"
