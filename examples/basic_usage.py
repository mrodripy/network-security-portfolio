#!/usr/bin/env python3
"""
Basic usage examples for the Network Security Scanner
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from portfolio_scanner import PortfolioNetworkScanner

def example_discovery():
    """Example 1: Network discovery"""
    print("Example 1: Discovering hosts in network")
    scanner = PortfolioNetworkScanner("192.168.1.0/24", "example_reports")
    result = scanner.scan("discovery")
    return result

def example_quick_scan():
    """Example 2: Quick security assessment"""
    print("Example 2: Quick port scan")
    scanner = PortfolioNetworkScanner("scanme.nmap.org", "example_reports")
    result = scanner.scan("quick")
    return result

def example_localhost():
    """Example 3: Scan localhost (safe for testing)"""
    print("Example 3: Scanning localhost")
    scanner = PortfolioNetworkScanner("127.0.0.1", "example_reports")
    result = scanner.scan("quick")
    return result

if __name__ == "__main__":
    print("🔧 Network Security Scanner - Examples")
    print("=" * 50)
    
    # Uncomment the example you want to run
    # example_discovery()
    # example_quick_scan()
    example_localhost()
