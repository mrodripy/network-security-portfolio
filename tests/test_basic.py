#!/usr/bin/env python3
"""
Basic tests for Network Security Scanner
"""

import unittest
import tempfile
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from portfolio_scanner import PortfolioNetworkScanner

class TestScannerBasics(unittest.TestCase):
    
    def test_scanner_initialization(self):
        """Test that scanner initializes correctly"""
        scanner = PortfolioNetworkScanner("127.0.0.1", "test_output")
        self.assertEqual(scanner.target, "127.0.0.1")
        self.assertEqual(scanner.output_dir, "test_output")
    
    def test_scan_profiles_exist(self):
        """Test that all scan profiles are defined"""
        scanner = PortfolioNetworkScanner("127.0.0.1")
        profiles = scanner.SCAN_PROFILES
        
        self.assertIn("discovery", profiles)
        self.assertIn("quick", profiles)
        self.assertIn("comprehensive", profiles)
        self.assertIn("vulnerability", profiles)
        self.assertIn("udp", profiles)
        
        # Check profile structure
        for profile_name, profile_info in profiles.items():
            self.assertIn("command", profile_info)
            self.assertIn("description", profile_info)
            self.assertIn("time", profile_info)

if __name__ == '__main__':
    unittest.main()
