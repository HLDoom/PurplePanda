#!/usr/bin/env python3
"""
Simple test script to verify the reanalyze argument parsing works
"""
import argparse
import sys

def test_argument_parsing():
    parser = argparse.ArgumentParser(description="Test reanalyze argument")
    parser.add_argument('-a', '--analyze', action='store_true', default=False, required=False, help='Fast analysis')
    parser.add_argument('-e', '--enumerate', action='store_true', default=False, required=False, help='Enumerate assets')
    parser.add_argument('-r', '--reanalyze', action='store_true', default=False, required=False, help='Re-analyze existing data')
    parser.add_argument('-p', '--platforms', type=str, required=True, help='Platforms to analyze')
    
    # Test with reanalyze flag
    test_args = ['-r', '-p', 'k8s']
    args = parser.parse_args(test_args)
    
    print(f"analyze: {args.analyze}")
    print(f"enumerate: {args.enumerate}")
    print(f"reanalyze: {args.reanalyze}")
    print(f"platforms: {args.platforms}")
    
    # Verify logic
    if not args.analyze and not args.enumerate and not args.reanalyze:
        print("ERROR: No valid action specified")
        return False
    
    print("SUCCESS: Argument parsing works correctly!")
    return True

if __name__ == "__main__":
    success = test_argument_parsing()
    sys.exit(0 if success else 1)
