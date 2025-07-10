#!/usr/bin/env python3
"""
Test script to demonstrate TSIG-authenticated vs unauthenticated DNS queries.
This script shows how to send properly authenticated TSIG queries that the server will accept.
"""

import dns.query
import dns.message
import dns.name
import dns.rdatatype
import dns.tsigkeyring
import time
import sys

def test_unauthenticated_query():
    """Test a regular DNS query without TSIG authentication."""
    print("=" * 60)
    print("Testing UNAUTHENTICATED query (no TSIG)")
    print("=" * 60)
    
    try:
        # Create a simple DNS query
        query = dns.message.make_query('example.com', 'A')
        
        print(f"Sending query to server: {query.question[0]}")
        print("Expected result: Timeout (server requires TSIG)")
        
        # Send UDP query with timeout
        start_time = time.time()
        response = dns.query.udp(query, '127.0.0.1', port=15353, timeout=5)
        end_time = time.time()
        
        print(f"Unexpected success! Response received in {end_time - start_time:.2f}s")
        print(f"Response: {response}")
        
    except dns.exception.Timeout:
        end_time = time.time()
        print(f"✓ Expected timeout after {end_time - start_time:.2f}s")
        print("  This confirms the server is rejecting unauthenticated requests")
    except Exception as e:
        print(f"Error: {e}")

def test_authenticated_query():
    """Test a DNS query WITH TSIG authentication."""
    print("\n" + "=" * 60)
    print("Testing AUTHENTICATED query (with TSIG)")
    print("=" * 60)
    
    try:
        # TSIG key configuration (from the running server)
        key_name = 'tsig-key-1752143261'
        key_secret = 'B2taLMH0NAk+tuoBtZHPOd1vxxG9dSFXNnPkDZxOSFg='
        
        # Create TSIG keyring
        keyring = dns.tsigkeyring.from_text({
            key_name: key_secret
        })
        
        # Create DNS query with TSIG
        query = dns.message.make_query('example.com', 'A')
        query.use_tsig(keyring, keyname=key_name)
        
        print(f"Sending TSIG-authenticated query: {query.question[0]}")
        print(f"Using TSIG key: {key_name}")
        print("Expected result: Successful response")
        
        # Send UDP query with TSIG authentication
        start_time = time.time()
        try:
            response = dns.query.udp(query, '127.0.0.1', port=15353, timeout=10)
            end_time = time.time()
            
            print(f"✓ Success! Response received in {end_time - start_time:.2f}s")
            print(f"Response flags: {response.flags}")
            print(f"Response rcode: {dns.rcode.to_text(response.rcode())}")
            print("Answer section:")
            for rrset in response.answer:
                print(f"  {rrset}")
            if not response.answer:
                print("  No answer records (query successful but no data)")
            
            # Check if response has TSIG
            if hasattr(response, 'tsig') and response.tsig:
                print("✓ Response includes TSIG signature")
            else:
                print("  Response does not include TSIG (might be expected)")
                
        except dns.exception.Timeout:
            end_time = time.time()
            print(f"✗ Timeout after {end_time - start_time:.2f}s")
            print("  This might indicate TSIG verification failed on server side")
    except Exception as e:
        print(f"Error: {e}")

def test_wrong_tsig_key():
    """Test a DNS query with wrong TSIG key."""
    print("\n" + "=" * 60)
    print("Testing query with WRONG TSIG key")
    print("=" * 60)
    
    try:
        # Wrong TSIG key
        wrong_key_name = 'wrong-key'
        wrong_key_secret = 'wrongsecretkey123456789=='
        
        # Create TSIG keyring with wrong key
        keyring = dns.tsigkeyring.from_text({
            wrong_key_name: wrong_key_secret
        })
        
        # Create DNS query with wrong TSIG
        query = dns.message.make_query('example.com', 'A')
        query.use_tsig(keyring, keyname=wrong_key_name)
        
        print(f"Sending query with wrong TSIG key: {wrong_key_name}")
        print("Expected result: Timeout or TSIG verification failure")
        
        # Send UDP query with wrong TSIG
        start_time = time.time()
        response = dns.query.udp(query, '127.0.0.1', port=15353, timeout=5)
        end_time = time.time()
        
        print(f"Unexpected success! Response received in {end_time - start_time:.2f}s")
        print(f"Response: {response}")
        
    except dns.exception.Timeout:
        end_time = time.time()
        print(f"✓ Expected timeout after {end_time - start_time:.2f}s")
        print("  This confirms the server rejected the wrong TSIG key")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("DNS TSIG Authentication Test")
    print("Make sure the DNS server is running on port 15353")
    print("Press Ctrl+C to stop\n")
    
    try:
        # Test 1: Unauthenticated query (should timeout)
        test_unauthenticated_query()
        
        # Test 2: Properly authenticated query (should succeed)
        test_authenticated_query()
        
        # Test 3: Wrong TSIG key (should timeout)
        test_wrong_tsig_key()
        
        print("\n" + "=" * 60)
        print("TSIG Test Summary:")
        print("1. Unauthenticated queries should timeout")
        print("2. Properly authenticated queries should succeed")
        print("3. Wrong TSIG keys should be rejected")
        print("=" * 60)
        
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"Test failed with error: {e}")
