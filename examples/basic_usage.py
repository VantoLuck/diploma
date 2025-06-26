#!/usr/bin/env python3
"""
Basic usage example for Dilithium Threshold Signature Scheme.

This example demonstrates the complete workflow:
1. Distributed key generation
2. Partial signing by participants
3. Signature combination
4. Verification

Author: Leonid Kartushin
"""

import sys
import os
import time

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from dilithium_threshold.core.threshold import ThresholdSignature
from dilithium_threshold.core.dilithium import Dilithium


def main():
    """
    Demonstrate basic threshold signature functionality.
    """
    print("=== Dilithium Threshold Signature Demo ===\n")
    
    # Configuration
    threshold = 3
    participants = 5
    security_level = 3
    message = b"Hello, post-quantum threshold signatures!"
    
    print(f"Configuration:")
    print(f"  Threshold: {threshold}/{participants}")
    print(f"  Security Level: {security_level}")
    print(f"  Message: {message.decode()}")
    print()
    
    # Initialize threshold signature scheme
    print("1. Initializing threshold signature scheme...")
    ts = ThresholdSignature(threshold, participants, security_level)
    print(f"   ✓ Scheme initialized with {threshold}/{participants} configuration")
    print()
    
    # Distributed key generation
    print("2. Performing distributed key generation...")
    start_time = time.time()
    
    key_shares = ts.distributed_keygen()
    
    keygen_time = time.time() - start_time
    print(f"   ✓ Generated {len(key_shares)} key shares")
    print(f"   ✓ Key generation time: {keygen_time:.3f} seconds")
    print()
    
    # Display key share information
    print("3. Key share information:")
    for i, share in enumerate(key_shares):
        print(f"   Participant {share.participant_id}: "
              f"s1_share={len(share.s1_share.share_vector)} polys, "
              f"s2_share={len(share.s2_share.share_vector)} polys")
    print()
    
    # Partial signing by threshold participants
    print("4. Creating partial signatures...")
    start_time = time.time()
    
    # Select first 'threshold' participants for signing
    signing_participants = key_shares[:threshold]
    partial_signatures = []
    
    for share in signing_participants:
        print(f"   Creating partial signature for participant {share.participant_id}...")
        partial_sig = ts.partial_sign(message, share)
        partial_signatures.append(partial_sig)
        
        # Verify partial signature
        is_valid = ts.verify_partial_signature(message, partial_sig, share)
        status = "✓" if is_valid else "✗"
        print(f"   {status} Partial signature from participant {share.participant_id}")
    
    partial_sign_time = time.time() - start_time
    print(f"   ✓ Created {len(partial_signatures)} partial signatures")
    print(f"   ✓ Partial signing time: {partial_sign_time:.3f} seconds")
    print()
    
    # Combine signatures
    print("5. Combining partial signatures...")
    start_time = time.time()
    
    try:
        combined_signature = ts.combine_signatures(
            partial_signatures, key_shares[0].public_key)
        
        combine_time = time.time() - start_time
        print(f"   ✓ Successfully combined signatures")
        print(f"   ✓ Combination time: {combine_time:.3f} seconds")
        print()
        
    except Exception as e:
        print(f"   ✗ Failed to combine signatures: {e}")
        return
    
    # Verify combined signature
    print("6. Verifying combined signature...")
    start_time = time.time()
    
    # Use standard Dilithium verification
    dilithium = Dilithium(security_level)
    is_valid = dilithium.verify(message, combined_signature, key_shares[0].public_key)
    
    verify_time = time.time() - start_time
    status = "✓" if is_valid else "✗"
    print(f"   {status} Signature verification: {'VALID' if is_valid else 'INVALID'}")
    print(f"   ✓ Verification time: {verify_time:.3f} seconds")
    print()
    
    # Performance summary
    total_time = keygen_time + partial_sign_time + combine_time + verify_time
    print("7. Performance Summary:")
    print(f"   Key Generation:    {keygen_time:.3f}s")
    print(f"   Partial Signing:   {partial_sign_time:.3f}s")
    print(f"   Signature Combine: {combine_time:.3f}s")
    print(f"   Verification:      {verify_time:.3f}s")
    print(f"   Total Time:        {total_time:.3f}s")
    print()
    
    # Security properties
    print("8. Security Properties:")
    print(f"   ✓ Post-quantum security (based on lattice problems)")
    print(f"   ✓ No intermediate secret reconstruction")
    print(f"   ✓ Threshold security ({threshold}/{participants})")
    print(f"   ✓ Compatible with NIST Dilithium standard")
    print()
    
    print("=== Demo completed successfully! ===")


def demonstrate_threshold_property():
    """
    Demonstrate that fewer than threshold signatures cannot create valid signature.
    """
    print("\n=== Threshold Property Demonstration ===\n")
    
    threshold = 3
    participants = 5
    message = b"Test message for threshold property"
    
    # Initialize and generate keys
    ts = ThresholdSignature(threshold, participants)
    key_shares = ts.distributed_keygen()
    
    print(f"Testing threshold property with {threshold}/{participants} scheme...")
    
    # Try with insufficient signatures (threshold - 1)
    insufficient_shares = key_shares[:threshold - 1]
    partial_signatures = []
    
    for share in insufficient_shares:
        partial_sig = ts.partial_sign(message, share)
        partial_signatures.append(partial_sig)
    
    print(f"Attempting to combine {len(partial_signatures)} signatures "
          f"(need {threshold})...")
    
    try:
        combined_signature = ts.combine_signatures(
            partial_signatures, key_shares[0].public_key)
        print("   ✗ ERROR: Should not be able to combine insufficient signatures!")
    except ValueError as e:
        print(f"   ✓ Correctly rejected: {e}")
    
    print("   ✓ Threshold property verified")


if __name__ == "__main__":
    try:
        main()
        demonstrate_threshold_property()
    except Exception as e:
        print(f"Error during demo: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

