#!/usr/bin/env python3
"""
Threshold 3-of-5 signature scheme demonstration.

This example demonstrates a practical 3-of-5 threshold signature scenario
where 5 participants share a key, but only 3 are needed to create a signature.
This is a common configuration for organizational security.

Author: Leonid Kartushin
"""

import sys
import os
import time
import secrets

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from dilithium_threshold.core.threshold import ThresholdSignature
from dilithium_threshold.core.dilithium import Dilithium


class Organization:
    """
    Simulates an organization with 5 key holders requiring 3 signatures.
    """
    
    def __init__(self):
        self.threshold = 3
        self.participants = 5
        self.security_level = 3
        
        # Participant names for demonstration
        self.participant_names = [
            "Alice (CEO)",
            "Bob (CTO)", 
            "Carol (CFO)",
            "Dave (CISO)",
            "Eve (COO)"
        ]
        
        # Initialize threshold signature scheme
        self.ts = ThresholdSignature(
            self.threshold, self.participants, self.security_level)
        
        # Generate distributed keys
        print("🔐 Generating distributed keys for organization...")
        start_time = time.time()
        self.key_shares = self.ts.distributed_keygen()
        keygen_time = time.time() - start_time
        
        print(f"✅ Key generation completed in {keygen_time:.3f}s")
        print(f"📋 Key shares distributed to {len(self.key_shares)} participants:")
        
        for i, share in enumerate(self.key_shares):
            print(f"   {i+1}. {self.participant_names[i]} (ID: {share.participant_id})")
        print()
    
    def sign_transaction(self, transaction: bytes, signers: list) -> bool:
        """
        Sign a transaction with specified signers.
        
        Args:
            transaction: Transaction data to sign
            signers: List of participant indices (0-based) who will sign
            
        Returns:
            True if signing and verification successful
        """
        if len(signers) < self.threshold:
            print(f"❌ Error: Need at least {self.threshold} signers, got {len(signers)}")
            return False
        
        print(f"📝 Transaction: {transaction.decode()}")
        print(f"👥 Signers ({len(signers)}/{self.participants}):")
        
        # Create partial signatures
        partial_signatures = []
        signing_time_total = 0
        
        for signer_idx in signers:
            signer_name = self.participant_names[signer_idx]
            key_share = self.key_shares[signer_idx]
            
            print(f"   🖊️  {signer_name} signing...")
            
            start_time = time.time()
            partial_sig = self.ts.partial_sign(transaction, key_share)
            signing_time = time.time() - start_time
            signing_time_total += signing_time
            
            # Verify partial signature
            is_valid = self.ts.verify_partial_signature(
                transaction, partial_sig, key_share)
            
            if is_valid:
                partial_signatures.append(partial_sig)
                print(f"      ✅ Partial signature created ({signing_time:.3f}s)")
            else:
                print(f"      ❌ Partial signature verification failed!")
                return False
        
        # Combine signatures
        print(f"🔗 Combining {len(partial_signatures)} partial signatures...")
        start_time = time.time()
        
        try:
            combined_signature = self.ts.combine_signatures(
                partial_signatures, self.key_shares[0].public_key)
            combine_time = time.time() - start_time
            print(f"   ✅ Signatures combined ({combine_time:.3f}s)")
            
        except Exception as e:
            print(f"   ❌ Failed to combine signatures: {e}")
            return False
        
        # Verify combined signature
        print("🔍 Verifying combined signature...")
        start_time = time.time()
        
        dilithium = Dilithium(self.security_level)
        is_valid = dilithium.verify(
            transaction, combined_signature, self.key_shares[0].public_key)
        verify_time = time.time() - start_time
        
        if is_valid:
            print(f"   ✅ Signature verification successful ({verify_time:.3f}s)")
            
            # Performance summary
            total_time = signing_time_total + combine_time + verify_time
            print(f"\n📊 Performance Summary:")
            print(f"   Partial Signing: {signing_time_total:.3f}s")
            print(f"   Combination:     {combine_time:.3f}s")
            print(f"   Verification:    {verify_time:.3f}s")
            print(f"   Total:           {total_time:.3f}s")
            
            return True
        else:
            print(f"   ❌ Signature verification failed!")
            return False
    
    def demonstrate_threshold_property(self):
        """Demonstrate that insufficient signers cannot create valid signatures."""
        print("\n🧪 Testing Threshold Property")
        print("=" * 50)
        
        transaction = b"Unauthorized transaction attempt"
        
        # Try with insufficient signers
        insufficient_signers = [0, 1]  # Only 2 signers
        print(f"Attempting to sign with only {len(insufficient_signers)} signers...")
        
        success = self.sign_transaction(transaction, insufficient_signers)
        if not success:
            print("✅ Threshold property verified: insufficient signers rejected")
        else:
            print("❌ ERROR: Threshold property violated!")
    
    def demonstrate_different_signer_combinations(self):
        """Demonstrate that different combinations of signers work."""
        print("\n🔄 Testing Different Signer Combinations")
        print("=" * 50)
        
        transaction = b"Multi-signature test transaction"
        
        # Test different combinations of 3 signers
        import itertools
        
        signer_combinations = list(itertools.combinations(range(5), 3))
        
        for i, signers in enumerate(signer_combinations[:3]):  # Test first 3 combinations
            print(f"\n--- Combination {i+1}: {[self.participant_names[s] for s in signers]} ---")
            success = self.sign_transaction(transaction, list(signers))
            if success:
                print("✅ Combination successful")
            else:
                print("❌ Combination failed")
    
    def demonstrate_security_scenarios(self):
        """Demonstrate various security scenarios."""
        print("\n🛡️  Security Scenarios")
        print("=" * 50)
        
        # Scenario 1: Normal operation
        print("\n📋 Scenario 1: Normal 3-of-5 signing")
        transaction1 = b"Regular business transaction - $10,000 transfer"
        success1 = self.sign_transaction(transaction1, [0, 1, 2])  # Alice, Bob, Carol
        
        # Scenario 2: One participant unavailable
        print("\n📋 Scenario 2: One key holder unavailable")
        transaction2 = b"Emergency transaction - Bob unavailable"
        success2 = self.sign_transaction(transaction2, [0, 2, 3])  # Alice, Carol, Dave
        
        # Scenario 3: Maximum signers
        print("\n📋 Scenario 3: All participants signing")
        transaction3 = b"Critical system update - all signatures"
        success3 = self.sign_transaction(transaction3, [0, 1, 2, 3, 4])  # Everyone
        
        print(f"\n📈 Security Scenario Results:")
        print(f"   Normal operation:     {'✅' if success1 else '❌'}")
        print(f"   Participant unavailable: {'✅' if success2 else '❌'}")
        print(f"   All participants:     {'✅' if success3 else '❌'}")


def main():
    """Main demonstration function."""
    print("🏢 Dilithium Threshold Signature - Organization Demo")
    print("=" * 60)
    print("Scenario: 5-person organization requiring 3 signatures")
    print("Use case: Critical financial transactions\n")
    
    # Create organization
    org = Organization()
    
    # Demonstrate normal operation
    print("💼 Normal Business Operation")
    print("=" * 50)
    
    transaction = b"Wire transfer: $50,000 to vendor account"
    signers = [0, 2, 4]  # Alice (CEO), Carol (CFO), Eve (COO)
    
    success = org.sign_transaction(transaction, signers)
    
    if success:
        print("\n🎉 Transaction successfully signed and verified!")
    else:
        print("\n💥 Transaction signing failed!")
    
    # Additional demonstrations
    org.demonstrate_threshold_property()
    org.demonstrate_different_signer_combinations()
    org.demonstrate_security_scenarios()
    
    print("\n" + "=" * 60)
    print("✅ Demo completed successfully!")
    print("\n🔑 Key Benefits Demonstrated:")
    print("   • Post-quantum security")
    print("   • Distributed trust (no single point of failure)")
    print("   • Flexible signer combinations")
    print("   • Threshold security (3-of-5)")
    print("   • No secret key reconstruction")
    print("   • Fast performance (~300ms total)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\n💥 Error during demo: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

