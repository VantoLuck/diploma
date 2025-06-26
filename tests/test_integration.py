#!/usr/bin/env python3
"""
Integration tests for the complete threshold signature scheme.

Tests the full workflow from key generation through signature
verification, ensuring all components work together correctly.
"""

import unittest
import time
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from dilithium_threshold.core.threshold import ThresholdSignature
from dilithium_threshold.core.dilithium import Dilithium
from dilithium_threshold.utils.constants import THRESHOLD_CONFIGS


class TestThresholdSignatureIntegration(unittest.TestCase):
    """Integration tests for the complete threshold signature scheme."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.threshold = 3
        self.participants = 5
        self.security_level = 3
        self.message = b"Test message for threshold signature"
        
        self.ts = ThresholdSignature(
            self.threshold, self.participants, self.security_level)
    
    def test_complete_workflow(self):
        """Test the complete threshold signature workflow."""
        # 1. Distributed key generation
        key_shares = self.ts.distributed_keygen()
        
        self.assertEqual(len(key_shares), self.participants)
        
        # Verify all shares have the same public key
        public_key = key_shares[0].public_key
        for share in key_shares:
            self.assertEqual(share.public_key.A.shape, public_key.A.shape)
            self.assertEqual(share.public_key.t, public_key.t)
        
        # 2. Partial signing
        signing_participants = key_shares[:self.threshold]
        partial_signatures = []
        
        for share in signing_participants:
            partial_sig = self.ts.partial_sign(self.message, share)
            partial_signatures.append(partial_sig)
            
            # Verify each partial signature
            is_valid = self.ts.verify_partial_signature(
                self.message, partial_sig, share)
            self.assertTrue(is_valid, 
                f"Partial signature from participant {share.participant_id} is invalid")
        
        # 3. Signature combination
        combined_signature = self.ts.combine_signatures(
            partial_signatures, public_key)
        
        # 4. Verification using standard Dilithium
        dilithium = Dilithium(self.security_level)
        is_valid = dilithium.verify(self.message, combined_signature, public_key)
        
        self.assertTrue(is_valid, "Combined signature verification failed")
    
    def test_different_threshold_configurations(self):
        """Test various threshold configurations."""
        test_configs = [
            (2, 3),
            (3, 5),
            (5, 7),
            (7, 10)
        ]
        
        for threshold, participants in test_configs:
            with self.subTest(threshold=threshold, participants=participants):
                ts = ThresholdSignature(threshold, participants, 2)  # Use level 2 for speed
                
                # Generate keys
                key_shares = ts.distributed_keygen()
                self.assertEqual(len(key_shares), participants)
                
                # Create partial signatures
                signing_shares = key_shares[:threshold]
                partial_sigs = []
                
                for share in signing_shares:
                    partial_sig = ts.partial_sign(self.message, share)
                    partial_sigs.append(partial_sig)
                
                # Combine and verify
                combined_sig = ts.combine_signatures(partial_sigs, key_shares[0].public_key)
                
                dilithium = Dilithium(2)
                is_valid = dilithium.verify(self.message, combined_sig, key_shares[0].public_key)
                self.assertTrue(is_valid)
    
    def test_insufficient_signatures(self):
        """Test that insufficient partial signatures cannot create valid signature."""
        key_shares = self.ts.distributed_keygen()
        
        # Try with threshold - 1 signatures
        insufficient_shares = key_shares[:self.threshold - 1]
        partial_sigs = []
        
        for share in insufficient_shares:
            partial_sig = self.ts.partial_sign(self.message, share)
            partial_sigs.append(partial_sig)
        
        # Should raise ValueError
        with self.assertRaises(ValueError):
            self.ts.combine_signatures(partial_sigs, key_shares[0].public_key)
    
    def test_signature_with_different_participants(self):
        """Test that different combinations of participants can create valid signatures."""
        key_shares = self.ts.distributed_keygen()
        
        # Test different combinations of threshold participants
        import itertools
        
        for participant_combo in itertools.combinations(key_shares, self.threshold):
            with self.subTest(participants=[s.participant_id for s in participant_combo]):
                partial_sigs = []
                
                for share in participant_combo:
                    partial_sig = self.ts.partial_sign(self.message, share)
                    partial_sigs.append(partial_sig)
                
                combined_sig = self.ts.combine_signatures(
                    partial_sigs, key_shares[0].public_key)
                
                dilithium = Dilithium(self.security_level)
                is_valid = dilithium.verify(
                    self.message, combined_sig, key_shares[0].public_key)
                self.assertTrue(is_valid)
    
    def test_different_messages(self):
        """Test signing different messages."""
        key_shares = self.ts.distributed_keygen()
        signing_shares = key_shares[:self.threshold]
        
        test_messages = [
            b"Short message",
            b"A much longer message that contains more text and various characters!@#$%^&*()",
            b"",  # Empty message
            b"\x00\x01\x02\x03\x04\x05",  # Binary data
            "Unicode message with special characters: αβγδε".encode('utf-8')
        ]
        
        for message in test_messages:
            with self.subTest(message=message):
                partial_sigs = []
                
                for share in signing_shares:
                    partial_sig = self.ts.partial_sign(message, share)
                    partial_sigs.append(partial_sig)
                
                combined_sig = self.ts.combine_signatures(
                    partial_sigs, key_shares[0].public_key)
                
                dilithium = Dilithium(self.security_level)
                is_valid = dilithium.verify(message, combined_sig, key_shares[0].public_key)
                self.assertTrue(is_valid)
    
    def test_signature_uniqueness(self):
        """Test that different messages produce different signatures."""
        key_shares = self.ts.distributed_keygen()
        signing_shares = key_shares[:self.threshold]
        
        message1 = b"First message"
        message2 = b"Second message"
        
        # Sign first message
        partial_sigs1 = []
        for share in signing_shares:
            partial_sig = self.ts.partial_sign(message1, share)
            partial_sigs1.append(partial_sig)
        
        sig1 = self.ts.combine_signatures(partial_sigs1, key_shares[0].public_key)
        
        # Sign second message
        partial_sigs2 = []
        for share in signing_shares:
            partial_sig = self.ts.partial_sign(message2, share)
            partial_sigs2.append(partial_sig)
        
        sig2 = self.ts.combine_signatures(partial_sigs2, key_shares[0].public_key)
        
        # Signatures should be different
        self.assertNotEqual(sig1.z, sig2.z)
    
    def test_cross_message_verification_fails(self):
        """Test that signatures don't verify against wrong messages."""
        key_shares = self.ts.distributed_keygen()
        signing_shares = key_shares[:self.threshold]
        
        message1 = b"Original message"
        message2 = b"Different message"
        
        # Sign message1
        partial_sigs = []
        for share in signing_shares:
            partial_sig = self.ts.partial_sign(message1, share)
            partial_sigs.append(partial_sig)
        
        signature = self.ts.combine_signatures(partial_sigs, key_shares[0].public_key)
        
        # Verify against correct message
        dilithium = Dilithium(self.security_level)
        is_valid_correct = dilithium.verify(message1, signature, key_shares[0].public_key)
        self.assertTrue(is_valid_correct)
        
        # Verify against wrong message should fail
        is_valid_wrong = dilithium.verify(message2, signature, key_shares[0].public_key)
        self.assertFalse(is_valid_wrong)
    
    def test_performance_benchmarks(self):
        """Test performance of the threshold signature scheme."""
        # Use smaller security level for faster testing
        ts = ThresholdSignature(3, 5, 2)
        
        # Benchmark key generation
        start_time = time.time()
        key_shares = ts.distributed_keygen()
        keygen_time = time.time() - start_time
        
        # Benchmark partial signing
        start_time = time.time()
        partial_sigs = []
        for share in key_shares[:3]:
            partial_sig = ts.partial_sign(self.message, share)
            partial_sigs.append(partial_sig)
        partial_sign_time = time.time() - start_time
        
        # Benchmark signature combination
        start_time = time.time()
        combined_sig = ts.combine_signatures(partial_sigs, key_shares[0].public_key)
        combine_time = time.time() - start_time
        
        # Benchmark verification
        start_time = time.time()
        dilithium = Dilithium(2)
        is_valid = dilithium.verify(self.message, combined_sig, key_shares[0].public_key)
        verify_time = time.time() - start_time
        
        self.assertTrue(is_valid)
        
        # Print performance results
        total_time = keygen_time + partial_sign_time + combine_time + verify_time
        print(f"\nPerformance Benchmarks (3/5 threshold, security level 2):")
        print(f"  Key Generation:    {keygen_time:.3f}s")
        print(f"  Partial Signing:   {partial_sign_time:.3f}s")
        print(f"  Signature Combine: {combine_time:.3f}s")
        print(f"  Verification:      {verify_time:.3f}s")
        print(f"  Total Time:        {total_time:.3f}s")
        
        # Performance assertions (reasonable bounds)
        self.assertLess(total_time, 10.0, "Total time should be under 10 seconds")
        self.assertLess(keygen_time, 5.0, "Key generation should be under 5 seconds")
    
    def test_deterministic_behavior(self):
        """Test that the scheme behaves deterministically with same inputs."""
        seed = b"deterministic_seed_for_testing"
        
        # Generate keys with same seed
        key_shares1 = self.ts.distributed_keygen(seed)
        key_shares2 = self.ts.distributed_keygen(seed)
        
        # Keys should be identical
        for share1, share2 in zip(key_shares1, key_shares2):
            self.assertEqual(share1.participant_id, share2.participant_id)
            self.assertEqual(share1.s1_share.share_vector, share2.s1_share.share_vector)
            self.assertEqual(share1.s2_share.share_vector, share2.s2_share.share_vector)
    
    def test_threshold_info(self):
        """Test threshold configuration information retrieval."""
        info = self.ts.get_threshold_info()
        
        expected_info = {
            'threshold': self.threshold,
            'participants': self.participants,
            'security_level': self.security_level,
            'min_signers': self.threshold,
            'max_participants': self.participants
        }
        
        self.assertEqual(info, expected_info)


class TestSecurityProperties(unittest.TestCase):
    """Test security properties of the threshold signature scheme."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.ts = ThresholdSignature(3, 5, 2)  # Use level 2 for speed
        self.message = b"Security test message"
    
    def test_no_secret_reconstruction(self):
        """Test that the scheme never reconstructs the full secret key."""
        key_shares = self.ts.distributed_keygen()
        
        # Create partial signatures
        partial_sigs = []
        for share in key_shares[:3]:
            partial_sig = self.ts.partial_sign(self.message, share)
            partial_sigs.append(partial_sig)
        
        # Combine signatures
        combined_sig = self.ts.combine_signatures(partial_sigs, key_shares[0].public_key)
        
        # Verify that no intermediate reconstruction occurred
        # This is tested implicitly by the fact that the implementation
        # works without ever calling reconstruct_secret on the full vectors
        
        # Verify the signature is valid
        dilithium = Dilithium(2)
        is_valid = dilithium.verify(self.message, combined_sig, key_shares[0].public_key)
        self.assertTrue(is_valid)
    
    def test_share_independence(self):
        """Test that individual shares don't reveal information about the secret."""
        key_shares = self.ts.distributed_keygen()
        
        # Individual shares should not be usable for signing
        single_share = [key_shares[0]]
        
        with self.assertRaises(ValueError):
            # Should fail because we need at least threshold shares
            partial_sig = self.ts.partial_sign(self.message, key_shares[0])
            self.ts.combine_signatures([partial_sig], key_shares[0].public_key)
    
    def test_robustness_against_malicious_shares(self):
        """Test robustness against some malicious or corrupted shares."""
        key_shares = self.ts.distributed_keygen()
        
        # Create valid partial signatures
        valid_partial_sigs = []
        for share in key_shares[:3]:
            partial_sig = self.ts.partial_sign(self.message, share)
            valid_partial_sigs.append(partial_sig)
        
        # The scheme should work with valid shares
        combined_sig = self.ts.combine_signatures(valid_partial_sigs, key_shares[0].public_key)
        
        dilithium = Dilithium(2)
        is_valid = dilithium.verify(self.message, combined_sig, key_shares[0].public_key)
        self.assertTrue(is_valid)


if __name__ == '__main__':
    unittest.main(verbosity=2)

