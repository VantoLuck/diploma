#!/usr/bin/env python3
"""
Unit tests for adapted Shamir secret sharing scheme.

Tests the core innovation of adapting Shamir's secret sharing
to work with polynomial vectors from Dilithium.
"""

import unittest
import numpy as np
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from dilithium_threshold.core.shamir import AdaptedShamirSSS, ShamirShare
from dilithium_threshold.crypto.polynomials import Polynomial, PolynomialVector
from dilithium_threshold.utils.constants import Q, N


class TestShamirShare(unittest.TestCase):
    """Test cases for ShamirShare class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.poly1 = Polynomial([1, 2, 3, 4, 5])
        self.poly2 = Polynomial([6, 7, 8, 9, 10])
        self.share_vector = PolynomialVector([self.poly1, self.poly2])
        self.share = ShamirShare(1, self.share_vector)
    
    def test_share_creation(self):
        """Test ShamirShare creation."""
        self.assertEqual(self.share.participant_id, 1)
        self.assertEqual(self.share.vector_length, 2)
        self.assertEqual(self.share.share_vector, self.share_vector)
    
    def test_invalid_participant_id(self):
        """Test that invalid participant IDs are rejected."""
        with self.assertRaises(ValueError):
            ShamirShare(0, self.share_vector)
        
        with self.assertRaises(ValueError):
            ShamirShare(-1, self.share_vector)
    
    def test_share_representation(self):
        """Test string representation of share."""
        repr_str = repr(self.share)
        self.assertIn("ShamirShare", repr_str)
        self.assertIn("id=1", repr_str)
        self.assertIn("length=2", repr_str)


class TestAdaptedShamirSSS(unittest.TestCase):
    """Test cases for AdaptedShamirSSS class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.threshold = 3
        self.participants = 5
        self.shamir = AdaptedShamirSSS(self.threshold, self.participants)
        
        # Create test secret vector
        self.secret_poly1 = Polynomial([1, 2, 3, 4, 5])
        self.secret_poly2 = Polynomial([10, 20, 30, 40, 50])
        self.secret_vector = PolynomialVector([self.secret_poly1, self.secret_poly2])
    
    def test_shamir_initialization(self):
        """Test AdaptedShamirSSS initialization."""
        self.assertEqual(self.shamir.threshold, self.threshold)
        self.assertEqual(self.shamir.participants, self.participants)
        self.assertEqual(len(self.shamir.participant_ids), self.participants)
        self.assertEqual(self.shamir.participant_ids, [1, 2, 3, 4, 5])
    
    def test_invalid_threshold_config(self):
        """Test that invalid threshold configurations are rejected."""
        # Threshold too small
        with self.assertRaises(ValueError):
            AdaptedShamirSSS(1, 5)
        
        # Threshold larger than participants
        with self.assertRaises(ValueError):
            AdaptedShamirSSS(6, 5)
        
        # Too many participants
        with self.assertRaises(ValueError):
            AdaptedShamirSSS(3, 300)
    
    def test_secret_splitting(self):
        """Test secret splitting into shares."""
        shares = self.shamir.split_secret(self.secret_vector)
        
        # Check we get correct number of shares
        self.assertEqual(len(shares), self.participants)
        
        # Check each share has correct participant ID
        for i, share in enumerate(shares):
            self.assertEqual(share.participant_id, i + 1)
            self.assertEqual(share.vector_length, len(self.secret_vector))
    
    def test_secret_reconstruction(self):
        """Test secret reconstruction from shares."""
        # Split secret
        shares = self.shamir.split_secret(self.secret_vector)
        
        # Reconstruct using exactly threshold shares
        reconstructed = self.shamir.reconstruct_secret(shares[:self.threshold])
        
        # Check reconstruction is correct
        self.assertEqual(reconstructed, self.secret_vector)
    
    def test_reconstruction_with_more_shares(self):
        """Test reconstruction with more than threshold shares."""
        shares = self.shamir.split_secret(self.secret_vector)
        
        # Use all shares
        reconstructed = self.shamir.reconstruct_secret(shares)
        self.assertEqual(reconstructed, self.secret_vector)
        
        # Use threshold + 1 shares
        reconstructed2 = self.shamir.reconstruct_secret(shares[:self.threshold + 1])
        self.assertEqual(reconstructed2, self.secret_vector)
    
    def test_insufficient_shares(self):
        """Test that insufficient shares cannot reconstruct secret."""
        shares = self.shamir.split_secret(self.secret_vector)
        
        # Try with threshold - 1 shares
        with self.assertRaises(ValueError):
            self.shamir.reconstruct_secret(shares[:self.threshold - 1])
        
        # Try with empty list
        with self.assertRaises(ValueError):
            self.shamir.reconstruct_secret([])
    
    def test_partial_reconstruction(self):
        """Test partial reconstruction of specific polynomials."""
        shares = self.shamir.split_secret(self.secret_vector)
        
        # Reconstruct only first polynomial
        partial = self.shamir.partial_reconstruct(shares[:self.threshold], [0])
        self.assertEqual(len(partial), 1)
        self.assertEqual(partial[0], self.secret_vector[0])
        
        # Reconstruct only second polynomial
        partial2 = self.shamir.partial_reconstruct(shares[:self.threshold], [1])
        self.assertEqual(len(partial2), 1)
        self.assertEqual(partial2[0], self.secret_vector[1])
    
    def test_share_verification(self):
        """Test share verification functionality."""
        shares = self.shamir.split_secret(self.secret_vector)
        
        # Valid shares should pass verification
        self.assertTrue(self.shamir.verify_shares(shares))
        self.assertTrue(self.shamir.verify_shares(shares[:self.threshold]))
        
        # Test with duplicate participant IDs
        duplicate_shares = shares[:2] + [shares[0]]  # Add duplicate
        self.assertFalse(self.shamir.verify_shares(duplicate_shares))
        
        # Test with too few shares
        self.assertFalse(self.shamir.verify_shares([shares[0]]))
    
    def test_modular_inverse(self):
        """Test modular inverse computation."""
        # Test known cases
        self.assertEqual(self.shamir._mod_inverse(1, Q), 1)
        
        # Test that a * a^(-1) ≡ 1 (mod Q)
        for a in [2, 3, 5, 7, 11]:
            if a < Q:
                inv_a = self.shamir._mod_inverse(a, Q)
                self.assertEqual((a * inv_a) % Q, 1)
        
        # Test that inverse of 0 doesn't exist
        with self.assertRaises(ValueError):
            self.shamir._mod_inverse(0, Q)
    
    def test_lagrange_interpolation(self):
        """Test Lagrange interpolation."""
        # Test with simple polynomial: f(x) = 2x + 3
        points = [(1, 5), (2, 7), (3, 9)]  # f(1)=5, f(2)=7, f(3)=9
        
        # Interpolate at x=0 to get constant term
        result = self.shamir._lagrange_interpolation(points, 0)
        self.assertEqual(result % Q, 3)  # Should be 3
        
        # Interpolate at x=4
        result4 = self.shamir._lagrange_interpolation(points, 4)
        self.assertEqual(result4 % Q, 11)  # Should be 2*4 + 3 = 11
    
    def test_polynomial_evaluation(self):
        """Test polynomial evaluation."""
        # Test polynomial: f(x) = 1 + 2x + 3x^2
        coeffs = [1, 2, 3]
        
        # f(0) = 1
        self.assertEqual(self.shamir._evaluate_polynomial(coeffs, 0), 1)
        
        # f(1) = 1 + 2 + 3 = 6
        self.assertEqual(self.shamir._evaluate_polynomial(coeffs, 1), 6)
        
        # f(2) = 1 + 4 + 12 = 17
        self.assertEqual(self.shamir._evaluate_polynomial(coeffs, 2), 17)
    
    def test_different_vector_lengths(self):
        """Test with different polynomial vector lengths."""
        # Test with single polynomial
        single_poly = PolynomialVector([self.secret_poly1])
        shares = self.shamir.split_secret(single_poly)
        reconstructed = self.shamir.reconstruct_secret(shares[:self.threshold])
        self.assertEqual(reconstructed, single_poly)
        
        # Test with longer vector
        poly3 = Polynomial([100, 200, 300])
        long_vector = PolynomialVector([self.secret_poly1, self.secret_poly2, poly3])
        shares2 = self.shamir.split_secret(long_vector)
        reconstructed2 = self.shamir.reconstruct_secret(shares2[:self.threshold])
        self.assertEqual(reconstructed2, long_vector)
    
    def test_zero_polynomial_handling(self):
        """Test handling of zero polynomials."""
        zero_poly = Polynomial.zero()
        zero_vector = PolynomialVector([zero_poly])
        
        shares = self.shamir.split_secret(zero_vector)
        reconstructed = self.shamir.reconstruct_secret(shares[:self.threshold])
        
        self.assertEqual(reconstructed, zero_vector)
        self.assertTrue(reconstructed[0].is_zero())
    
    def test_random_polynomial_reconstruction(self):
        """Test reconstruction with random polynomials."""
        # Generate random polynomial vector
        random_polys = []
        for _ in range(3):
            coeffs = np.random.randint(0, 1000, size=10)
            random_polys.append(Polynomial(coeffs))
        
        random_vector = PolynomialVector(random_polys)
        
        # Split and reconstruct
        shares = self.shamir.split_secret(random_vector)
        reconstructed = self.shamir.reconstruct_secret(shares[:self.threshold])
        
        self.assertEqual(reconstructed, random_vector)
    
    def test_edge_case_thresholds(self):
        """Test edge cases for threshold values."""
        # Minimum threshold (2 out of 2)
        shamir_min = AdaptedShamirSSS(2, 2)
        shares = shamir_min.split_secret(self.secret_vector)
        reconstructed = shamir_min.reconstruct_secret(shares)
        self.assertEqual(reconstructed, self.secret_vector)
        
        # Large threshold
        shamir_large = AdaptedShamirSSS(10, 15)
        shares_large = shamir_large.split_secret(self.secret_vector)
        reconstructed_large = shamir_large.reconstruct_secret(shares_large[:10])
        self.assertEqual(reconstructed_large, self.secret_vector)


if __name__ == '__main__':
    unittest.main()

