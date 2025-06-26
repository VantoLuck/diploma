#!/usr/bin/env python3
"""
Unit tests for polynomial operations in Rq.

Tests the fundamental polynomial arithmetic operations used
in the Dilithium threshold signature scheme.
"""

import unittest
import numpy as np
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from dilithium_threshold.crypto.polynomials import Polynomial, PolynomialVector
from dilithium_threshold.utils.constants import Q, N


class TestPolynomial(unittest.TestCase):
    """Test cases for Polynomial class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.zero_poly = Polynomial.zero()
        self.one_poly = Polynomial.one()
        self.test_coeffs = [1, 2, 3, 4, 5]
        self.test_poly = Polynomial(self.test_coeffs)
    
    def test_polynomial_creation(self):
        """Test polynomial creation and initialization."""
        # Test creation with list
        poly = Polynomial([1, 2, 3])
        self.assertEqual(len(poly.coeffs), N)
        self.assertEqual(poly.coeffs[0], 1)
        self.assertEqual(poly.coeffs[1], 2)
        self.assertEqual(poly.coeffs[2], 3)
        
        # Test creation with numpy array
        coeffs_array = np.array([5, 4, 3, 2, 1], dtype=np.int32)
        poly2 = Polynomial(coeffs_array)
        self.assertEqual(poly2.coeffs[0], 5)
        self.assertEqual(poly2.coeffs[4], 1)
    
    def test_polynomial_addition(self):
        """Test polynomial addition."""
        poly1 = Polynomial([1, 2, 3])
        poly2 = Polynomial([4, 5, 6])
        result = poly1 + poly2
        
        self.assertEqual(result.coeffs[0], 5)
        self.assertEqual(result.coeffs[1], 7)
        self.assertEqual(result.coeffs[2], 9)
    
    def test_polynomial_subtraction(self):
        """Test polynomial subtraction."""
        poly1 = Polynomial([10, 20, 30])
        poly2 = Polynomial([1, 2, 3])
        result = poly1 - poly2
        
        self.assertEqual(result.coeffs[0], 9)
        self.assertEqual(result.coeffs[1], 18)
        self.assertEqual(result.coeffs[2], 27)
    
    def test_polynomial_scalar_multiplication(self):
        """Test polynomial multiplication by scalar."""
        poly = Polynomial([1, 2, 3])
        result = poly * 5
        
        self.assertEqual(result.coeffs[0], 5)
        self.assertEqual(result.coeffs[1], 10)
        self.assertEqual(result.coeffs[2], 15)
        
        # Test right multiplication
        result2 = 3 * poly
        self.assertEqual(result2.coeffs[0], 3)
        self.assertEqual(result2.coeffs[1], 6)
        self.assertEqual(result2.coeffs[2], 9)
    
    def test_polynomial_negation(self):
        """Test polynomial negation."""
        poly = Polynomial([1, 2, 3])
        neg_poly = -poly
        
        self.assertEqual(neg_poly.coeffs[0], (Q - 1) % Q)
        self.assertEqual(neg_poly.coeffs[1], (Q - 2) % Q)
        self.assertEqual(neg_poly.coeffs[2], (Q - 3) % Q)
    
    def test_polynomial_equality(self):
        """Test polynomial equality comparison."""
        poly1 = Polynomial([1, 2, 3])
        poly2 = Polynomial([1, 2, 3])
        poly3 = Polynomial([1, 2, 4])
        
        self.assertEqual(poly1, poly2)
        self.assertNotEqual(poly1, poly3)
    
    def test_polynomial_norms(self):
        """Test polynomial norm calculations."""
        # Test with small coefficients
        poly = Polynomial([1, -2, 3, -4])
        
        inf_norm = poly.norm_infinity()
        self.assertGreaterEqual(inf_norm, 0)
        
        l2_norm = poly.norm_l2()
        self.assertGreaterEqual(l2_norm, 0)
    
    def test_polynomial_degree(self):
        """Test polynomial degree calculation."""
        # Zero polynomial
        zero_poly = Polynomial.zero()
        self.assertEqual(zero_poly.degree(), -1)
        
        # Constant polynomial
        const_poly = Polynomial([5])
        self.assertEqual(const_poly.degree(), 0)
        
        # Higher degree polynomial
        poly = Polynomial([1, 2, 3, 0, 0])
        self.assertEqual(poly.degree(), 2)
    
    def test_polynomial_is_zero(self):
        """Test zero polynomial detection."""
        zero_poly = Polynomial.zero()
        self.assertTrue(zero_poly.is_zero())
        
        non_zero_poly = Polynomial([1])
        self.assertFalse(non_zero_poly.is_zero())
    
    def test_polynomial_copy(self):
        """Test polynomial copying."""
        original = Polynomial([1, 2, 3])
        copy_poly = original.copy()
        
        self.assertEqual(original, copy_poly)
        
        # Modify copy and ensure original is unchanged
        copy_poly.coeffs[0] = 999
        self.assertNotEqual(original, copy_poly)
    
    def test_special_polynomials(self):
        """Test special polynomial creation."""
        # Zero polynomial
        zero = Polynomial.zero()
        self.assertTrue(zero.is_zero())
        
        # One polynomial
        one = Polynomial.one()
        self.assertEqual(one.coeffs[0], 1)
        self.assertTrue(all(one.coeffs[i] == 0 for i in range(1, N)))
    
    def test_modular_reduction(self):
        """Test that coefficients are properly reduced modulo Q."""
        large_coeffs = [Q + 1, Q + 2, Q + 3]
        poly = Polynomial(large_coeffs)
        
        self.assertEqual(poly.coeffs[0], 1)
        self.assertEqual(poly.coeffs[1], 2)
        self.assertEqual(poly.coeffs[2], 3)


class TestPolynomialVector(unittest.TestCase):
    """Test cases for PolynomialVector class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.poly1 = Polynomial([1, 2, 3])
        self.poly2 = Polynomial([4, 5, 6])
        self.poly3 = Polynomial([7, 8, 9])
        self.vector = PolynomialVector([self.poly1, self.poly2, self.poly3])
    
    def test_vector_creation(self):
        """Test polynomial vector creation."""
        vector = PolynomialVector([self.poly1, self.poly2])
        self.assertEqual(len(vector), 2)
        self.assertEqual(vector[0], self.poly1)
        self.assertEqual(vector[1], self.poly2)
    
    def test_vector_addition(self):
        """Test polynomial vector addition."""
        vector1 = PolynomialVector([self.poly1, self.poly2])
        vector2 = PolynomialVector([self.poly2, self.poly3])
        result = vector1 + vector2
        
        self.assertEqual(len(result), 2)
        expected_poly1 = self.poly1 + self.poly2
        expected_poly2 = self.poly2 + self.poly3
        self.assertEqual(result[0], expected_poly1)
        self.assertEqual(result[1], expected_poly2)
    
    def test_vector_subtraction(self):
        """Test polynomial vector subtraction."""
        vector1 = PolynomialVector([self.poly2, self.poly3])
        vector2 = PolynomialVector([self.poly1, self.poly1])
        result = vector1 - vector2
        
        expected_poly1 = self.poly2 - self.poly1
        expected_poly2 = self.poly3 - self.poly1
        self.assertEqual(result[0], expected_poly1)
        self.assertEqual(result[1], expected_poly2)
    
    def test_vector_scalar_multiplication(self):
        """Test polynomial vector scalar multiplication."""
        vector = PolynomialVector([self.poly1, self.poly2])
        result = vector * 3
        
        expected_poly1 = self.poly1 * 3
        expected_poly2 = self.poly2 * 3
        self.assertEqual(result[0], expected_poly1)
        self.assertEqual(result[1], expected_poly2)
        
        # Test right multiplication
        result2 = 2 * vector
        expected_poly1_2 = self.poly1 * 2
        expected_poly2_2 = self.poly2 * 2
        self.assertEqual(result2[0], expected_poly1_2)
        self.assertEqual(result2[1], expected_poly2_2)
    
    def test_vector_indexing(self):
        """Test polynomial vector indexing."""
        vector = PolynomialVector([self.poly1, self.poly2, self.poly3])
        
        # Test getting
        self.assertEqual(vector[0], self.poly1)
        self.assertEqual(vector[1], self.poly2)
        self.assertEqual(vector[2], self.poly3)
        
        # Test setting
        new_poly = Polynomial([10, 11, 12])
        vector[1] = new_poly
        self.assertEqual(vector[1], new_poly)
    
    def test_vector_equality(self):
        """Test polynomial vector equality."""
        vector1 = PolynomialVector([self.poly1, self.poly2])
        vector2 = PolynomialVector([self.poly1, self.poly2])
        vector3 = PolynomialVector([self.poly1, self.poly3])
        
        self.assertEqual(vector1, vector2)
        self.assertNotEqual(vector1, vector3)
    
    def test_vector_norm(self):
        """Test polynomial vector norm calculation."""
        vector = PolynomialVector([self.poly1, self.poly2])
        norm = vector.norm_infinity()
        self.assertGreaterEqual(norm, 0)
    
    def test_vector_copy(self):
        """Test polynomial vector copying."""
        original = PolynomialVector([self.poly1, self.poly2])
        copy_vector = original.copy()
        
        self.assertEqual(original, copy_vector)
        
        # Modify copy and ensure original is unchanged
        new_poly = Polynomial([999])
        copy_vector[0] = new_poly
        self.assertNotEqual(original, copy_vector)
    
    def test_special_vectors(self):
        """Test special vector creation."""
        # Zero vector
        zero_vector = PolynomialVector.zero(3)
        self.assertEqual(len(zero_vector), 3)
        for poly in zero_vector.polys:
            self.assertTrue(poly.is_zero())
        
        # Random vector
        random_vector = PolynomialVector.random(2, 100)
        self.assertEqual(len(random_vector), 2)
    
    def test_vector_length_mismatch(self):
        """Test operations with mismatched vector lengths."""
        vector1 = PolynomialVector([self.poly1, self.poly2])
        vector2 = PolynomialVector([self.poly1])
        
        with self.assertRaises(ValueError):
            vector1 + vector2
        
        with self.assertRaises(ValueError):
            vector1 - vector2


if __name__ == '__main__':
    unittest.main()

