"""
Adapted Shamir's Secret Sharing for Polynomial Vectors.

This module implements the core innovation of the threshold signature scheme:
adapting Shamir's secret sharing to work with polynomial vectors from the
Dilithium algorithm, enabling threshold signatures without intermediate
secret reconstruction.
"""

import numpy as np
from typing import List, Tuple, Dict
import secrets
from ..crypto.polynomials import Polynomial, PolynomialVector
from ..utils.constants import Q, N, validate_threshold_config


class ShamirShare:
    """
    Represents a share in the adapted Shamir secret sharing scheme.
    
    Each share contains the participant ID and the polynomial vector
    representing their portion of the secret.
    """
    
    def __init__(self, participant_id: int, share_vector: PolynomialVector):
        """
        Initialize a Shamir share.
        
        Args:
            participant_id: Unique identifier for the participant (1-based)
            share_vector: Polynomial vector representing the share
        """
        if participant_id < 1:
            raise ValueError("Participant ID must be positive")
        
        self.participant_id = participant_id
        self.share_vector = share_vector
        self.vector_length = len(share_vector)
    
    def __repr__(self) -> str:
        return f"ShamirShare(id={self.participant_id}, length={self.vector_length})"


class AdaptedShamirSSS:
    """
    Adapted Shamir Secret Sharing Scheme for Polynomial Vectors.
    
    This class implements the key innovation: applying Shamir's scheme
    to each coefficient of each polynomial in the vector independently,
    then organizing the results into structured shares.
    """
    
    def __init__(self, threshold: int, participants: int):
        """
        Initialize the adapted Shamir scheme.
        
        Args:
            threshold: Minimum number of shares needed for reconstruction
            participants: Total number of participants
            
        Raises:
            ValueError: If threshold configuration is invalid
        """
        if not validate_threshold_config(threshold, participants):
            raise ValueError("Invalid threshold configuration")
        
        self.threshold = threshold
        self.participants = participants
        self.participant_ids = list(range(1, participants + 1))
    
    def split_secret(self, secret_vector: PolynomialVector) -> List[ShamirShare]:
        """
        Split a polynomial vector secret into shares.
        
        The key innovation: for each polynomial in the vector, and for each
        coefficient in that polynomial, we create a separate Shamir polynomial.
        This allows reconstruction without ever assembling the full secret.
        
        Args:
            secret_vector: The polynomial vector to be shared
            
        Returns:
            List of shares, one for each participant
        """
        vector_length = len(secret_vector)
        shares = []
        
        # For each participant, we'll collect their share of each coefficient
        participant_shares = {pid: [] for pid in self.participant_ids}
        
        # Process each polynomial in the vector
        for poly_idx in range(vector_length):
            polynomial = secret_vector[poly_idx]
            
            # Process each coefficient in the polynomial
            for coeff_idx in range(N):
                secret_coeff = polynomial.coeffs[coeff_idx]
                
                # Create Shamir polynomial for this coefficient
                shamir_poly = self._create_shamir_polynomial(secret_coeff)
                
                # Evaluate polynomial at each participant's ID
                for pid in self.participant_ids:
                    share_value = self._evaluate_polynomial(shamir_poly, pid)
                    participant_shares[pid].append((poly_idx, coeff_idx, share_value))
        
        # Organize shares into polynomial vectors for each participant
        for pid in self.participant_ids:
            share_polys = []
            
            for poly_idx in range(vector_length):
                # Collect coefficients for this polynomial
                coeffs = np.zeros(N, dtype=np.int32)
                
                for poly_i, coeff_i, value in participant_shares[pid]:
                    if poly_i == poly_idx:
                        coeffs[coeff_i] = value
                
                share_polys.append(Polynomial(coeffs))
            
            share_vector = PolynomialVector(share_polys)
            shares.append(ShamirShare(pid, share_vector))
        
        return shares
    
    def reconstruct_secret(self, shares: List[ShamirShare]) -> PolynomialVector:
        """
        Reconstruct the secret from a sufficient number of shares.
        
        Args:
            shares: List of shares (must have at least threshold shares)
            
        Returns:
            Reconstructed polynomial vector
            
        Raises:
            ValueError: If insufficient shares provided
        """
        if len(shares) < self.threshold:
            raise ValueError(f"Need at least {self.threshold} shares, got {len(shares)}")
        
        # Use first threshold shares
        active_shares = shares[:self.threshold]
        vector_length = active_shares[0].vector_length
        
        # Verify all shares have same vector length
        if not all(share.vector_length == vector_length for share in active_shares):
            raise ValueError("All shares must have same vector length")
        
        reconstructed_polys = []
        
        # Reconstruct each polynomial in the vector
        for poly_idx in range(vector_length):
            coeffs = np.zeros(N, dtype=np.int32)
            
            # Reconstruct each coefficient
            for coeff_idx in range(N):
                # Collect share values for this coefficient
                points = []
                for share in active_shares:
                    x = share.participant_id
                    y = share.share_vector[poly_idx].coeffs[coeff_idx]
                    points.append((x, y))
                
                # Use Lagrange interpolation to reconstruct coefficient
                reconstructed_coeff = self._lagrange_interpolation(points, 0)
                coeffs[coeff_idx] = reconstructed_coeff % Q
            
            reconstructed_polys.append(Polynomial(coeffs))
        
        return PolynomialVector(reconstructed_polys)
    
    def partial_reconstruct(self, shares: List[ShamirShare], 
                          poly_indices: List[int]) -> PolynomialVector:
        """
        Partially reconstruct only specified polynomials from the vector.
        
        This is useful for threshold operations where we only need
        specific parts of the secret vector.
        
        Args:
            shares: List of shares
            poly_indices: Indices of polynomials to reconstruct
            
        Returns:
            Polynomial vector containing only requested polynomials
        """
        if len(shares) < self.threshold:
            raise ValueError(f"Need at least {self.threshold} shares")
        
        active_shares = shares[:self.threshold]
        reconstructed_polys = []
        
        for poly_idx in poly_indices:
            coeffs = np.zeros(N, dtype=np.int32)
            
            for coeff_idx in range(N):
                points = []
                for share in active_shares:
                    x = share.participant_id
                    y = share.share_vector[poly_idx].coeffs[coeff_idx]
                    points.append((x, y))
                
                reconstructed_coeff = self._lagrange_interpolation(points, 0)
                coeffs[coeff_idx] = reconstructed_coeff % Q
            
            reconstructed_polys.append(Polynomial(coeffs))
        
        return PolynomialVector(reconstructed_polys)
    
    def _create_shamir_polynomial(self, secret: int) -> List[int]:
        """
        Create a Shamir polynomial with given secret as constant term.
        
        Args:
            secret: The secret value (constant term)
            
        Returns:
            List of polynomial coefficients [a0, a1, ..., a_{t-1}]
            where a0 = secret
        """
        coeffs = [secret]
        
        # Generate random coefficients for higher degree terms
        for _ in range(self.threshold - 1):
            coeffs.append(secrets.randbelow(Q))
        
        return coeffs
    
    def _evaluate_polynomial(self, poly_coeffs: List[int], x: int) -> int:
        """
        Evaluate polynomial at given point using Horner's method.
        
        Args:
            poly_coeffs: Polynomial coefficients [a0, a1, ..., a_{t-1}]
            x: Point at which to evaluate
            
        Returns:
            Polynomial value at x, modulo Q
        """
        result = 0
        x_power = 1
        
        for coeff in poly_coeffs:
            result = (result + coeff * x_power) % Q
            x_power = (x_power * x) % Q
        
        return result
    
    def _lagrange_interpolation(self, points: List[Tuple[int, int]], x: int) -> int:
        """
        Perform Lagrange interpolation to find polynomial value at x.
        
        Args:
            points: List of (x_i, y_i) points
            x: Point at which to evaluate
            
        Returns:
            Interpolated value at x, modulo Q
        """
        result = 0
        n = len(points)
        
        for i in range(n):
            xi, yi = points[i]
            
            # Compute Lagrange basis polynomial L_i(x)
            numerator = 1
            denominator = 1
            
            for j in range(n):
                if i != j:
                    xj, _ = points[j]
                    numerator = (numerator * (x - xj)) % Q
                    denominator = (denominator * (xi - xj)) % Q
            
            # Compute modular inverse of denominator
            denominator_inv = self._mod_inverse(denominator, Q)
            
            # Add contribution of this basis polynomial
            contribution = (yi * numerator * denominator_inv) % Q
            result = (result + contribution) % Q
        
        return result
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """
        Compute modular inverse of a modulo m using extended Euclidean algorithm.
        
        Args:
            a: Number to find inverse of
            m: Modulus
            
        Returns:
            Modular inverse of a modulo m
            
        Raises:
            ValueError: If inverse doesn't exist
        """
        if m == 1:
            return 0
        
        # Extended Euclidean Algorithm
        def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % m, m)
        
        if gcd != 1:
            raise ValueError(f"Modular inverse of {a} modulo {m} does not exist")
        
        return (x % m + m) % m
    
    def verify_shares(self, shares: List[ShamirShare]) -> bool:
        """
        Verify that shares are consistent and valid.
        
        Args:
            shares: List of shares to verify
            
        Returns:
            True if shares are valid, False otherwise
        """
        if len(shares) < 2:
            return False
        
        # Check that all shares have same vector length
        vector_length = shares[0].vector_length
        if not all(share.vector_length == vector_length for share in shares):
            return False
        
        # Check that participant IDs are unique and valid
        participant_ids = [share.participant_id for share in shares]
        if len(set(participant_ids)) != len(participant_ids):
            return False
        
        if not all(1 <= pid <= self.participants for pid in participant_ids):
            return False
        
        return True

