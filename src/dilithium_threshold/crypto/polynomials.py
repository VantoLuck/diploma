"""
Polynomial operations in the ring Rq = Zq[X]/(X^256 + 1).

This module implements polynomial arithmetic operations needed for the
Dilithium algorithm, including addition, multiplication, and reduction
operations in the quotient ring.
"""

import numpy as np
from typing import List, Union
from ..utils.constants import Q, N


class Polynomial:
    """
    Represents a polynomial in Rq = Zq[X]/(X^256 + 1).
    
    Coefficients are stored as a numpy array of integers modulo Q.
    """
    
    def __init__(self, coeffs: Union[List[int], np.ndarray]):
        """
        Initialize polynomial with given coefficients.
        
        Args:
            coeffs: List or array of polynomial coefficients
        """
        if isinstance(coeffs, list):
            coeffs = np.array(coeffs, dtype=np.int32)
        elif not isinstance(coeffs, np.ndarray):
            raise TypeError("Coefficients must be list or numpy array")
            
        # Ensure we have exactly N coefficients
        if len(coeffs) > N:
            # Reduce modulo X^N + 1
            self.coeffs = self._reduce_mod_xn_plus_1(coeffs)
        elif len(coeffs) < N:
            # Pad with zeros
            self.coeffs = np.zeros(N, dtype=np.int32)
            self.coeffs[:len(coeffs)] = coeffs
        else:
            self.coeffs = coeffs.astype(np.int32)
            
        # Reduce coefficients modulo Q
        self.coeffs = self.coeffs % Q
    
    def _reduce_mod_xn_plus_1(self, coeffs: np.ndarray) -> np.ndarray:
        """
        Reduce polynomial modulo X^N + 1.
        
        Args:
            coeffs: Polynomial coefficients (possibly longer than N)
            
        Returns:
            Reduced coefficients of length N
        """
        result = np.zeros(N, dtype=np.int32)
        
        for i, coeff in enumerate(coeffs):
            pos = i % N
            if i >= N and (i // N) % 2 == 1:
                # X^N = -1, so X^(N+k) = -X^k
                result[pos] = (result[pos] - coeff) % Q
            else:
                result[pos] = (result[pos] + coeff) % Q
                
        return result
    
    def __add__(self, other: 'Polynomial') -> 'Polynomial':
        """Add two polynomials."""
        return Polynomial((self.coeffs + other.coeffs) % Q)
    
    def __sub__(self, other: 'Polynomial') -> 'Polynomial':
        """Subtract two polynomials."""
        return Polynomial((self.coeffs - other.coeffs) % Q)
    
    def __mul__(self, other: Union['Polynomial', int]) -> 'Polynomial':
        """Multiply polynomial by another polynomial or scalar."""
        if isinstance(other, int):
            return Polynomial((self.coeffs * other) % Q)
        elif isinstance(other, Polynomial):
            return self._poly_multiply(other)
        else:
            raise TypeError("Can only multiply by Polynomial or int")
    
    def __rmul__(self, other: int) -> 'Polynomial':
        """Right multiplication by scalar."""
        return self.__mul__(other)
    
    def __neg__(self) -> 'Polynomial':
        """Negate polynomial."""
        return Polynomial((-self.coeffs) % Q)
    
    def __eq__(self, other: 'Polynomial') -> bool:
        """Check equality of polynomials."""
        return np.array_equal(self.coeffs, other.coeffs)
    
    def __repr__(self) -> str:
        """String representation of polynomial."""
        return f"Polynomial({self.coeffs.tolist()})"
    
    def _poly_multiply(self, other: 'Polynomial') -> 'Polynomial':
        """
        Multiply two polynomials in Rq.
        
        This is a naive O(N^2) implementation. For better performance,
        use NTT-based multiplication in the ntt module.
        """
        result_coeffs = np.zeros(2 * N - 1, dtype=np.int64)
        
        for i in range(N):
            for j in range(N):
                result_coeffs[i + j] += self.coeffs[i] * other.coeffs[j]
        
        return Polynomial(result_coeffs % Q)
    
    def norm_infinity(self) -> int:
        """
        Compute infinity norm of polynomial.
        
        Returns:
            Maximum absolute value of coefficients
        """
        # Convert to signed representation
        signed_coeffs = self.coeffs.copy()
        signed_coeffs[signed_coeffs > Q // 2] -= Q
        return int(np.max(np.abs(signed_coeffs)))
    
    def norm_l2(self) -> float:
        """
        Compute L2 norm of polynomial.
        
        Returns:
            L2 norm of coefficients
        """
        signed_coeffs = self.coeffs.copy()
        signed_coeffs[signed_coeffs > Q // 2] -= Q
        return float(np.sqrt(np.sum(signed_coeffs ** 2)))
    
    def is_zero(self) -> bool:
        """Check if polynomial is zero."""
        return np.all(self.coeffs == 0)
    
    def degree(self) -> int:
        """
        Get degree of polynomial.
        
        Returns:
            Degree of polynomial (-1 for zero polynomial)
        """
        if self.is_zero():
            return -1
        
        for i in range(N - 1, -1, -1):
            if self.coeffs[i] != 0:
                return i
        return -1
    
    def copy(self) -> 'Polynomial':
        """Create a copy of the polynomial."""
        return Polynomial(self.coeffs.copy())
    
    @classmethod
    def zero(cls) -> 'Polynomial':
        """Create zero polynomial."""
        return cls(np.zeros(N, dtype=np.int32))
    
    @classmethod
    def one(cls) -> 'Polynomial':
        """Create polynomial representing 1."""
        coeffs = np.zeros(N, dtype=np.int32)
        coeffs[0] = 1
        return cls(coeffs)
    
    @classmethod
    def random(cls, bound: int = Q) -> 'Polynomial':
        """
        Generate random polynomial with coefficients in [0, bound).
        
        Args:
            bound: Upper bound for coefficients
            
        Returns:
            Random polynomial
        """
        coeffs = np.random.randint(0, bound, size=N, dtype=np.int32)
        return cls(coeffs)


class PolynomialVector:
    """
    Represents a vector of polynomials in Rq.
    
    Used for representing keys and intermediate values in Dilithium.
    """
    
    def __init__(self, polynomials: List[Polynomial]):
        """
        Initialize polynomial vector.
        
        Args:
            polynomials: List of Polynomial objects
        """
        if not all(isinstance(p, Polynomial) for p in polynomials):
            raise TypeError("All elements must be Polynomial objects")
        self.polys = polynomials.copy()
        self.length = len(polynomials)
    
    def __add__(self, other: 'PolynomialVector') -> 'PolynomialVector':
        """Add two polynomial vectors."""
        if self.length != other.length:
            raise ValueError("Vector lengths must match")
        return PolynomialVector([p1 + p2 for p1, p2 in zip(self.polys, other.polys)])
    
    def __sub__(self, other: 'PolynomialVector') -> 'PolynomialVector':
        """Subtract two polynomial vectors."""
        if self.length != other.length:
            raise ValueError("Vector lengths must match")
        return PolynomialVector([p1 - p2 for p1, p2 in zip(self.polys, other.polys)])
    
    def __mul__(self, scalar: int) -> 'PolynomialVector':
        """Multiply vector by scalar."""
        return PolynomialVector([p * scalar for p in self.polys])
    
    def __rmul__(self, scalar: int) -> 'PolynomialVector':
        """Right multiplication by scalar."""
        return self.__mul__(scalar)
    
    def __getitem__(self, index: int) -> Polynomial:
        """Get polynomial at index."""
        return self.polys[index]
    
    def __setitem__(self, index: int, value: Polynomial):
        """Set polynomial at index."""
        if not isinstance(value, Polynomial):
            raise TypeError("Value must be a Polynomial")
        self.polys[index] = value
    
    def __len__(self) -> int:
        """Get length of vector."""
        return self.length
    
    def __eq__(self, other: 'PolynomialVector') -> bool:
        """Check equality of vectors."""
        return (self.length == other.length and 
                all(p1 == p2 for p1, p2 in zip(self.polys, other.polys)))
    
    def norm_infinity(self) -> int:
        """
        Compute infinity norm of vector.
        
        Returns:
            Maximum infinity norm among all polynomials
        """
        return max(p.norm_infinity() for p in self.polys)
    
    def copy(self) -> 'PolynomialVector':
        """Create a copy of the vector."""
        return PolynomialVector([p.copy() for p in self.polys])
    
    @classmethod
    def zero(cls, length: int) -> 'PolynomialVector':
        """Create zero vector of given length."""
        return cls([Polynomial.zero() for _ in range(length)])
    
    @classmethod
    def random(cls, length: int, bound: int = Q) -> 'PolynomialVector':
        """
        Generate random polynomial vector.
        
        Args:
            length: Number of polynomials in vector
            bound: Upper bound for coefficients
            
        Returns:
            Random polynomial vector
        """
        return cls([Polynomial.random(bound) for _ in range(length)])

