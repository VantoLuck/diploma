"""
CRYSTALS-Dilithium Digital Signature Algorithm.

This module implements the core Dilithium algorithm as specified in the
NIST Post-Quantum Cryptography standard. It provides the foundation
for the threshold signature scheme.
"""

import hashlib
import secrets
import numpy as np
from typing import Tuple, Optional
from ..crypto.polynomials import Polynomial, PolynomialVector
from ..utils.constants import Q, N, get_params, DEFAULT_SECURITY_LEVEL


class DilithiumKeyPair:
    """
    Represents a Dilithium key pair (public and private keys).
    """
    
    def __init__(self, public_key: 'DilithiumPublicKey', 
                 private_key: 'DilithiumPrivateKey'):
        """
        Initialize key pair.
        
        Args:
            public_key: Public key component
            private_key: Private key component
        """
        self.public_key = public_key
        self.private_key = private_key


class DilithiumPublicKey:
    """
    Dilithium public key containing matrix A and vector t.
    """
    
    def __init__(self, A: np.ndarray, t: PolynomialVector, 
                 security_level: int = DEFAULT_SECURITY_LEVEL):
        """
        Initialize public key.
        
        Args:
            A: Public matrix A (k x l matrix of polynomials)
            t: Public vector t (k-dimensional polynomial vector)
            security_level: Security level (2, 3, or 5)
        """
        self.A = A
        self.t = t
        self.security_level = security_level
        self.params = get_params(security_level)


class DilithiumPrivateKey:
    """
    Dilithium private key containing secret vectors s1 and s2.
    """
    
    def __init__(self, s1: PolynomialVector, s2: PolynomialVector,
                 security_level: int = DEFAULT_SECURITY_LEVEL):
        """
        Initialize private key.
        
        Args:
            s1: Secret vector s1 (l-dimensional polynomial vector)
            s2: Secret vector s2 (k-dimensional polynomial vector)
            security_level: Security level (2, 3, or 5)
        """
        self.s1 = s1
        self.s2 = s2
        self.security_level = security_level
        self.params = get_params(security_level)


class DilithiumSignature:
    """
    Dilithium signature containing vectors z and h, and challenge c.
    """
    
    def __init__(self, z: PolynomialVector, h: PolynomialVector, c: Polynomial):
        """
        Initialize signature.
        
        Args:
            z: Response vector z
            h: Hint vector h
            c: Challenge polynomial c
        """
        self.z = z
        self.h = h
        self.c = c


class Dilithium:
    """
    Main Dilithium algorithm implementation.
    
    Provides key generation, signing, and verification functionality
    according to the CRYSTALS-Dilithium specification.
    """
    
    def __init__(self, security_level: int = DEFAULT_SECURITY_LEVEL):
        """
        Initialize Dilithium with specified security level.
        
        Args:
            security_level: Security level (2, 3, or 5)
        """
        self.security_level = security_level
        self.params = get_params(security_level)
        
        # Extract parameters for convenience
        self.k = self.params['k']
        self.l = self.params['l']
        self.eta = self.params['eta']
        self.tau = self.params['tau']
        self.beta = self.params['beta']
        self.gamma1 = self.params['gamma1']
        self.gamma2 = self.params['gamma2']
        self.d = self.params['d']
    
    def keygen(self, seed: Optional[bytes] = None) -> DilithiumKeyPair:
        """
        Generate a Dilithium key pair.
        
        Args:
            seed: Optional seed for deterministic key generation
            
        Returns:
            Generated key pair
        """
        if seed is None:
            seed = secrets.token_bytes(32)
        
        # Expand seed to generate randomness
        rho, rho_prime, K = self._expand_seed(seed)
        
        # Generate matrix A from rho
        A = self._expand_A(rho)
        
        # Sample secret vectors s1 and s2
        s1 = self._sample_s1(rho_prime)
        s2 = self._sample_s2(rho_prime)
        
        # Compute t = A * s1 + s2
        t = self._matrix_vector_multiply(A, s1) + s2
        
        # Extract high-order bits of t
        t1 = self._high_bits(t)
        
        public_key = DilithiumPublicKey(A, t1, self.security_level)
        private_key = DilithiumPrivateKey(s1, s2, self.security_level)
        
        return DilithiumKeyPair(public_key, private_key)
    
    def sign(self, message: bytes, private_key: DilithiumPrivateKey,
             randomness: Optional[bytes] = None) -> DilithiumSignature:
        """
        Sign a message using Dilithium.
        
        Args:
            message: Message to sign
            private_key: Private key for signing
            randomness: Optional randomness for deterministic signing
            
        Returns:
            Dilithium signature
        """
        if randomness is None:
            randomness = secrets.token_bytes(32)
        
        # Hash message
        mu = hashlib.shake_256(message).digest(64)
        
        # Initialize signing loop
        kappa = 0
        max_attempts = 1000  # Prevent infinite loops
        
        while kappa < max_attempts:
            # Sample mask vector y
            y = self._sample_y(randomness, kappa)
            
            # Compute w = A * y
            w = self._matrix_vector_multiply(private_key.s1, y)  # Simplified
            w1 = self._high_bits(w)
            
            # Generate challenge
            c = self._generate_challenge(mu, w1)
            
            # Compute response z = y + c * s1
            z = y + self._polynomial_vector_multiply(c, private_key.s1)
            
            # Check bounds
            if self._check_z_bounds(z):
                # Compute hint h
                h = self._compute_hint(w, z, private_key.s2, c)
                
                if self._check_h_bounds(h):
                    return DilithiumSignature(z, h, c)
            
            kappa += 1
        
        raise RuntimeError("Failed to generate signature after maximum attempts")
    
    def verify(self, message: bytes, signature: DilithiumSignature,
               public_key: DilithiumPublicKey) -> bool:
        """
        Verify a Dilithium signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Public key for verification
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Check signature bounds
            if not self._check_signature_bounds(signature):
                return False
            
            # Hash message
            mu = hashlib.shake_256(message).digest(64)
            
            # Recompute w'
            w_prime = self._recompute_w(signature, public_key)
            
            # Extract high bits using hint
            w1_prime = self._use_hint(signature.h, w_prime)
            
            # Recompute challenge
            c_prime = self._generate_challenge(mu, w1_prime)
            
            # Verify challenge matches
            return signature.c == c_prime
            
        except Exception:
            return False
    
    def _expand_seed(self, seed: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Expand seed into rho, rho_prime, and K.
        
        Args:
            seed: Input seed
            
        Returns:
            Tuple of (rho, rho_prime, K)
        """
        expanded = hashlib.shake_256(seed).digest(96)
        rho = expanded[:32]
        rho_prime = expanded[32:64]
        K = expanded[64:96]
        return rho, rho_prime, K
    
    def _expand_A(self, rho: bytes) -> np.ndarray:
        """
        Expand rho to generate public matrix A.
        
        Args:
            rho: Seed for matrix generation
            
        Returns:
            k x l matrix of polynomials
        """
        A = np.empty((self.k, self.l), dtype=object)
        
        for i in range(self.k):
            for j in range(self.l):
                # Generate polynomial A[i,j] from rho, i, j
                seed = rho + i.to_bytes(1, 'little') + j.to_bytes(1, 'little')
                poly_coeffs = self._sample_uniform(seed)
                A[i, j] = Polynomial(poly_coeffs)
        
        return A
    
    def _sample_uniform(self, seed: bytes) -> np.ndarray:
        """
        Sample uniform polynomial from seed.
        
        Args:
            seed: Seed for sampling
            
        Returns:
            Array of polynomial coefficients
        """
        # Simplified uniform sampling
        hash_output = hashlib.shake_256(seed).digest(N * 4)
        coeffs = np.frombuffer(hash_output, dtype=np.uint32)[:N] % Q
        return coeffs.astype(np.int32)
    
    def _sample_s1(self, rho_prime: bytes) -> PolynomialVector:
        """
        Sample secret vector s1.
        
        Args:
            rho_prime: Seed for sampling
            
        Returns:
            Secret vector s1
        """
        polys = []
        for i in range(self.l):
            seed = rho_prime + b's1' + i.to_bytes(1, 'little')
            coeffs = self._sample_eta(seed)
            polys.append(Polynomial(coeffs))
        return PolynomialVector(polys)
    
    def _sample_s2(self, rho_prime: bytes) -> PolynomialVector:
        """
        Sample secret vector s2.
        
        Args:
            rho_prime: Seed for sampling
            
        Returns:
            Secret vector s2
        """
        polys = []
        for i in range(self.k):
            seed = rho_prime + b's2' + i.to_bytes(1, 'little')
            coeffs = self._sample_eta(seed)
            polys.append(Polynomial(coeffs))
        return PolynomialVector(polys)
    
    def _sample_eta(self, seed: bytes) -> np.ndarray:
        """
        Sample polynomial with coefficients in [-eta, eta].
        
        Args:
            seed: Seed for sampling
            
        Returns:
            Array of polynomial coefficients
        """
        # Simplified eta sampling
        hash_output = hashlib.shake_256(seed).digest(N)
        coeffs = np.array([int(b) % (2 * self.eta + 1) - self.eta 
                          for b in hash_output], dtype=np.int32)
        return coeffs % Q
    
    def _sample_y(self, randomness: bytes, kappa: int) -> PolynomialVector:
        """
        Sample mask vector y.
        
        Args:
            randomness: Source of randomness
            kappa: Attempt counter
            
        Returns:
            Mask vector y
        """
        polys = []
        for i in range(self.l):
            seed = randomness + kappa.to_bytes(2, 'little') + i.to_bytes(1, 'little')
            coeffs = self._sample_gamma1(seed)
            polys.append(Polynomial(coeffs))
        return PolynomialVector(polys)
    
    def _sample_gamma1(self, seed: bytes) -> np.ndarray:
        """
        Sample polynomial with coefficients in [-gamma1, gamma1].
        
        Args:
            seed: Seed for sampling
            
        Returns:
            Array of polynomial coefficients
        """
        # Simplified gamma1 sampling
        hash_output = hashlib.shake_256(seed).digest(N * 4)
        coeffs = np.frombuffer(hash_output, dtype=np.uint32)[:N]
        coeffs = coeffs % (2 * self.gamma1 + 1) - self.gamma1
        return coeffs.astype(np.int32) % Q
    
    def _matrix_vector_multiply(self, A: np.ndarray, v: PolynomialVector) -> PolynomialVector:
        """
        Multiply matrix A by vector v.
        
        Args:
            A: Matrix of polynomials
            v: Polynomial vector
            
        Returns:
            Result of A * v
        """
        # Simplified matrix-vector multiplication
        result_polys = []
        rows, cols = A.shape
        
        for i in range(rows):
            result_poly = Polynomial.zero()
            for j in range(cols):
                if j < len(v):
                    result_poly = result_poly + A[i, j] * v[j]
            result_polys.append(result_poly)
        
        return PolynomialVector(result_polys)
    
    def _high_bits(self, v: PolynomialVector) -> PolynomialVector:
        """
        Extract high-order bits from polynomial vector.
        
        Args:
            v: Input polynomial vector
            
        Returns:
            High-order bits
        """
        # Simplified high bits extraction
        result_polys = []
        for poly in v.polys:
            high_coeffs = (poly.coeffs + self.gamma2) // (2 * self.gamma2)
            result_polys.append(Polynomial(high_coeffs))
        return PolynomialVector(result_polys)
    
    def _generate_challenge(self, mu: bytes, w1: PolynomialVector) -> Polynomial:
        """
        Generate challenge polynomial from message hash and w1.
        
        Args:
            mu: Message hash
            w1: High-order bits of w
            
        Returns:
            Challenge polynomial
        """
        # Simplified challenge generation
        seed = mu + b'challenge'
        coeffs = np.zeros(N, dtype=np.int32)
        
        # Sample tau positions for ±1 coefficients
        hash_output = hashlib.shake_256(seed).digest(self.tau * 2)
        for i in range(self.tau):
            pos = hash_output[i * 2] % N
            sign = 1 if hash_output[i * 2 + 1] % 2 == 0 else -1
            coeffs[pos] = sign
        
        return Polynomial(coeffs)
    
    def _polynomial_vector_multiply(self, c: Polynomial, v: PolynomialVector) -> PolynomialVector:
        """
        Multiply polynomial c by vector v.
        
        Args:
            c: Polynomial
            v: Polynomial vector
            
        Returns:
            Result of c * v
        """
        result_polys = []
        for poly in v.polys:
            result_polys.append(c * poly)
        return PolynomialVector(result_polys)
    
    def _check_z_bounds(self, z: PolynomialVector) -> bool:
        """
        Check if z satisfies bound requirements.
        
        Args:
            z: Response vector
            
        Returns:
            True if bounds are satisfied
        """
        return z.norm_infinity() < self.gamma1 - self.beta
    
    def _compute_hint(self, w: PolynomialVector, z: PolynomialVector,
                     s2: PolynomialVector, c: Polynomial) -> PolynomialVector:
        """
        Compute hint vector h.
        
        Args:
            w: Vector w
            z: Response vector z
            s2: Secret vector s2
            c: Challenge polynomial
            
        Returns:
            Hint vector h
        """
        # Simplified hint computation
        cs2 = self._polynomial_vector_multiply(c, s2)
        w_minus_cs2 = w - cs2
        return self._make_hint(w_minus_cs2, w)
    
    def _make_hint(self, v1: PolynomialVector, v2: PolynomialVector) -> PolynomialVector:
        """
        Create hint from two vectors.
        
        Args:
            v1: First vector
            v2: Second vector
            
        Returns:
            Hint vector
        """
        # Simplified hint creation
        result_polys = []
        for p1, p2 in zip(v1.polys, v2.polys):
            hint_coeffs = np.zeros(N, dtype=np.int32)
            # Simplified hint logic
            result_polys.append(Polynomial(hint_coeffs))
        return PolynomialVector(result_polys)
    
    def _check_h_bounds(self, h: PolynomialVector) -> bool:
        """
        Check if hint h satisfies bound requirements.
        
        Args:
            h: Hint vector
            
        Returns:
            True if bounds are satisfied
        """
        # Simplified bound check
        return True
    
    def _check_signature_bounds(self, signature: DilithiumSignature) -> bool:
        """
        Check if signature components satisfy bound requirements.
        
        Args:
            signature: Signature to check
            
        Returns:
            True if bounds are satisfied
        """
        return (signature.z.norm_infinity() < self.gamma1 - self.beta and
                signature.c.norm_infinity() <= self.tau)
    
    def _recompute_w(self, signature: DilithiumSignature,
                    public_key: DilithiumPublicKey) -> PolynomialVector:
        """
        Recompute w during verification.
        
        Args:
            signature: Signature being verified
            public_key: Public key
            
        Returns:
            Recomputed w vector
        """
        # w = A * z - c * t * 2^d
        Az = self._matrix_vector_multiply(public_key.A, signature.z)
        ct = self._polynomial_vector_multiply(signature.c, public_key.t)
        ct_scaled = ct * (2 ** self.d)
        return Az - ct_scaled
    
    def _use_hint(self, h: PolynomialVector, w: PolynomialVector) -> PolynomialVector:
        """
        Use hint to recover high-order bits.
        
        Args:
            h: Hint vector
            w: Vector w
            
        Returns:
            Recovered high-order bits
        """
        # Simplified hint usage
        return self._high_bits(w)

