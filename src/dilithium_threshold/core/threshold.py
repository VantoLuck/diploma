"""
Threshold Signature Scheme based on Dilithium.

This module implements the main threshold signature scheme that combines
the CRYSTALS-Dilithium algorithm with the adapted Shamir secret sharing
to enable threshold signatures without intermediate secret reconstruction.
"""

import hashlib
import secrets
import numpy as np
from typing import List, Tuple, Optional, Dict
from ..crypto.polynomials import Polynomial, PolynomialVector
from .dilithium import Dilithium, DilithiumPublicKey, DilithiumSignature
from .shamir import AdaptedShamirSSS, ShamirShare
from ..utils.constants import validate_threshold_config, DEFAULT_SECURITY_LEVEL, Q, N


class ThresholdKeyShare:
    """
    Represents a participant's share of the threshold key.
    
    Contains both the Shamir share of the secret key and the
    participant's identification information.
    """
    
    def __init__(self, participant_id: int, s1_share: ShamirShare, 
                 s2_share: ShamirShare, public_key: DilithiumPublicKey):
        """
        Initialize threshold key share.
        
        Args:
            participant_id: Unique participant identifier
            s1_share: Share of secret vector s1
            s2_share: Share of secret vector s2
            public_key: Shared public key
        """
        self.participant_id = participant_id
        self.s1_share = s1_share
        self.s2_share = s2_share
        self.public_key = public_key
    
    def __repr__(self) -> str:
        return f"ThresholdKeyShare(id={self.participant_id})"


class PartialSignature:
    """
    Represents a partial signature from one participant.
    
    Contains the participant's contribution to the threshold signature
    along with verification information.
    """
    
    def __init__(self, participant_id: int, z_partial: PolynomialVector,
                 commitment: PolynomialVector, challenge: Polynomial):
        """
        Initialize partial signature.
        
        Args:
            participant_id: Participant who created this partial signature
            z_partial: Partial response vector
            commitment: Commitment to the randomness used
            challenge: Challenge polynomial (same for all participants)
        """
        self.participant_id = participant_id
        self.z_partial = z_partial
        self.commitment = commitment
        self.challenge = challenge
    
    def __repr__(self) -> str:
        return f"PartialSignature(id={self.participant_id})"


class ThresholdSignature:
    """
    Main threshold signature scheme implementation.
    
    Provides distributed key generation, partial signing, and signature
    combination functionality while preventing secret leakage.
    """
    
    def __init__(self, threshold: int, participants: int,
                 security_level: int = DEFAULT_SECURITY_LEVEL):
        """
        Initialize threshold signature scheme.
        
        Args:
            threshold: Minimum participants needed for signing
            participants: Total number of participants
            security_level: Dilithium security level (2, 3, or 5)
            
        Raises:
            ValueError: If threshold configuration is invalid
        """
        if not validate_threshold_config(threshold, participants):
            raise ValueError("Invalid threshold configuration")
        
        self.threshold = threshold
        self.participants = participants
        self.security_level = security_level
        
        # Initialize underlying schemes
        self.dilithium = Dilithium(security_level)
        self.shamir_s1 = AdaptedShamirSSS(threshold, participants)
        self.shamir_s2 = AdaptedShamirSSS(threshold, participants)
        
        # Store participant IDs
        self.participant_ids = list(range(1, participants + 1))
    
    def distributed_keygen(self, seed: Optional[bytes] = None) -> List[ThresholdKeyShare]:
        """
        Generate threshold keys using distributed key generation.
        
        This method generates a Dilithium key pair and then splits the
        private key into shares using the adapted Shamir scheme.
        
        Args:
            seed: Optional seed for deterministic key generation
            
        Returns:
            List of threshold key shares, one for each participant
        """
        # Generate base Dilithium key pair
        key_pair = self.dilithium.keygen(seed)
        
        # Split secret vectors using adapted Shamir scheme
        s1_shares = self.shamir_s1.split_secret(key_pair.private_key.s1)
        s2_shares = self.shamir_s2.split_secret(key_pair.private_key.s2)
        
        # Create threshold key shares
        threshold_shares = []
        for i in range(self.participants):
            share = ThresholdKeyShare(
                participant_id=self.participant_ids[i],
                s1_share=s1_shares[i],
                s2_share=s2_shares[i],
                public_key=key_pair.public_key
            )
            threshold_shares.append(share)
        
        return threshold_shares
    
    def partial_sign(self, message: bytes, key_share: ThresholdKeyShare,
                    randomness: Optional[bytes] = None) -> PartialSignature:
        """
        Create a partial signature using a key share.
        
        This is the core innovation: each participant can create a partial
        signature using only their share, without reconstructing the full
        secret key.
        
        Args:
            message: Message to sign
            key_share: Participant's key share
            randomness: Optional randomness for deterministic signing
            
        Returns:
            Partial signature from this participant
        """
        if randomness is None:
            randomness = secrets.token_bytes(32)
        
        # Hash message
        mu = hashlib.shake_256(message).digest(64)
        
        # Generate participant-specific randomness
        participant_randomness = self._derive_participant_randomness(
            randomness, key_share.participant_id)
        
        # Sample mask vector y (participant's portion)
        y_partial = self._sample_partial_y(participant_randomness)
        
        # Compute partial commitment w_partial = A * y_partial
        # Note: This is simplified - in practice, we need coordination
        # between participants to compute the full commitment
        w_partial = self._compute_partial_commitment(
            key_share.public_key.A, y_partial)
        
        # For now, use a simplified challenge generation
        # In practice, this requires coordination between participants
        challenge = self._generate_partial_challenge(mu, w_partial)
        
        # Compute partial response z_partial = y_partial + c * s1_share
        c_s1 = self._multiply_challenge_by_share(challenge, key_share.s1_share)
        z_partial = y_partial + c_s1
        
        return PartialSignature(
            participant_id=key_share.participant_id,
            z_partial=z_partial,
            commitment=w_partial,
            challenge=challenge
        )
    
    def combine_signatures(self, partial_signatures: List[PartialSignature],
                          public_key: DilithiumPublicKey) -> DilithiumSignature:
        """
        Combine partial signatures into a complete threshold signature.
        
        This method reconstructs the full signature from partial signatures
        without ever reconstructing the secret key.
        
        Args:
            partial_signatures: List of partial signatures (≥ threshold)
            public_key: Public key for verification
            
        Returns:
            Complete Dilithium signature
            
        Raises:
            ValueError: If insufficient partial signatures provided
        """
        if len(partial_signatures) < self.threshold:
            raise ValueError(f"Need at least {self.threshold} partial signatures")
        
        # Verify all partial signatures use the same challenge
        challenge = partial_signatures[0].challenge
        if not all(ps.challenge == challenge for ps in partial_signatures):
            raise ValueError("All partial signatures must use the same challenge")
        
        # Use first threshold partial signatures
        active_partials = partial_signatures[:self.threshold]
        
        # Reconstruct z vector using Lagrange interpolation
        z = self._reconstruct_z_vector(active_partials)
        
        # Reconstruct hint h (simplified for this implementation)
        h = self._reconstruct_hint(active_partials, public_key)
        
        return DilithiumSignature(z, h, challenge)
    
    def verify_partial_signature(self, message: bytes, 
                                partial_sig: PartialSignature,
                                key_share: ThresholdKeyShare) -> bool:
        """
        Verify a partial signature.
        
        Args:
            message: Original message
            partial_sig: Partial signature to verify
            key_share: Key share used for signing
            
        Returns:
            True if partial signature is valid
        """
        try:
            # Hash message
            mu = hashlib.shake_256(message).digest(64)
            
            # Verify challenge consistency
            expected_challenge = self._generate_partial_challenge(
                mu, partial_sig.commitment)
            
            if partial_sig.challenge != expected_challenge:
                return False
            
            # Verify partial signature bounds
            if not self._check_partial_bounds(partial_sig):
                return False
            
            return True
            
        except Exception:
            return False
    
    def _derive_participant_randomness(self, base_randomness: bytes,
                                     participant_id: int) -> bytes:
        """
        Derive participant-specific randomness.
        
        Args:
            base_randomness: Base randomness
            participant_id: Participant identifier
            
        Returns:
            Participant-specific randomness
        """
        hasher = hashlib.sha256()
        hasher.update(base_randomness)
        hasher.update(participant_id.to_bytes(4, 'little'))
        hasher.update(b'participant_randomness')
        return hasher.digest()
    
    def _sample_partial_y(self, randomness: bytes) -> PolynomialVector:
        """
        Sample partial mask vector y.
        
        Args:
            randomness: Source of randomness
            
        Returns:
            Partial mask vector
        """
        # Sample polynomials for this participant's portion
        polys = []
        for i in range(self.dilithium.l):
            seed = randomness + i.to_bytes(1, 'little')
            coeffs = self.dilithium._sample_gamma1(seed)
            polys.append(Polynomial(coeffs))
        
        return PolynomialVector(polys)
    
    def _compute_partial_commitment(self, A, y_partial: PolynomialVector) -> PolynomialVector:
        """
        Compute partial commitment w_partial.
        
        Args:
            A: Public matrix
            y_partial: Partial mask vector
            
        Returns:
            Partial commitment
        """
        # Simplified partial commitment computation
        return self.dilithium._matrix_vector_multiply(A, y_partial)
    
    def _generate_partial_challenge(self, mu: bytes, 
                                  w_partial: PolynomialVector) -> Polynomial:
        """
        Generate challenge polynomial (simplified version).
        
        In practice, this requires coordination between participants
        to ensure all use the same challenge.
        
        Args:
            mu: Message hash
            w_partial: Partial commitment
            
        Returns:
            Challenge polynomial
        """
        # Simplified challenge generation
        return self.dilithium._generate_challenge(mu, w_partial)
    
    def _multiply_challenge_by_share(self, challenge: Polynomial,
                                   share: ShamirShare) -> PolynomialVector:
        """
        Multiply challenge by secret share.
        
        Args:
            challenge: Challenge polynomial
            share: Secret share
            
        Returns:
            Result of c * share
        """
        result_polys = []
        for poly in share.share_vector.polys:
            result_polys.append(challenge * poly)
        return PolynomialVector(result_polys)
    
    def _reconstruct_z_vector(self, partial_signatures: List[PartialSignature]) -> PolynomialVector:
        """
        Reconstruct z vector from partial signatures using Lagrange interpolation.
        
        Args:
            partial_signatures: List of partial signatures
            
        Returns:
            Reconstructed z vector
        """
        if not partial_signatures:
            raise ValueError("No partial signatures provided")
        
        # Get vector length from first partial signature
        vector_length = len(partial_signatures[0].z_partial)
        
        # Reconstruct each polynomial in the vector
        reconstructed_polys = []
        
        for poly_idx in range(vector_length):
            # Reconstruct each coefficient of this polynomial
            coeffs = np.zeros(N, dtype=np.int32)
            
            for coeff_idx in range(N):
                # Collect points for Lagrange interpolation
                points = []
                for ps in partial_signatures:
                    x = ps.participant_id
                    y = ps.z_partial[poly_idx].coeffs[coeff_idx]
                    points.append((x, y))
                
                # Perform Lagrange interpolation
                reconstructed_coeff = self._lagrange_interpolation(points, 0)
                coeffs[coeff_idx] = reconstructed_coeff % Q
            
            reconstructed_polys.append(Polynomial(coeffs))
        
        return PolynomialVector(reconstructed_polys)
    
    def _reconstruct_hint(self, partial_signatures: List[PartialSignature],
                         public_key: DilithiumPublicKey) -> PolynomialVector:
        """
        Reconstruct hint vector (simplified implementation).
        
        Args:
            partial_signatures: List of partial signatures
            public_key: Public key
            
        Returns:
            Reconstructed hint vector
        """
        # Simplified hint reconstruction
        # In practice, this would involve more complex coordination
        hint_polys = []
        for i in range(self.dilithium.k):
            hint_polys.append(Polynomial.zero())
        
        return PolynomialVector(hint_polys)
    
    def _lagrange_interpolation(self, points: List[Tuple[int, int]], x: int) -> int:
        """
        Perform Lagrange interpolation.
        
        Args:
            points: List of (x_i, y_i) points
            x: Point at which to evaluate
            
        Returns:
            Interpolated value at x
        """
        from ..utils.constants import Q
        
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
            
            # Compute modular inverse
            denominator_inv = pow(denominator, Q - 2, Q)  # Fermat's little theorem
            
            # Add contribution
            # Use int64 to prevent overflow
            contribution = (int(yi) * int(numerator) * int(denominator_inv)) % Q
            result = (result + contribution) % Q
        
        return result
    
    def _check_partial_bounds(self, partial_sig: PartialSignature) -> bool:
        """
        Check if partial signature satisfies bound requirements.
        
        Args:
            partial_sig: Partial signature to check
            
        Returns:
            True if bounds are satisfied
        """
        # Check z_partial bounds
        gamma1 = self.dilithium.params['gamma1']
        beta = self.dilithium.params['beta']
        
        return partial_sig.z_partial.norm_infinity() < gamma1 - beta
    
    def get_threshold_info(self) -> Dict[str, int]:
        """
        Get information about the threshold configuration.
        
        Returns:
            Dictionary with threshold configuration details
        """
        return {
            'threshold': self.threshold,
            'participants': self.participants,
            'security_level': self.security_level,
            'min_signers': self.threshold,
            'max_participants': self.participants
        }

