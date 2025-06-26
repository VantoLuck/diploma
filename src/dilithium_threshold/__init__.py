"""
Dilithium Threshold Signature Scheme

A post-quantum threshold signature implementation based on the CRYSTALS-Dilithium algorithm.
This implementation provides a secure threshold signature scheme that prevents secret leakage
during the signing process by adapting Shamir's secret sharing to polynomial vectors.

Author: Leonid Kartushin
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Leonid Kartushin"
__email__ = "leonid.kartushin@example.com"

from .core.threshold import ThresholdSignature
from .protocols.keygen import ThresholdKeyGen
from .protocols.sign import ThresholdSigner
from .protocols.verify import ThresholdVerifier

__all__ = [
    "ThresholdSignature",
    "ThresholdKeyGen", 
    "ThresholdSigner",
    "ThresholdVerifier"
]

