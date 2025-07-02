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
from .core.dilithium import Dilithium
from .core.shamir import AdaptedShamirSSS
from .crypto.polynomials import Polynomial, PolynomialVector

__all__ = [
    "ThresholdSignature",
    "Dilithium", 
    "AdaptedShamirSSS",
    "Polynomial",
    "PolynomialVector"
]

