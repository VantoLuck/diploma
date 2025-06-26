"""
Constants for Dilithium algorithm and threshold signature scheme.

This module contains all the mathematical constants and parameters
used in the CRYSTALS-Dilithium algorithm and its threshold adaptation.
"""

# Ring parameters
Q = 8380417  # Prime modulus for Zq
N = 256      # Polynomial degree (X^256 + 1)

# Dilithium parameter sets
DILITHIUM_PARAMS = {
    2: {  # Dilithium2 (NIST Level 1)
        'k': 4,      # Dimension of vector s1
        'l': 4,      # Dimension of vector s2  
        'eta': 2,    # Bound for coefficients in s1, s2
        'tau': 39,   # Number of ±1's in challenge polynomial
        'beta': 78,  # Bound for infinity norm of z
        'gamma1': (Q - 1) // 88,  # Bound for y coefficients
        'gamma2': (Q - 1) // 32,  # Bound for low-order bits
        'd': 13,     # Dropped bits from t
    },
    3: {  # Dilithium3 (NIST Level 3)
        'k': 6,
        'l': 5,
        'eta': 4,
        'tau': 49,
        'beta': 196,
        'gamma1': (Q - 1) // 32,
        'gamma2': (Q - 1) // 32,
        'd': 13,
    },
    5: {  # Dilithium5 (NIST Level 5)
        'k': 8,
        'l': 7,
        'eta': 2,
        'tau': 60,
        'beta': 120,
        'gamma1': (Q - 1) // 32,
        'gamma2': (Q - 1) // 32,
        'd': 13,
    }
}

# Default parameter set
DEFAULT_SECURITY_LEVEL = 3
DEFAULT_PARAMS = DILITHIUM_PARAMS[DEFAULT_SECURITY_LEVEL]

# Threshold signature parameters
MAX_PARTICIPANTS = 255  # Maximum number of participants
MIN_THRESHOLD = 2       # Minimum threshold value

# Common threshold configurations
THRESHOLD_CONFIGS = {
    '2_of_3': (2, 3),
    '3_of_5': (3, 5),
    '5_of_7': (5, 7),
    '7_of_10': (7, 10),
}

# NTT parameters for fast polynomial multiplication
# Primitive 512th root of unity modulo Q
ZETA = 1753  
NTT_ZETAS = []  # Will be computed during initialization

# Hash function parameters
SHAKE256_RATE = 136  # Rate for SHAKE256
HASH_OUTPUT_LENGTH = 32  # Standard hash output length

# Serialization parameters
POLY_BYTES = 32 * N // 8  # Bytes needed for one polynomial
SIGNATURE_BYTES = {
    2: 2420,  # Dilithium2 signature size
    3: 3293,  # Dilithium3 signature size  
    5: 4595,  # Dilithium5 signature size
}

# Error messages
ERROR_MESSAGES = {
    'invalid_threshold': "Threshold must be between 2 and number of participants",
    'invalid_participants': f"Number of participants must be between 2 and {MAX_PARTICIPANTS}",
    'insufficient_shares': "Insufficient shares for signature reconstruction",
    'invalid_share': "Invalid share format or content",
    'verification_failed': "Signature verification failed",
    'key_generation_failed': "Key generation failed",
}

def get_params(security_level: int = DEFAULT_SECURITY_LEVEL) -> dict:
    """
    Get Dilithium parameters for specified security level.
    
    Args:
        security_level: Security level (2, 3, or 5)
        
    Returns:
        Dictionary containing all parameters for the security level
        
    Raises:
        ValueError: If security level is not supported
    """
    if security_level not in DILITHIUM_PARAMS:
        raise ValueError(f"Unsupported security level: {security_level}")
    return DILITHIUM_PARAMS[security_level].copy()

def validate_threshold_config(threshold: int, participants: int) -> bool:
    """
    Validate threshold signature configuration.
    
    Args:
        threshold: Minimum number of participants needed for signing
        participants: Total number of participants
        
    Returns:
        True if configuration is valid, False otherwise
    """
    return (MIN_THRESHOLD <= threshold <= participants <= MAX_PARTICIPANTS)

