# API Reference

## Core Classes

### ThresholdSignature

Main class for threshold signature operations.

```python
class ThresholdSignature:
    def __init__(self, threshold: int, participants: int, security_level: int = 3)
```

#### Parameters
- `threshold`: Minimum number of participants needed for signing (2 ≤ threshold ≤ participants)
- `participants`: Total number of participants (threshold ≤ participants ≤ 255)
- `security_level`: Dilithium security level (2, 3, or 5)

#### Methods

##### `distributed_keygen(seed: Optional[bytes] = None) -> List[ThresholdKeyShare]`

Generate threshold key shares for all participants.

**Parameters:**
- `seed`: Optional seed for deterministic key generation

**Returns:**
- List of `ThresholdKeyShare` objects, one for each participant

**Example:**
```python
ts = ThresholdSignature(3, 5)
key_shares = ts.distributed_keygen()
```

##### `partial_sign(message: bytes, key_share: ThresholdKeyShare, randomness: Optional[bytes] = None) -> PartialSignature`

Create a partial signature using a participant's key share.

**Parameters:**
- `message`: Message to sign
- `key_share`: Participant's key share
- `randomness`: Optional randomness for deterministic signing

**Returns:**
- `PartialSignature` object

**Example:**
```python
message = b"Hello, world!"
partial_sig = ts.partial_sign(message, key_shares[0])
```

##### `combine_signatures(partial_signatures: List[PartialSignature], public_key: DilithiumPublicKey) -> DilithiumSignature`

Combine partial signatures into a complete threshold signature.

**Parameters:**
- `partial_signatures`: List of partial signatures (must have ≥ threshold signatures)
- `public_key`: Public key for verification

**Returns:**
- `DilithiumSignature` object

**Raises:**
- `ValueError`: If insufficient partial signatures provided

**Example:**
```python
partial_sigs = [ts.partial_sign(message, share) for share in key_shares[:3]]
signature = ts.combine_signatures(partial_sigs, key_shares[0].public_key)
```

##### `verify_partial_signature(message: bytes, partial_sig: PartialSignature, key_share: ThresholdKeyShare) -> bool`

Verify a partial signature.

**Parameters:**
- `message`: Original message
- `partial_sig`: Partial signature to verify
- `key_share`: Key share used for signing

**Returns:**
- `True` if partial signature is valid, `False` otherwise

##### `get_threshold_info() -> Dict[str, int]`

Get information about the threshold configuration.

**Returns:**
- Dictionary with configuration details

### ThresholdKeyShare

Represents a participant's share of the threshold key.

```python
class ThresholdKeyShare:
    participant_id: int
    s1_share: ShamirShare
    s2_share: ShamirShare
    public_key: DilithiumPublicKey
```

#### Attributes
- `participant_id`: Unique participant identifier (1-based)
- `s1_share`: Share of secret vector s1
- `s2_share`: Share of secret vector s2
- `public_key`: Shared public key

### PartialSignature

Represents a partial signature from one participant.

```python
class PartialSignature:
    participant_id: int
    z_partial: PolynomialVector
    commitment: PolynomialVector
    challenge: Polynomial
```

#### Attributes
- `participant_id`: Participant who created this partial signature
- `z_partial`: Partial response vector
- `commitment`: Commitment to the randomness used
- `challenge`: Challenge polynomial

### AdaptedShamirSSS

Implements adapted Shamir secret sharing for polynomial vectors.

```python
class AdaptedShamirSSS:
    def __init__(self, threshold: int, participants: int)
```

#### Methods

##### `split_secret(secret_vector: PolynomialVector) -> List[ShamirShare]`

Split a polynomial vector secret into shares.

**Parameters:**
- `secret_vector`: The polynomial vector to be shared

**Returns:**
- List of `ShamirShare` objects

##### `reconstruct_secret(shares: List[ShamirShare]) -> PolynomialVector`

Reconstruct the secret from shares.

**Parameters:**
- `shares`: List of shares (must have ≥ threshold shares)

**Returns:**
- Reconstructed polynomial vector

**Raises:**
- `ValueError`: If insufficient shares provided

##### `partial_reconstruct(shares: List[ShamirShare], poly_indices: List[int]) -> PolynomialVector`

Partially reconstruct only specified polynomials.

**Parameters:**
- `shares`: List of shares
- `poly_indices`: Indices of polynomials to reconstruct

**Returns:**
- Polynomial vector containing only requested polynomials

##### `verify_shares(shares: List[ShamirShare]) -> bool`

Verify that shares are consistent and valid.

**Parameters:**
- `shares`: List of shares to verify

**Returns:**
- `True` if shares are valid, `False` otherwise

### ShamirShare

Represents a share in the adapted Shamir secret sharing scheme.

```python
class ShamirShare:
    participant_id: int
    share_vector: PolynomialVector
    vector_length: int
```

#### Attributes
- `participant_id`: Unique identifier for the participant
- `share_vector`: Polynomial vector representing the share
- `vector_length`: Length of the share vector

### Dilithium

Standard CRYSTALS-Dilithium implementation.

```python
class Dilithium:
    def __init__(self, security_level: int = 3)
```

#### Methods

##### `keygen(seed: Optional[bytes] = None) -> DilithiumKeyPair`

Generate a Dilithium key pair.

**Parameters:**
- `seed`: Optional seed for deterministic key generation

**Returns:**
- `DilithiumKeyPair` object

##### `sign(message: bytes, private_key: DilithiumPrivateKey, randomness: Optional[bytes] = None) -> DilithiumSignature`

Sign a message using Dilithium.

**Parameters:**
- `message`: Message to sign
- `private_key`: Private key for signing
- `randomness`: Optional randomness for deterministic signing

**Returns:**
- `DilithiumSignature` object

##### `verify(message: bytes, signature: DilithiumSignature, public_key: DilithiumPublicKey) -> bool`

Verify a Dilithium signature.

**Parameters:**
- `message`: Original message
- `signature`: Signature to verify
- `public_key`: Public key for verification

**Returns:**
- `True` if signature is valid, `False` otherwise

### DilithiumKeyPair

Represents a Dilithium key pair.

```python
class DilithiumKeyPair:
    public_key: DilithiumPublicKey
    private_key: DilithiumPrivateKey
```

### DilithiumPublicKey

Dilithium public key.

```python
class DilithiumPublicKey:
    A: np.ndarray  # Public matrix
    t: PolynomialVector  # Public vector
    security_level: int
    params: dict
```

### DilithiumPrivateKey

Dilithium private key.

```python
class DilithiumPrivateKey:
    s1: PolynomialVector  # Secret vector s1
    s2: PolynomialVector  # Secret vector s2
    security_level: int
    params: dict
```

### DilithiumSignature

Dilithium signature.

```python
class DilithiumSignature:
    z: PolynomialVector  # Response vector
    h: PolynomialVector  # Hint vector
    c: Polynomial  # Challenge polynomial
```

## Polynomial Classes

### Polynomial

Represents a polynomial in Rq = Zq[X]/(X^256 + 1).

```python
class Polynomial:
    coeffs: np.ndarray  # Polynomial coefficients
```

#### Methods

##### `__init__(coeffs: Union[List[int], np.ndarray])`

Initialize polynomial with coefficients.

##### `__add__(other: 'Polynomial') -> 'Polynomial'`

Add two polynomials.

##### `__sub__(other: 'Polynomial') -> 'Polynomial'`

Subtract two polynomials.

##### `__mul__(other: Union['Polynomial', int]) -> 'Polynomial'`

Multiply polynomial by another polynomial or scalar.

##### `norm_infinity() -> int`

Compute infinity norm of polynomial.

##### `norm_l2() -> float`

Compute L2 norm of polynomial.

##### `is_zero() -> bool`

Check if polynomial is zero.

##### `degree() -> int`

Get degree of polynomial.

##### `copy() -> 'Polynomial'`

Create a copy of the polynomial.

##### Class Methods

##### `zero() -> 'Polynomial'`

Create zero polynomial.

##### `one() -> 'Polynomial'`

Create polynomial representing 1.

##### `random(bound: int = Q) -> 'Polynomial'`

Generate random polynomial.

### PolynomialVector

Represents a vector of polynomials.

```python
class PolynomialVector:
    polys: List[Polynomial]
    length: int
```

#### Methods

##### `__init__(polynomials: List[Polynomial])`

Initialize polynomial vector.

##### `__add__(other: 'PolynomialVector') -> 'PolynomialVector'`

Add two polynomial vectors.

##### `__sub__(other: 'PolynomialVector') -> 'PolynomialVector'`

Subtract two polynomial vectors.

##### `__mul__(scalar: int) -> 'PolynomialVector'`

Multiply vector by scalar.

##### `__getitem__(index: int) -> Polynomial`

Get polynomial at index.

##### `__setitem__(index: int, value: Polynomial)`

Set polynomial at index.

##### `norm_infinity() -> int`

Compute infinity norm of vector.

##### `copy() -> 'PolynomialVector'`

Create a copy of the vector.

##### Class Methods

##### `zero(length: int) -> 'PolynomialVector'`

Create zero vector of given length.

##### `random(length: int, bound: int = Q) -> 'PolynomialVector'`

Generate random polynomial vector.

## Constants

### Ring Parameters

```python
Q = 8380417  # Prime modulus for Zq
N = 256      # Polynomial degree
```

### Dilithium Parameters

```python
DILITHIUM_PARAMS = {
    2: {  # Security Level 2
        'k': 4, 'l': 4, 'eta': 2, 'tau': 39,
        'beta': 78, 'gamma1': 95232, 'gamma2': 261888, 'd': 13
    },
    3: {  # Security Level 3
        'k': 6, 'l': 5, 'eta': 4, 'tau': 49,
        'beta': 196, 'gamma1': 261888, 'gamma2': 261888, 'd': 13
    },
    5: {  # Security Level 5
        'k': 8, 'l': 7, 'eta': 2, 'tau': 60,
        'beta': 120, 'gamma1': 261888, 'gamma2': 261888, 'd': 13
    }
}
```

### Threshold Configurations

```python
THRESHOLD_CONFIGS = {
    '2_of_3': (2, 3),
    '3_of_5': (3, 5),
    '5_of_7': (5, 7),
    '7_of_10': (7, 10),
}
```

## Utility Functions

### `get_params(security_level: int) -> dict`

Get Dilithium parameters for specified security level.

### `validate_threshold_config(threshold: int, participants: int) -> bool`

Validate threshold signature configuration.

## Error Handling

### Common Exceptions

- `ValueError`: Invalid parameters or insufficient data
- `TypeError`: Incorrect data types
- `RuntimeError`: Algorithm failures or implementation errors

### Error Messages

The library provides descriptive error messages for common issues:

- Invalid threshold configurations
- Insufficient shares for reconstruction
- Invalid share formats
- Signature verification failures
- Key generation failures

## Usage Examples

### Complete Workflow

```python
from dilithium_threshold import ThresholdSignature
from dilithium_threshold.core.dilithium import Dilithium

# Initialize
ts = ThresholdSignature(3, 5, security_level=3)

# Generate keys
key_shares = ts.distributed_keygen()

# Sign message
message = b"Important message"
partial_sigs = []
for share in key_shares[:3]:  # Use 3 out of 5
    partial_sig = ts.partial_sign(message, share)
    partial_sigs.append(partial_sig)

# Combine signatures
signature = ts.combine_signatures(partial_sigs, key_shares[0].public_key)

# Verify
dilithium = Dilithium(3)
is_valid = dilithium.verify(message, signature, key_shares[0].public_key)
print(f"Signature valid: {is_valid}")
```

### Error Handling

```python
try:
    # Attempt to combine insufficient signatures
    insufficient_sigs = partial_sigs[:2]  # Only 2 out of 3 needed
    signature = ts.combine_signatures(insufficient_sigs, key_shares[0].public_key)
except ValueError as e:
    print(f"Error: {e}")  # "Need at least 3 partial signatures"
```

