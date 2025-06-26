# Theoretical Foundations

## Mathematical Background

### Ring Structure

The Dilithium algorithm operates in the ring:

```
Rq = Zq[X]/(X^256 + 1)
```

where:
- `q = 8380417` (prime modulus)
- `n = 256` (polynomial degree)

Elements in this ring are polynomials of degree at most 255 with coefficients in Zq.

### Polynomial Arithmetic

#### Addition
For polynomials `f(x) = Σ fi·x^i` and `g(x) = Σ gi·x^i`:
```
(f + g)(x) = Σ (fi + gi mod q)·x^i
```

#### Multiplication
Polynomial multiplication is performed modulo `X^256 + 1`:
```
X^256 ≡ -1 (mod X^256 + 1)
```

This means `X^(256+k) ≡ -X^k`, which is efficiently computed using Number Theoretic Transform (NTT).

### Dilithium Algorithm

#### Key Generation
1. Sample matrix `A ∈ Rq^(k×l)` uniformly at random
2. Sample secret vectors `s1 ∈ Rq^l` and `s2 ∈ Rq^k` from small coefficient distribution
3. Compute `t = A·s1 + s2`
4. Public key: `(A, t1)` where `t1` is high-order bits of `t`
5. Private key: `(s1, s2)`

#### Signing
1. Sample mask vector `y ∈ Rq^l` from uniform distribution
2. Compute `w = A·y`
3. Generate challenge `c ∈ Rq` from message and `w1` (high bits of `w`)
4. Compute response `z = y + c·s1`
5. Check bounds and compute hint `h`
6. Signature: `(z, h, c)`

#### Verification
1. Recompute `w' = A·z - c·t·2^d`
2. Use hint `h` to recover high-order bits `w1'`
3. Recompute challenge `c'` from message and `w1'`
4. Accept if `c = c'`

## Threshold Adaptation

### Problem Statement

Traditional threshold schemes require reconstructing the secret key during signing, which creates a security vulnerability. Our approach eliminates this requirement.

### Adapted Shamir Secret Sharing

#### Classical Shamir Scheme
For a secret `s` and threshold `t`:
1. Create polynomial `P(x) = s + a1·x + ... + at-1·x^(t-1)`
2. Distribute shares `(i, P(i))` for `i = 1, ..., n`
3. Reconstruct using Lagrange interpolation

#### Adaptation for Polynomial Vectors

For a polynomial vector `s = (s1, s2, ..., sl)` where each `si ∈ Rq`:

1. **Coefficient-wise sharing**: For each polynomial `si(x) = Σ si,j·x^j`:
   - Apply Shamir sharing to each coefficient `si,j` independently
   - Create polynomial `Pi,j(x) = si,j + ai,j,1·x + ... + ai,j,t-1·x^(t-1)`

2. **Share organization**: Participant `u` receives:
   ```
   share_u = {Pi,j(u) | ∀i ∈ [1,l], ∀j ∈ [0,255]}
   ```

3. **Structured reconstruction**: Reconstruct specific coefficients without full secret recovery

### Threshold Signing Protocol

#### Partial Signature Generation
Each participant `u` with share `share_u`:

1. Sample partial mask `yu`
2. Compute partial commitment `wu = A·yu`
3. Generate challenge `c` (coordinated among participants)
4. Compute partial response `zu = yu + c·share_u`
5. Output partial signature `(zu, wu, c)`

#### Signature Combination
Given `t` partial signatures `{(zu, wu, c)}`:

1. **Reconstruct response**: Use Lagrange interpolation to compute:
   ```
   z = Σ λu·zu
   ```
   where `λu` are Lagrange coefficients

2. **Compute hint**: Derive hint `h` from partial commitments

3. **Output signature**: `(z, h, c)`

### Security Analysis

#### Threshold Security
- **Unforgeability**: Requires at least `t` participants to forge
- **Privacy**: Individual shares reveal no information about secret
- **Robustness**: Tolerates up to `n-t` corrupted participants

#### Post-Quantum Security
- **Lattice hardness**: Based on LWE problem hardness
- **Quantum resistance**: No known quantum algorithms break LWE efficiently
- **Parameter security**: Follows NIST security level recommendations

#### No Secret Leakage
- **Key insight**: Never reconstruct full secret vectors `s1, s2`
- **Partial reconstruction**: Only reconstruct specific polynomial coefficients as needed
- **Information-theoretic security**: Shares are perfectly secret

## Implementation Considerations

### Efficiency Optimizations

#### Number Theoretic Transform (NTT)
- Fast polynomial multiplication in `O(n log n)` time
- Primitive root of unity: `ζ = 1753`
- Forward/inverse NTT for efficient ring operations

#### Coefficient Packing
- Store polynomial coefficients in contiguous arrays
- Vectorized operations using NumPy
- Memory-efficient share representation

#### Lagrange Interpolation
- Precompute interpolation coefficients
- Modular arithmetic optimizations
- Batch processing for multiple coefficients

### Security Implementation

#### Constant-Time Operations
- Avoid timing side-channels in critical operations
- Use constant-time modular arithmetic
- Secure random number generation

#### Input Validation
- Verify share consistency and bounds
- Check polynomial coefficient ranges
- Validate threshold parameters

#### Error Handling
- Graceful failure for insufficient shares
- Secure cleanup of sensitive data
- Comprehensive error reporting

## Comparison with Existing Schemes

### Classical Threshold Signatures

| Property | RSA-TSS | ECDSA-TSS | Our Scheme |
|----------|---------|-----------|------------|
| Post-quantum | ❌ | ❌ | ✅ |
| No secret reconstruction | ❌ | ❌ | ✅ |
| Standard compatibility | ✅ | ✅ | ✅ |
| Efficiency | Medium | High | High |

### Post-Quantum Alternatives

| Scheme | Base Algorithm | Secret Leakage | Performance |
|--------|----------------|----------------|-------------|
| Falcon-TSS | Falcon | Yes | Fast |
| SPHINCS+-TSS | SPHINCS+ | No | Slow |
| Our Scheme | Dilithium | No | Fast |

## Future Research Directions

### Optimizations
- Advanced NTT implementations
- Parallel signature generation
- Hardware acceleration support

### Extensions
- Proactive secret sharing
- Verifiable secret sharing
- Multi-signature schemes

### Applications
- Blockchain integration
- PKI infrastructure
- Secure multi-party computation

