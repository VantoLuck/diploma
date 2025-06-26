# Contributing to Dilithium Threshold Signature

Thank you for your interest in contributing to the Dilithium Threshold Signature project! This document provides guidelines for contributing to this research implementation.

## 🎯 Project Goals

This project implements a post-quantum threshold signature scheme based on CRYSTALS-Dilithium with the following objectives:

- Provide a secure threshold signature without secret reconstruction
- Maintain compatibility with NIST Dilithium standard
- Achieve practical performance for real-world deployment
- Serve as a reference implementation for research and education

## 🤝 How to Contribute

### Types of Contributions

We welcome various types of contributions:

- **Bug reports** and **bug fixes**
- **Performance improvements** and **optimizations**
- **Documentation** improvements
- **Test coverage** enhancements
- **New features** (please discuss first)
- **Research** and **analysis**

### Getting Started

1. **Fork the repository**
   ```bash
   git clone https://github.com/your-username/dilithium-threshold-signature.git
   cd dilithium-threshold-signature
   ```

2. **Set up development environment**
   ```bash
   pip install -r requirements.txt
   pip install -e ".[dev]"
   ```

3. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

4. **Run tests to ensure everything works**
   ```bash
   python -m pytest tests/ -v
   ```

## 📝 Development Guidelines

### Code Style

We follow Python best practices and use automated tools:

- **Black** for code formatting
- **Flake8** for linting
- **MyPy** for type checking
- **isort** for import sorting

Run formatting before committing:
```bash
black src/ tests/ examples/
flake8 src/ tests/ examples/
mypy src/
isort src/ tests/ examples/
```

### Code Structure

```
src/dilithium_threshold/
├── core/           # Core algorithms
├── crypto/         # Cryptographic primitives
├── utils/          # Utility functions
└── protocols/      # Protocol implementations
```

### Naming Conventions

- **Classes**: PascalCase (`ThresholdSignature`)
- **Functions/Methods**: snake_case (`partial_sign`)
- **Constants**: UPPER_SNAKE_CASE (`DEFAULT_SECURITY_LEVEL`)
- **Variables**: snake_case (`key_shares`)

### Documentation

- Use **docstrings** for all public functions and classes
- Follow **Google style** docstring format
- Include **type hints** for all function parameters and returns
- Add **examples** in docstrings for complex functions

Example:
```python
def partial_sign(self, message: bytes, key_share: ThresholdKeyShare,
                randomness: Optional[bytes] = None) -> PartialSignature:
    """
    Create a partial signature using a key share.
    
    Args:
        message: Message to sign
        key_share: Participant's key share
        randomness: Optional randomness for deterministic signing
        
    Returns:
        Partial signature from this participant
        
    Raises:
        ValueError: If key share is invalid
        
    Example:
        >>> ts = ThresholdSignature(3, 5)
        >>> key_shares = ts.distributed_keygen()
        >>> message = b"Hello, world!"
        >>> partial_sig = ts.partial_sign(message, key_shares[0])
    """
```

## 🧪 Testing Guidelines

### Test Structure

```
tests/
├── test_polynomials.py     # Polynomial operations
├── test_shamir.py          # Shamir secret sharing
├── test_dilithium.py       # Dilithium algorithm
├── test_threshold.py       # Threshold signatures
└── test_integration.py     # Integration tests
```

### Writing Tests

- Use **pytest** framework
- Write **unit tests** for individual components
- Write **integration tests** for complete workflows
- Include **edge cases** and **error conditions**
- Aim for **high test coverage** (>90%)

Example test:
```python
def test_threshold_signing():
    """Test complete threshold signing workflow."""
    ts = ThresholdSignature(3, 5, security_level=2)
    key_shares = ts.distributed_keygen()
    message = b"Test message"
    
    # Create partial signatures
    partial_sigs = []
    for share in key_shares[:3]:
        partial_sig = ts.partial_sign(message, share)
        partial_sigs.append(partial_sig)
    
    # Combine and verify
    signature = ts.combine_signatures(partial_sigs, key_shares[0].public_key)
    
    dilithium = Dilithium(2)
    assert dilithium.verify(message, signature, key_shares[0].public_key)
```

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src/dilithium_threshold --cov-report=html

# Run specific test file
python -m pytest tests/test_threshold.py -v

# Run specific test
python -m pytest tests/test_threshold.py::test_threshold_signing -v
```

## 🔒 Security Considerations

### Cryptographic Code

- **Never** implement cryptographic primitives from scratch without expertise
- **Always** use constant-time operations for sensitive computations
- **Validate** all inputs and parameters
- **Handle** errors securely (no information leakage)
- **Use** secure random number generation

### Code Review

All cryptographic code changes require:
- **Thorough review** by maintainers
- **Security analysis** documentation
- **Test coverage** for security properties
- **Performance benchmarks**

## 📊 Performance Guidelines

### Optimization Priorities

1. **Correctness** first - never sacrifice security for performance
2. **Algorithmic** improvements over micro-optimizations
3. **Memory** efficiency for large-scale deployments
4. **Parallelization** opportunities

### Benchmarking

Include benchmarks for significant changes:
```python
def benchmark_threshold_signing():
    """Benchmark threshold signing performance."""
    ts = ThresholdSignature(3, 5, security_level=2)
    
    # Benchmark key generation
    start = time.time()
    key_shares = ts.distributed_keygen()
    keygen_time = time.time() - start
    
    # ... benchmark other operations
    
    print(f"Key generation: {keygen_time:.3f}s")
```

## 📋 Pull Request Process

### Before Submitting

1. **Create** a feature branch from `main`
2. **Write** tests for your changes
3. **Run** the full test suite
4. **Update** documentation if needed
5. **Add** entry to CHANGELOG.md
6. **Ensure** code follows style guidelines

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Performance improvement
- [ ] Documentation update
- [ ] Test improvement

## Testing
- [ ] All tests pass
- [ ] New tests added for changes
- [ ] Manual testing performed

## Security Impact
- [ ] No security implications
- [ ] Security review required
- [ ] Cryptographic changes made

## Performance Impact
- [ ] No performance impact
- [ ] Performance improved
- [ ] Benchmarks included
```

### Review Process

1. **Automated checks** must pass (tests, linting, etc.)
2. **Code review** by at least one maintainer
3. **Security review** for cryptographic changes
4. **Performance review** for optimization changes
5. **Documentation review** for API changes

## 🐛 Bug Reports

### Before Reporting

1. **Search** existing issues
2. **Update** to latest version
3. **Reproduce** the bug
4. **Minimize** test case

### Bug Report Template

```markdown
## Bug Description
Clear description of the bug

## Steps to Reproduce
1. Step one
2. Step two
3. ...

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- Python version:
- OS:
- Package version:

## Additional Context
Any other relevant information
```

## 💡 Feature Requests

### Before Requesting

1. **Check** if feature already exists
2. **Search** existing feature requests
3. **Consider** if it fits project scope
4. **Think** about implementation approach

### Feature Request Template

```markdown
## Feature Description
Clear description of the proposed feature

## Use Case
Why is this feature needed?

## Proposed Solution
How should this feature work?

## Alternatives Considered
Other approaches you've considered

## Additional Context
Any other relevant information
```

## 📚 Research Contributions

### Academic Contributions

We welcome research contributions:
- **Theoretical analysis** of security properties
- **Performance optimizations** with mathematical justification
- **New threshold configurations** or protocols
- **Formal verification** of implementations
- **Cryptanalysis** and security assessments

### Research Guidelines

1. **Cite** relevant literature
2. **Provide** mathematical proofs when applicable
3. **Include** experimental validation
4. **Document** assumptions and limitations
5. **Consider** practical implications

## 🏆 Recognition

Contributors will be recognized in:
- **CONTRIBUTORS.md** file
- **Release notes** for significant contributions
- **Academic papers** for research contributions
- **Project documentation**

## 📞 Getting Help

- **GitHub Issues** for bugs and feature requests
- **GitHub Discussions** for questions and ideas
- **Email** maintainers for security issues
- **Documentation** for usage questions

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🙏 Code of Conduct

This project follows a code of conduct based on respect, inclusivity, and collaboration. Please be:

- **Respectful** in all interactions
- **Constructive** in feedback and criticism
- **Inclusive** of different perspectives and backgrounds
- **Professional** in all communications

Thank you for contributing to post-quantum cryptography research! 🚀

