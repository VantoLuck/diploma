#!/usr/bin/env python3
"""
Setup script for Dilithium Threshold Signature Scheme.

This package implements a post-quantum threshold signature scheme
based on the CRYSTALS-Dilithium algorithm with adapted Shamir
secret sharing for polynomial vectors.
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

# Get version from package
def get_version():
    version_file = os.path.join("src", "dilithium_threshold", "__init__.py")
    with open(version_file, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("__version__"):
                return line.split("=")[1].strip().strip('"').strip("'")
    return "1.0.0"

setup(
    name="dilithium-threshold-signature",
    version=get_version(),
    author="Leonid Kartushin",
    author_email="leonid.kartushin@example.com",
    description="Post-quantum threshold signature scheme based on CRYSTALS-Dilithium",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/dilithium-threshold-signature",
    project_urls={
        "Bug Tracker": "https://github.com/your-username/dilithium-threshold-signature/issues",
        "Documentation": "https://github.com/your-username/dilithium-threshold-signature/docs",
        "Source Code": "https://github.com/your-username/dilithium-threshold-signature",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
        "Topic :: Scientific/Engineering :: Mathematics",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.21.0",
        "cryptography>=3.4.8",
    ],
    extras_require={
        "dev": [
            "pytest>=6.2.0",
            "pytest-cov>=2.12.0",
            "black>=21.0.0",
            "flake8>=3.9.0",
            "mypy>=0.910",
        ],
        "docs": [
            "sphinx>=4.0.0",
            "sphinx-rtd-theme>=0.5.0",
        ],
        "benchmarks": [
            "matplotlib>=3.3.0",
            "pandas>=1.3.0",
            "seaborn>=0.11.0",
        ],
        "all": [
            "pytest>=6.2.0",
            "pytest-cov>=2.12.0",
            "black>=21.0.0",
            "flake8>=3.9.0",
            "mypy>=0.910",
            "sphinx>=4.0.0",
            "sphinx-rtd-theme>=0.5.0",
            "matplotlib>=3.3.0",
            "pandas>=1.3.0",
            "seaborn>=0.11.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "dilithium-threshold=dilithium_threshold.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=[
        "cryptography",
        "post-quantum",
        "threshold-signature",
        "dilithium",
        "lattice-cryptography",
        "shamir-secret-sharing",
        "distributed-cryptography",
    ],
)

