from setuptools import setup, find_packages

setup(
    name="shark_protocol",
    version="1.3.1",
    description="Formal Verification (41 Lean 4 Theorems), 200-Bit mpmath.iv Patankar-Euler & WP19 Duhamel Interval Certificates, Multi-Principal Subprocess Ed25519 Signer, and Multi-Cloud AI Gateway",
    author="Prince Upadhyay",
    author_email="starxshark@gmail.com",
    url="https://github.com/reggaesharkk/The-Reggae-Shark-Protocol",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "numpy>=1.24.0,<3.0.0",
        "scipy>=1.10.0,<2.0.0",
        "mpmath>=1.3.0,<2.0.0",
        "requests>=2.31.0,<3.0.0",
        "python-dotenv>=1.0.0,<2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "shark-protocol=shark_protocol.cli:main",
        ],
    },
    python_requires=">=3.10",
)
