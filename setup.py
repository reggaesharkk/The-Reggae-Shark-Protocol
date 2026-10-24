from setuptools import setup, find_packages

setup(
    name="shark_protocol",
    version="1.1.2",
    description="Formal Verification, 4D Soft-Wall ODE Governor, LRSC 11/99 Spectral Compression, and Merkle-DAG Provenance Kernel",
    author="Prince Upadhyay",
    author_email="starxshark@gmail.com",
    url="https://github.com/reggaesharkk/The-Reggae-Shark-Protocol",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "numpy>=1.24.0",
        "scipy>=1.10.0",
        "requests>=2.31.0",
        "python-dotenv>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "shark-protocol=shark_protocol.cli:main",
        ],
    },
    python_requires=">=3.10",
)
