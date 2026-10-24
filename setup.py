from setuptools import setup, find_packages

setup(
    name="shark_protocol",
    version="1.1.0",
    description="Verifiable, Proof-Carrying AI Execution OS & Security Gateway governed by VRK v0.3.1, Typestate Epoch Isolation, 4D Soft-Wall ODEs, and LRSC 11/99 Spectral Compression",
    author="Prince Upadhyay",
    author_email="starxshark@gmail.com",
    url="https://github.com/reggaesharkk/The-Reggae-Shark-Protocol",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "numpy>=1.26.0",
        "scipy>=1.11.0",
        "requests>=2.31.0",
        "streamlit>=1.30.0",
        "plotly>=5.18.0",
    ],
    entry_points={
        "console_scripts": [
            "shark-protocol=shark_protocol.cli:main",
        ],
    },
)
