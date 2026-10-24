from setuptools import setup, find_packages

setup(
    name="shark-protocol",
    version="1.0.0",
    author="Prince Upadhyay",
    description="Fail-Closed, Proof-Carrying Epistemic Architecture & AgentOS",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=["numpy>=1.20.0", "scipy>=1.7.0"],
    entry_points={
        "console_scripts": ["shark-protocol=shark_protocol.cli:main"]
    }
)
