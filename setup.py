from setuptools import setup, find_packages

setup(
    name="shark_protocol",
    version="1.0.2",
    packages=find_packages(),
    install_requires=[
        "numpy",
        "scipy",
        "requests",
        "streamlit",
        "plotly"
    ],
    entry_points={
        "console_scripts": [
            "shark-protocol=shark_protocol.cli:main",
        ],
    },
)
