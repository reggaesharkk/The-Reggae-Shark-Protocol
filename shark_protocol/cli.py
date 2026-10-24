import sys
import argparse
from .gateway import MultiProviderGateway

def main():
    parser = argparse.ArgumentParser(description="The Shark Protocol CLI & Gateway")
    parser.add_argument("--server", action="store_true", help="Start HTTP proxy server")
    parser.add_argument("--cli", action="store_true", help="Start interactive CLI proxy")
    args = parser.parse_args()

    gateway = MultiProviderGateway()
    gateway.prompt_keys_interactively()

if __name__ == "__main__":
    main()
