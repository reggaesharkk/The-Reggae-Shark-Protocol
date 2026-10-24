import sys
from .gateway import MultiProviderGateway

def main():
    gw = MultiProviderGateway()
    print("SharkGateway v1.0.2 initialized")
    res = gw.process_request("gemini", "CLI Test Prompt")
    print(res)

if __name__ == "__main__":
    main()
