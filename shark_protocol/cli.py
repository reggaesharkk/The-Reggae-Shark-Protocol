import sys
from .gateway import MultiProviderGateway

def main():
    gw = MultiProviderGateway()
    print("=== The Shark Protocol Security Gateway v1.0.3 ===")
    print("Active Backends: Groq | Together AI | Google Gemini | Hugging Face
")
    res = gw.process_request("groq", "Security audit prompt")
    print("Status:", res["status"])
    print("Provider:", res["provider"], "(Model:", res["target_model"] + ")")
    print("VRK Proof:", res["layer1_vrk"])
    print("4D Governor State:", res["layer2_governor"])
    print("Response:", res["output"])

if __name__ == "__main__":
    main()
