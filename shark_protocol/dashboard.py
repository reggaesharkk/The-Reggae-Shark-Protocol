import streamlit as st
import numpy as np
import matplotlib.pyplot as plt
from shark_protocol.kernel import SharkProtocolEngine
from shark_protocol.gateway import MultiProviderGateway

st.set_page_config(
    page_title="The Shark Protocol Dashboard",
    page_icon="🦈",
    layout="wide"
)

st.title("🦈 The Shark Protocol: Live Security & Governor Dashboard")
st.caption("Developed by Prince Upadhyay (@reggaesharkk) | Lean 4 Verified AgentOS")

st.sidebar.header("API Provider Settings")
groq_key = st.sidebar.text_input("Groq API Key", type="password")
together_key = st.sidebar.text_input("Together AI API Key", type="password")
gemini_key = st.sidebar.text_input("Gemini API Key", type="password")
hf_key = st.sidebar.text_input("HuggingFace API Key", type="password")

keys = {}
if groq_key: keys["groq"] = groq_key
if together_key: keys["together"] = together_key
if gemini_key: keys["gemini"] = gemini_key
if hf_key: keys["huggingface"] = hf_key

gateway = MultiProviderGateway(keys=keys)

tab1, tab2, tab3 = st.tabs(["🚀 Live Gateway Proxy", "📈 4D Governor ODE Dynamics", "📜 Cryptographic Ledger"])

with tab1:
    st.subheader("Test Proof-Carrying Prompt Execution")
    col1, col2 = st.columns([3, 1])
    
    with col1:
        prompt = st.text_area("User Prompt", "Analyze 4D stability bounds of ODE Governor under zero drive")
    with col2:
        provider = st.selectbox("Provider", ["groq", "together", "gemini", "huggingface"])
        evidence = st.selectbox("Evidence Class", ["PROVED", "CERTIFIED", "SIMULATED", "DIAGNOSTIC", "INVALID_MUTATION"])
    
    if st.button("Submit Verified Request"):
        res = gateway.dispatch_request(prompt=prompt, provider=provider, evidence_class=evidence)
        if res["status"] == "200_OK":
            st.success("Request Sealed and Verified Successfully!")
            st.json(res)
        else:
            st.error("FAIL-CLOSED REJECTION TRIGGERED!")
            st.json(res)

with tab2:
    st.subheader("4D ODE Trapping Box Trajectory Simulation")
    p0_val = st.slider("Task Drive P0", 0.0, 5.0, 0.0, 0.1)
    
    engine = SharkProtocolEngine()
    sol = engine.simulate_4d_governor(t_span=(0, 50), P0=p0_val)
    
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(sol.t, sol.y[0], label=r'Context Decay $\gamma(t)$', color='#1f77b4', linewidth=2)
    ax.plot(sol.t, sol.y[1], label=r'Entropy {\mathrm{obs}}(t)$', color='#ff7f0e', linewidth=2)
    ax.plot(sol.t, sol.y[2], label=r'Processing Rate $\dot{I}(t)$', color='#2ca02c', linewidth=2)
    ax.plot(sol.t, sol.y[3], label=r'Self-Modeling Readout $\Psi(t)$', color='#d62728', linewidth=2.5)
    ax.axhline(0.0, color='black', linestyle='--', alpha=0.5)
    ax.axhline(1.0, color='gray', linestyle=':', alpha=0.5)
    ax.set_title(f"4D Trapping Box Trajectory (Drive P0 = {p0_val})", fontweight='bold')
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Magnitude")
    ax.legend(loc='upper right')
    ax.grid(True, alpha=0.3)
    
    st.pyplot(fig)

with tab3:
    st.subheader("Append-Only Cryptographic Trust Ledger")
    st.write(f"**Trust Root Hash:** ")
    st.dataframe(gateway.engine.ledger)
