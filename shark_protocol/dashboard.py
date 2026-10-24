import streamlit as st
import plotly.graph_objects as go
import numpy as np
from shark_protocol.gateway import MultiProviderGateway

st.set_page_config(page_title="The Shark Protocol Dashboard", layout="wide")
st.title("🛡️ The Shark Protocol Security Gateway v1.0.3")
st.markdown("Verifiable, Proof-Carrying AI Execution OS Governed by 4D ODE Dynamics & VRK Proofs")

gw = MultiProviderGateway()

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("🌐 Multi-Cloud LLM Provider Test")
    provider = st.selectbox("Select Active Provider", ["Groq", "Together AI", "Google Gemini", "Hugging Face"])
    prompt = st.text_area("Prompt Input", "Execute secure agent transaction...")
    if st.button("Run Verified Prompt"):
        res = gw.process_request(provider, prompt)
        st.success(f"Status: {res['status']}")
        st.info(f"VRK Proof: {res['layer1_vrk']}")
        st.json(res['layer2_governor'])
        st.code(res['output'])

with col2:
    st.subheader("📈 Real-Time 4D Cognitive ODE Monitor")
    t = np.linspace(0, 10, 100)
    gamma = 3.0 + 0.5 * np.sin(t)
    psi = 0.98 - 0.05 * np.exp(-0.2 * t)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=t, y=gamma, mode='lines', name='Gamma (Decay Floor)'))
    fig.add_trace(go.Scatter(x=t, y=psi, mode='lines', name='Psi (Lucid Readout)'))
    fig.update_layout(height=350, margin=dict(l=20, r=20, t=30, b=20))
    st.plotly_chart(fig, use_container_width=True)
