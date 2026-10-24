"""
Streamlit Interactive Security & 4D Cognitive ODE Dashboard for The Shark Protocol (v1.1.0).
Integrates the real 4D Soft-Wall ODE trajectory (`SharkProtocolEngine.simulate_trajectory`),
live LRSC 11/99 spectral compression readouts, and VRK v0.3.1 hash-chain verification.
"""

import streamlit as st
import plotly.graph_objects as go
from shark_protocol.gateway import MultiProviderGateway

st.set_page_config(page_title="The Shark Protocol Dashboard v1.1.0", layout="wide")
st.title("🛡️ The Shark Protocol Security Gateway v1.1.0")
st.markdown(
    "**Verifiable, Proof-Carrying AI Execution OS** governed by **VRK v0.3.1 Hash-Chaining**, "
    "**Typestate Epoch Isolation (`php2shell` Immunity)**, **4D Soft-Wall ODE Dynamics (`B_4`)**, "
    "and **LRSC `11/99` Spectral Context Compression**."
)

if "gateway" not in st.session_state:
    st.session_state.gateway = MultiProviderGateway()

gw: MultiProviderGateway = st.session_state.gateway

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("🌐 Multi-Cloud LLM Provider & Typestate Gate")
    provider = st.selectbox("Select Active Provider", ["Groq", "Together AI", "Google Gemini", "Hugging Face"])
    prompt = st.text_area("Prompt Input", "Execute verified autonomous agent transaction under 4D soft-wall ODE bounds...")
    sim_oom = st.checkbox("Simulate OOM Interrupt in PARTIAL_INIT (Test CVE-2026-109618 Defense)", value=False)

    if st.button("Run Verified Prompt"):
        try:
            res = gw.process_request(provider, prompt, simulate_oom=sim_oom)
            st.success(f"Status: {res['status']} | Mode: {res['dispatch_mode']} | Epoch: {res['worker_epoch']} ({res['typestate_final']})")
            st.info(f"Layer 1 (VRK): {res['layer1_vrk']}")
            st.markdown("**Layer 2 (4D Soft-Wall ODE State in $\mathcal{B}_4$):**")
            st.json(res["layer2_governor"])
            st.markdown("**Layer 3 (LRSC $M=99 \to K=11$ Spectral Compression):**")
            st.json({
                "footprint": res["layer3_lrsc"]["footprint_fraction"],
                "relative_l2_error": res["layer3_lrsc"]["relative_l2_error"],
                "spectral_digest": res["layer3_lrsc"]["spectral_digest"],
            })
            st.code(res["output"])
        except Exception as exc:
            st.error(f"FAIL-CLOSED REJECTION: {exc}")

with col2:
    st.subheader("📈 Real-Time 4D Soft-Wall ODE Trajectory (Eqs. B.1–B.4)")
    traj = gw.engine.simulate_trajectory(total_time=80.0, sample_points=320)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=traj["t"], y=traj["gamma"], mode="lines", name="γ(t) Reconstruction [0, 10]"))
    fig.add_trace(go.Scatter(x=traj["t"], y=[h / 10.0 for h in traj["H_obs"]], mode="lines", name="0.1 × H_obs(t) Entropy [scaled]"))
    fig.add_trace(go.Scatter(x=traj["t"], y=traj["I_dot"], mode="lines", name="İ(t) Processing Rate"))
    fig.add_trace(go.Scatter(x=traj["t"], y=[p * 10.0 for p in traj["Psi"]], mode="lines", name="10 × Ψ(t) Self-Modeling Readout"))
    fig.update_layout(
        height=420,
        margin=dict(l=20, r=20, t=30, b=20),
        xaxis_title="Time t (s)",
        yaxis_title="Bounded State Magnitude inside B_4",
    )
    st.plotly_chart(fig, use_container_width=True)
