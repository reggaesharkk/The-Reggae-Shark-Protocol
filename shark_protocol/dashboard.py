"""
Streamlit 4D ODE & VRK Telemetry Dashboard (`shark_protocol/dashboard.py`)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Version: 1.3.2 (Concept DOI: 10.5281/zenodo.23618032)
"""

from __future__ import annotations

from typing import Any, Dict

from . import __concept_doi__, __version__
from .gateway import MultiProviderGateway


def generate_dashboard_telemetry(
    prompt: str = "Autopoietic 4D soft-wall trajectory & LRSC 11/99 verification",
    P_0: float = 4.0,
    duration: float = 15.0,
    dt: float = 0.05,
) -> Dict[str, Any]:
    """Compute 4D ODE trajectory, float64 Patankar check, 200-bit mpmath.iv interval certificate, LRSC 11/99 witness, and Ed25519-signed VRK seal."""
    gw = MultiProviderGateway()
    gw.engine.P_0 = float(P_0)
    exec_bundle = gw.process_request(prompt=prompt, provider="groq")
    traj = gw.engine.simulate_trajectory(duration=duration, dt=dt, P_0=P_0)
    patankar = gw.engine.step_ode_patankar_interval(dt=dt, P_0=P_0)
    patankar_mp = gw.engine.step_ode_patankar_mp_interval(dt=dt, P_0=P_0)
    ok, msg = gw.engine.verify_ledger_integrity()
    return {
        "execution": exec_bundle,
        "trajectory": traj,
        "patankar_interval": patankar,
        "patankar_mp_interval": patankar_mp,
        "vrk_verified": ok,
        "vrk_message": msg,
    }


def render_streamlit_dashboard() -> None:
    """Render interactive Streamlit telemetry view if `streamlit` is installed."""
    import streamlit as st  # type: ignore

    st.set_page_config(page_title=f"The Reggae Shark Protocol v{__version__} Telemetry", layout="wide")
    st.title(f"The Reggae Shark Protocol (v{__version__})")
    st.caption(f"Concept DOI: {__concept_doi__} | Code & 42 Lean 4 Proofs: MIT | Specification: CC BY 4.0")

    p0_val = st.slider("Basal Sensory Drive (P_0)", min_value=0.0, max_value=6.0, value=4.0, step=0.1)
    prompt_val = st.text_input("Gateway Prompt", value="Verify 4D Soft-Wall ODE & LRSC 11/99 Spectral Witness")
    data = generate_dashboard_telemetry(prompt=prompt_val, P_0=p0_val, duration=15.0, dt=0.05)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("VRK Chain Status", data["vrk_message"])
    col2.metric("Worker Epoch", str(data["execution"]["worker_epoch"]))
    col3.metric("LRSC Witness Ratio", data["execution"]["lrsc"]["compression_ratio_exact"])
    box_label = (
        "Checked (float64) / Certified (200-bit mp.iv)"
        if (data["patankar_interval"]["inside_B4_checked"] and data["patankar_mp_interval"]["inside_B4_mp_iv_certified"])
        else ("Checked (float64)" if data["patankar_interval"]["inside_B4_checked"] else "Failed")
    )
    col4.metric("Patankar Box B_4", box_label)
    st.json(data["execution"]["vrk_seal"])


if __name__ == "__main__":
    print(generate_dashboard_telemetry()["vrk_message"])
