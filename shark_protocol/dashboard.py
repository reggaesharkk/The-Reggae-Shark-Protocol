"""
Streamlit 4D ODE & VRK Telemetry Dashboard (`shark_protocol/dashboard.py`)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Canonical DOI: 10.5281/zenodo.23620074
"""

from __future__ import annotations

from typing import Any, Dict

from .gateway import MultiProviderGateway


def generate_dashboard_telemetry(
    prompt: str = "Autopoietic 4D soft-wall trajectory & LRSC 11/99 audit",
    P_0: float = 4.0,
    duration: float = 15.0,
    dt: float = 0.05,
) -> Dict[str, Any]:
    """Compute real 4D ODE trajectory, Patankar interval enclosure, LRSC 11/99 witness, and VRK seal."""
    gw = MultiProviderGateway()
    gw.engine.P_0 = float(P_0)
    traj = gw.engine.simulate_trajectory(duration=duration, dt=dt, P_0=P_0)
    interval_step = gw.engine.step_ode_patankar_interval(dt=dt, P_0=P_0)
    exec_res = gw.process_request(prompt=prompt, provider="groq")
    ok, chain_status = gw.engine.verify_ledger_integrity()
    return {
        "trajectory": traj,
        "patankar_interval": interval_step,
        "execution": exec_res,
        "vrk_chain_ok": ok,
        "vrk_chain_status": chain_status,
    }


def run_streamlit_app() -> None:
    import streamlit as st
    import pandas as pd

    st.set_page_config(page_title="The Shark Protocol v1.1.2 Dashboard", layout="wide")
    st.title("The Reggae Shark Protocol (v1.1.2) — 4D ODE, Patankar Interval & VRK Ledger")
    st.caption("Canonical Zenodo DOI: 10.5281/zenodo.23620074 | Code: MIT | Specification: CC BY 4.0")

    p0_val = st.sidebar.slider("Basal Sensory Drive (P_0)", 0.0, 6.0, 4.0, 0.1)
    dur_val = st.sidebar.slider("Simulation Horizon (s)", 5.0, 40.0, 15.0, 1.0)
    prompt_val = st.text_input("Gateway Prompt", "Verify 4D soft-wall ODE and LRSC 11/99 spectral witness")

    telemetry = generate_dashboard_telemetry(prompt=prompt_val, P_0=p0_val, duration=dur_val)
    df = pd.DataFrame({
        "gamma": telemetry["trajectory"]["gamma"],
        "H_obs": telemetry["trajectory"]["H_obs"],
        "I_dot": telemetry["trajectory"]["I_dot"],
        "Psi": telemetry["trajectory"]["Psi"],
    }, index=telemetry["trajectory"]["t"])
    st.subheader("Layer 2: 4D Soft-Wall ODE Trajectory in B_4")
    st.line_chart(df)
    st.subheader("Layer 1 & 3: VRK Seal & LRSC 11/99 Spectral Witness")
    st.json({
        "vrk_chain_status": telemetry["vrk_chain_status"],
        "patankar_interval_width": telemetry["patankar_interval"]["max_interval_width"],
        "lrsc": telemetry["execution"]["lrsc"],
        "vrk_seal": telemetry["execution"]["vrk_seal"],
    })


if __name__ == "__main__":
    run_streamlit_app()
