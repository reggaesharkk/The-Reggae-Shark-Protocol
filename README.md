[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23618033.svg)](https://doi.org/10.5281/zenodo.23618033)

# The Shark Protocol

**Verifiable, Proof-Carrying AI Execution OS & Security Gateway** governed by **4D ODE Dynamics**, **Lean 4 Formal Theorems**, and **Low-Rank Spectral Context Compression**.

Developed by **Prince Upadhyay** (Independent Researcher, India).

---

## Executive Summary

As autonomous AI agents acquire tool-calling capabilities and direct access to external infrastructure, traditional empirical safeguards fail under edge cases. **The Shark Protocol** is a proof-carrying epistemic operating system and security proxy that enforces mathematical and cryptographic boundaries on agent execution.

### Key Architectural Pillars:
* **Layer 1: VRK Cryptographic Claim Shell (v0.3.1):** Enforces an append-only SHA-256 ledger schema (`intentseal-vrk-claim-v2`).
* **Layer 2: 4D ODE Cognitive Dynamics Governor:** Controls agent state trajectory in continuous phase space. Backed by **17 machine-checked zero-sorry theorems** in Lean 4 (`lean/ExistenceVerification.lean`).
* **Layer 3: Low-Rank Spectral Context Memory (LRSC):** Compresses context memory down to a **1/9th spectral footprint** with zero relative reconstruction error, verified across 13.43 billion subsets.
* **Layer 4: Multi-Cloud Security Gateway Proxy:** Live local HTTP server (`http://localhost:8000`) providing zero-downtime proxy failover across **4 major LLM providers**: **Groq**, **Together AI**, **Google Gemini**, and **Hugging Face**.

---

## Multi-Cloud API Gateway Configuration (4 Backends)

The protocol integrates four primary LLM API backends. Configure your keys in a `.env` file in the project root:

```ini
GROQ_API_KEY=your_key_here
TOGETHER_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here
HUGGINGFACE_API_KEY=your_key_here
```

### Supported API Providers & Target Models:
1. **Groq API:** `llama-3.3-70b-versatile` — Low latency agent execution.
2. **Together AI:** `meta-llama/Llama-3.3-70B-Instruct-Turbo` — High-throughput agent reasoning.
3. **Google Gemini:** `gemini-1.5-flash` — Multimodal contextual synthesis.
4. **Hugging Face API:** `mistralai/Mistral-7B-Instruct-v0.2` — Open-weights fallback provider.

---

## Quickstart & Installation

```bash
git clone https://github.com/reggaesharkk/The-Reggae-Shark-Protocol.git
cd The-Reggae-Shark-Protocol
pip install .
shark-protocol --cli
```

### Launch Streamlit Dashboard:
```bash
streamlit run shark_protocol/dashboard.py
```

---

## Technical Specification & Formal Proofs

* **LaTeX Source Code:** `paper/specification.tex`
* **Compiled PDF Report:** `paper/specification.pdf`
* **Lean 4 Proofs:** `lean/ExistenceVerification.lean`

---

## Citation & License

Licensed under the **MIT License**.


