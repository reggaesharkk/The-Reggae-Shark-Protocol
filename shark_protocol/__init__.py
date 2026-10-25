"""
The Reggae Shark Protocol (v1.2.0 — Zenodo v4 Final Edition)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Lineage DOIs: Supersedes v3 (10.5281/zenodo.23624605), v2 (10.5281/zenodo.23620074), and v1.0.3 (10.5281/zenodo.23618033)
License: MIT (Code & Lean 4 Proofs) / CC BY 4.0 (Specification Manuscript)
"""

from .kernel import (
    FLOAT64_NORMAL_MIN,
    VRK_TRUST_ROOT_DIGEST,
    LifecycleState,
    LifecycleEvent,
    TypestateViolationError,
    StaleWorkerEpochError,
    BasinCollapseError,
    RequestSlot,
    WorkerEpochGuard,
    LRSCCompressor,
    SharkProtocolEngine,
)
from .gateway import (
    GatewayConfigError,
    MultiProviderGateway,
    run_http_gateway_server,
)

__version__ = "1.2.0"
__doi__ = "10.5281/zenodo.23624605"
__previous_dois__ = ("10.5281/zenodo.23624605", "10.5281/zenodo.23620074", "10.5281/zenodo.23618033")
__all__ = [
    "FLOAT64_NORMAL_MIN",
    "VRK_TRUST_ROOT_DIGEST",
    "LifecycleState",
    "LifecycleEvent",
    "TypestateViolationError",
    "StaleWorkerEpochError",
    "BasinCollapseError",
    "RequestSlot",
    "WorkerEpochGuard",
    "LRSCCompressor",
    "SharkProtocolEngine",
    "GatewayConfigError",
    "MultiProviderGateway",
    "run_http_gateway_server",
]
