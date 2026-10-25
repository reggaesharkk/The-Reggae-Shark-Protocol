"""
The Reggae Shark Protocol (v1.1.2)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Canonical Zenodo DOI: 10.5281/zenodo.23624605 (Superseded v1.0.3 DOI: 10.5281/zenodo.23618033)
License: MIT (Code & Lean 4 Proofs) / CC BY 4.0 (Specification Manuscript)
"""

from .kernel import (
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

__version__ = "1.1.2"
__doi__ = "10.5281/zenodo.23624605"
__all__ = [
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
