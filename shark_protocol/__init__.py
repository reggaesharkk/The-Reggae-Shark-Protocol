"""
The Reggae Shark Protocol (v1.3.0 — Cross-Program 3-Track Upgrade Edition)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Concept DOI: 10.5281/zenodo.23618032 | Zenodo v4 DOI: 10.5281/zenodo.23635351
"""

from .kernel import (
    FLOAT64_NORMAL_MIN,
    VRK_TRUST_ROOT_DIGEST,
    BasinCollapseError,
    Ed25519AuthoritySigner,
    IsolatedSignerSubprocess,
    LRSCCompressor,
    LifecycleEvent,
    LifecycleState,
    RequestSlot,
    SharkProtocolEngine,
    StaleWorkerEpochError,
    TypestateViolationError,
    WorkerEpochGuard,
    certify_wp19_piecewise_duhamel_bridge,
    sha256_canonical,
)
from .gateway import (
    GatewayConfigError,
    GatewayDispatchError,
    MultiProviderGateway,
    create_gateway_http_server,
    run_http_gateway_server,
)

__version__ = "1.3.0"
__doi__ = "10.5281/zenodo.23635351"
__concept_doi__ = "10.5281/zenodo.23618032"

__all__ = [
    "FLOAT64_NORMAL_MIN",
    "VRK_TRUST_ROOT_DIGEST",
    "BasinCollapseError",
    "Ed25519AuthoritySigner",
    "IsolatedSignerSubprocess",
    "LRSCCompressor",
    "LifecycleEvent",
    "LifecycleState",
    "RequestSlot",
    "SharkProtocolEngine",
    "StaleWorkerEpochError",
    "TypestateViolationError",
    "WorkerEpochGuard",
    "certify_wp19_piecewise_duhamel_bridge",
    "sha256_canonical",
    "GatewayConfigError",
    "GatewayDispatchError",
    "MultiProviderGateway",
    "create_gateway_http_server",
    "run_http_gateway_server",
]
