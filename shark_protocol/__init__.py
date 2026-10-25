"""
The Reggae Shark Protocol (v1.3.1 — Reviewer-Audited Edition)
Concept DOI: 10.5281/zenodo.23618032 | Prior v4 DOI: 10.5281/zenodo.23635351
"""

from .kernel import (
    FLOAT64_NORMAL_MIN,
    RETIRED_V120_PUBKEY_HEX,
    RETIRED_V120_SEED_SHA256,
    VRK_TRUST_ROOT_DIGEST,
    WP19_SEGMENTS_EXPECTED_SHA256,
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
    evaluate_wp19_piecewise_duhamel_study,
    sha256_canonical,
)
from .gateway import (
    GatewayConfigError,
    GatewayDispatchError,
    GatewayRateLimitError,
    MultiProviderGateway,
    create_gateway_http_server,
    run_http_gateway_server,
)

__version__ = "1.3.1"
__doi__ = "10.5281/zenodo.23618032"
__concept_doi__ = "10.5281/zenodo.23618032"

__all__ = [
    "FLOAT64_NORMAL_MIN",
    "RETIRED_V120_PUBKEY_HEX",
    "RETIRED_V120_SEED_SHA256",
    "VRK_TRUST_ROOT_DIGEST",
    "WP19_SEGMENTS_EXPECTED_SHA256",
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
    "evaluate_wp19_piecewise_duhamel_study",
    "sha256_canonical",
    "GatewayConfigError",
    "GatewayDispatchError",
    "GatewayRateLimitError",
    "MultiProviderGateway",
    "create_gateway_http_server",
    "run_http_gateway_server",
]
