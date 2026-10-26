"""
The Reggae Shark Protocol (v1.3.2)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Concept DOI: 10.5281/zenodo.23618032
"""

__version__ = "1.3.2"
__doi__ = "10.5281/zenodo.23618032"
__concept_doi__ = "10.5281/zenodo.23618032"

from .kernel import (
    FLOAT64_NORMAL_MIN,
    RELEASE_REFERENCE_HEAD_HASH,
    RETIRED_V120_PUBKEY_HEX,
    RETIRED_V120_SEED_SHA256,
    REVOKED_PUBLIC_PUBKEY_HEX,
    REVOKED_PUBLIC_SEED_SHA256,
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
    SOCKET_TIMEOUT_SECONDS,
    GatewayAuthError,
    GatewayCapacityError,
    GatewayConfigError,
    GatewayDispatchError,
    GatewayRateLimitError,
    MultiProviderGateway,
    create_gateway_http_server,
    run_http_gateway_server,
)

__all__ = [
    "__version__",
    "__doi__",
    "__concept_doi__",
    "FLOAT64_NORMAL_MIN",
    "RELEASE_REFERENCE_HEAD_HASH",
    "REVOKED_PUBLIC_PUBKEY_HEX",
    "REVOKED_PUBLIC_SEED_SHA256",
    "RETIRED_V120_PUBKEY_HEX",
    "RETIRED_V120_SEED_SHA256",
    "VRK_TRUST_ROOT_DIGEST",
    "WP19_SEGMENTS_EXPECTED_SHA256",
    "SOCKET_TIMEOUT_SECONDS",
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
    "GatewayAuthError",
    "GatewayCapacityError",
    "GatewayConfigError",
    "GatewayDispatchError",
    "GatewayRateLimitError",
    "MultiProviderGateway",
    "create_gateway_http_server",
    "run_http_gateway_server",
]
