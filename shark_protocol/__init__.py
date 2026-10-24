"""
The Shark Protocol (v1.1.0 — Ironclad VRK, 4D Soft-Wall ODE, LRSC 11/99 & Typestate Gateway)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
License: MIT
"""

from .kernel import (
    SharkProtocolEngine,
    LifecycleState,
    LifecycleEvent,
    RequestSlot,
    TypestateViolationError,
    VRKSchemaError,
    LRSCCompressor,
)
from .gateway import MultiProviderGateway, run_http_gateway

__version__ = "1.1.0"
__all__ = [
    "SharkProtocolEngine",
    "LifecycleState",
    "LifecycleEvent",
    "RequestSlot",
    "TypestateViolationError",
    "VRKSchemaError",
    "LRSCCompressor",
    "MultiProviderGateway",
    "run_http_gateway",
]
