"""Safe tool adapters for AegisEV."""

from .framework import (
    AdapterMetadata,
    AdapterPlanner,
    AdapterRegistry,
    AttackSurfaceGraphAdapter,
    ApiImportAdapter,
    DuplicateAdapterError,
    EchoPlanAdapter,
    SafeHttpFetchAdapter,
    SafeToolAdapter,
    TechnologyFingerprintAdapter,
    ToolActionPlan,
    ToolActionRequest,
    UnknownAdapterError,
    WebHeaderConfigCheckAdapter,
    default_registry,
)

__all__ = [
    "AdapterMetadata",
    "AdapterPlanner",
    "AdapterRegistry",
    "AttackSurfaceGraphAdapter",
    "ApiImportAdapter",
    "DuplicateAdapterError",
    "EchoPlanAdapter",
    "SafeHttpFetchAdapter",
    "SafeToolAdapter",
    "TechnologyFingerprintAdapter",
    "ToolActionPlan",
    "ToolActionRequest",
    "UnknownAdapterError",
    "WebHeaderConfigCheckAdapter",
    "default_registry",
]
