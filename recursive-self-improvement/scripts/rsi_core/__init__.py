"""Strict, append-only storage primitives for RSI run metadata."""

from .events import EventEnvelope, EventRegistry, EventValidationError, fold_run

__all__ = [
    "DeploymentAmbiguousError",
    "DeploymentError",
    "DeploymentLockTimeout",
    "DeploymentOperationConflict",
    "DeploymentPaths",
    "DeploymentPlan",
    "DeploymentSourceError",
    "DeploymentStatus",
    "DeploymentUnsupported",
    "EventEnvelope",
    "EventRegistry",
    "EventStore",
    "EventValidationError",
    "GlobalRsiDeployer",
    "StoreIntegrityError",
    "fold_run",
]

_DEPLOYMENT_EXPORTS = frozenset(
    {
        "DeploymentAmbiguousError",
        "DeploymentError",
        "DeploymentLockTimeout",
        "DeploymentOperationConflict",
        "DeploymentPaths",
        "DeploymentPlan",
        "DeploymentSourceError",
        "DeploymentStatus",
        "DeploymentUnsupported",
        "GlobalRsiDeployer",
    }
)


def __getattr__(name: str):
    if name in {"EventStore", "StoreIntegrityError"}:
        from .storage import EventStore, StoreIntegrityError

        return {"EventStore": EventStore, "StoreIntegrityError": StoreIntegrityError}[name]
    if name in _DEPLOYMENT_EXPORTS:
        from . import deployment

        return getattr(deployment, name)
    raise AttributeError(name)
