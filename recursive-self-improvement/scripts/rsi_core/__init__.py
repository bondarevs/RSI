"""Strict, append-only storage primitives for RSI run metadata."""

from .events import EventEnvelope, EventRegistry, EventValidationError, fold_run

__all__ = ["EventEnvelope", "EventRegistry", "EventValidationError", "EventStore", "StoreIntegrityError", "fold_run"]


def __getattr__(name: str):
    if name in {"EventStore", "StoreIntegrityError"}:
        from .storage import EventStore, StoreIntegrityError

        return {"EventStore": EventStore, "StoreIntegrityError": StoreIntegrityError}[name]
    raise AttributeError(name)
