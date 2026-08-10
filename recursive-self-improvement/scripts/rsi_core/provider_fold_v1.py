"""Immutable Task 8 profile identifier for strict provider-v1 JSONL folding.

The executable fold lives in ``evolver_adapter`` so current and historical
guards share one bounded descriptor path.  This module is deliberately tiny:
its raw digest is the reviewed, permanently retained profile identity.
"""

PROFILE_ID = "rsi-provider-fold-v1"
SUPPORTED_PROVIDER_EVENT_SCHEMA_VERSIONS = (1,)
