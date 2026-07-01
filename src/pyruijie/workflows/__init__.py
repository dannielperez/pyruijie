"""High-level workflow orchestrations for Ruijie/Reyee deployments.

Technician-facing multi-step operations built on top of
``pyruijie.cli``. All workflows share a consistent shape:

* **Idempotent.** Running twice on a finished system is safe.
* **Observable.** Events flow through :class:`ProgressSink`.
* **Structured results.** Every workflow returns a frozen dataclass
  with ``success`` (or ``ok``) and ``.to_dict()`` for JSON/GUI use.
* **Dry-run by default.** Write operations require explicit
  ``apply=True``.
* **Secret-safe.** Private keys, preshared keys, tokens, and
  passwords never appear in result fields or progress events.

Stability: **Provisional** — subject to refinement as more sites are
onboarded.
"""

from __future__ import annotations

from .drift import DriftScanResult, PeerDriftOutcome, detect_hub_drift
from .endpoint import (
    EndpointTarget,
    EndpointUpdateBatchResult,
    EndpointUpdateOutcome,
    update_site_endpoints,
)
from .exceptions import WorkflowError, WorkflowPrecheckError
from .progress import (
    ConsoleProgressSink,
    NullProgressSink,
    ProgressEvent,
    ProgressSink,
)
from .site_onboarding import SiteOnboardingResult, onboard_site
from .wireguard import (
    PeerAddBatchResult,
    PeerAddOutcome,
    PeerAddRequest,
    add_hub_peers,
)

__all__ = [
    "ConsoleProgressSink",
    "DriftScanResult",
    "EndpointTarget",
    "EndpointUpdateBatchResult",
    "EndpointUpdateOutcome",
    "NullProgressSink",
    "PeerAddBatchResult",
    "PeerAddOutcome",
    "PeerAddRequest",
    "PeerDriftOutcome",
    "ProgressEvent",
    "ProgressSink",
    "SiteOnboardingResult",
    "WorkflowError",
    "WorkflowPrecheckError",
    "add_hub_peers",
    "detect_hub_drift",
    "onboard_site",
    "update_site_endpoints",
]
