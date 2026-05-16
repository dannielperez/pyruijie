"""Workflow-specific exceptions for :mod:`pyruijie.workflows`."""

from __future__ import annotations

from pyruijie.exceptions import RuijieError


class WorkflowError(RuijieError):
    """Base class for orchestration-level workflow failures.

    Distinct from :class:`~pyruijie.exceptions.RuijieWireGuardError` in
    that workflow errors signal that the overall multi-step operation
    could not proceed, rather than a single API call returning an
    error.
    """


class WorkflowPrecheckError(WorkflowError):
    """Raised before any side-effect when inputs are invalid or unsafe.

    Examples: requested peer IP outside the server's network;
    ``--configure-site`` requested without a site private key; missing
    credentials.
    """
