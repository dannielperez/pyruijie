"""pyruijie — Python client library for Ruijie/Reyee Cloud-managed networking."""

from pyruijie.client import RuijieClient
from pyruijie.exceptions import APIError, AuthenticationError, ConnectionError, RuijieError
from pyruijie.models import Device, Project

__version__ = "0.1.0"

__all__ = [
    "RuijieClient",
    "APIError",
    "AuthenticationError",
    "ConnectionError",
    "RuijieError",
    "Device",
    "Project",
]
