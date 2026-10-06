"""TrustGate: layered scam & impersonation risk verification before money moves."""

__version__ = "0.1.0"

from trustgate.schemas import RiskReport, VerificationRequest  # noqa: E402
from trustgate.core import TrustGate, verify  # noqa: E402

__all__ = ["RiskReport", "TrustGate", "VerificationRequest", "__version__", "verify"]
