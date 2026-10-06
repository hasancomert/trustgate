"""Public data contracts for TrustGate.

`VerificationRequest` goes in, `RiskReport` comes out. The API, the web UI and
(later) payment flows all speak these models, so changes here are API changes.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Channel(str, Enum):
    SMS = "sms"
    WHATSAPP = "whatsapp"
    EMAIL = "email"
    OTHER = "other"


class Initiator(str, Enum):
    """Who is about to act on the message.

    `ai_agent` covers autonomous shopping/payment agents acting for a user;
    they need stricter handling because they can be instructed by the message itself.
    """

    HUMAN = "human"
    AI_AGENT = "ai_agent"


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


class RecommendedAction(str, Enum):
    """What a payment flow should do with money tied to this message."""

    PROCEED = "proceed"
    HOLD = "hold"
    BLOCK = "block"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


class ScamType(str, Enum):
    CEO_INVOICE_FRAUD = "ceo_invoice_fraud"
    FAMILY_IMPERSONATION = "family_impersonation"
    FAKE_DELIVERY = "fake_delivery"
    BANK_IMPERSONATION = "bank_impersonation"
    INVESTMENT_SCAM = "investment_scam"
    TECH_SUPPORT = "tech_support"
    ACCOUNT_PHISHING = "account_phishing"
    GOVERNMENT_IMPERSONATION = "government_impersonation"
    PRIZE_LOTTERY = "prize_lottery"
    ROMANCE_SCAM = "romance_scam"
    JOB_SCAM = "job_scam"
    MARKETPLACE_SCAM = "marketplace_scam"
    OTHER = "other"
    NONE = "none"

    @property
    def label(self) -> str:
        return SCAM_TYPE_LABELS[self]


SCAM_TYPE_LABELS: dict[ScamType, str] = {
    ScamType.CEO_INVOICE_FRAUD: "CEO / invoice fraud (business email compromise)",
    ScamType.FAMILY_IMPERSONATION: "Family impersonation (\"Hi Mum, new number\")",
    ScamType.FAKE_DELIVERY: "Fake delivery / parcel fee",
    ScamType.BANK_IMPERSONATION: "Fake bank security team",
    ScamType.INVESTMENT_SCAM: "Investment / crypto scam",
    ScamType.TECH_SUPPORT: "Fake tech support",
    ScamType.ACCOUNT_PHISHING: "Account / credential phishing",
    ScamType.GOVERNMENT_IMPERSONATION: "Government / tax impersonation",
    ScamType.PRIZE_LOTTERY: "Prize / lottery scam",
    ScamType.ROMANCE_SCAM: "Romance scam",
    ScamType.JOB_SCAM: "Job / task scam",
    ScamType.MARKETPLACE_SCAM: "Marketplace / overpayment scam",
    ScamType.OTHER: "Other fraud pattern",
    ScamType.NONE: "No scam pattern detected",
}


class SenderInfo(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    display_name: str | None = Field(default=None, max_length=200, description="Name shown by the app, e.g. 'Northwind Bank'.")
    address: str | None = Field(default=None, max_length=320, description="Email address or phone number.")
    claimed_organization: str | None = Field(default=None, max_length=200, description="Organization the sender claims to be.")


PaymentMethod = Literal["bank_transfer", "card", "gift_card", "crypto", "wallet", "cash", "other"]


class PaymentDetails(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    amount: float | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    payee_name: str | None = Field(default=None, max_length=200)
    payee_account: str | None = Field(default=None, max_length=120, description="IBAN, wallet address or payment email.")
    method: PaymentMethod | None = None
    new_payee: bool | None = Field(default=None, description="True if the payer has never paid this payee before.")

    @field_validator("currency")
    @classmethod
    def _upper_currency(cls, v: str | None) -> str | None:
        return v.upper() if v else v


class VerificationRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    message: str = Field(min_length=1, max_length=20_000, description="SMS, WhatsApp or email text.")
    channel: Channel = Channel.OTHER
    sender: SenderInfo | None = None
    urls: list[str] = Field(default_factory=list, max_length=50, description="Extra URLs; URLs inside the message are extracted automatically.")
    payment: PaymentDetails | None = None
    initiator: Initiator = Initiator.HUMAN


class RedFlag(BaseModel):
    rule_id: str
    category: str
    severity: Severity
    title: str
    explanation: str
    evidence: str | None = None
    start: int | None = Field(default=None, description="Character offset in `message` (inclusive).")
    end: int | None = Field(default=None, description="Character offset in `message` (exclusive).")
    source: Literal["rules", "links", "sender", "payment", "llm"] = "rules"


class LinkFinding(BaseModel):
    url: str
    host: str
    registered_domain: str
    issues: list[str] = Field(default_factory=list)
    severity: Severity | None = None
    impersonated_brand: str | None = None


LayerStatus = Literal["ok", "mock", "fallback", "unavailable", "disabled"]


class LayerSignal(BaseModel):
    score: float | None = Field(default=None, ge=0, le=100)
    weight: float = Field(ge=0, description="Configured weight.")
    effective_weight: float = Field(ge=0, description="Weight after redistributing unavailable layers.")
    status: LayerStatus
    detail: str | None = None


class SignalBreakdown(BaseModel):
    rules: LayerSignal
    ml: LayerSignal
    llm: LayerSignal
    weighted_score: float
    floor_applied: int | None = None


class RiskReport(BaseModel):
    request_id: str
    risk_score: int = Field(ge=0, le=100)
    verdict: Verdict
    recommended_action: RecommendedAction
    scam_type: ScamType
    scam_type_label: str
    summary: str
    red_flags: list[RedFlag]
    link_findings: list[LinkFinding]
    safe_steps: list[str]
    signals: SignalBreakdown
    disclaimer: str
    engine_version: str
    latency_ms: int
