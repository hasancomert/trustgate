"""Score fusion, verdicts, scam-type resolution and safe-step guidance."""

from __future__ import annotations

from trustgate.config import Thresholds, Weights
from trustgate.llm import LLMOutcome
from trustgate.rules import RuleResult
from trustgate.schemas import (
    Initiator,
    LayerSignal,
    RecommendedAction,
    RedFlag,
    ScamType,
    Severity,
    SignalBreakdown,
    Verdict,
    VerificationRequest,
)

# ---------------------------------------------------------------------- fusion


def fuse(weights: Weights, rule_result: RuleResult, ml_score: float | None, llm: LLMOutcome) -> tuple[int, SignalBreakdown]:
    """Weighted average of the available layers, then the rule floor.

    Layers without a real score (ML model missing, LLM in mock/fallback mode)
    get weight 0 and their share is redistributed over the others.
    """
    raw = {
        "rules": (rule_result.score, "ok", None),
        "ml": (ml_score, "ok" if ml_score is not None else "unavailable", None if ml_score is not None else "Model file not found; run the training script."),
        "llm": (llm.score, llm.status, llm.detail),
    }
    configured = {"rules": weights.rules, "ml": weights.ml, "llm": weights.llm}
    active = {name: w for name, w in configured.items() if raw[name][0] is not None and w > 0}
    total = sum(active.values()) or 1.0
    weighted = sum(active[name] * raw[name][0] for name in active) / total

    floor = rule_result.floor
    final = max(weighted, float(floor or 0))
    signals = {
        name: LayerSignal(
            score=None if score is None else round(score, 1),
            weight=configured[name],
            effective_weight=round(active.get(name, 0.0) / total, 3),
            status=status,
            detail=detail,
        )
        for name, (score, status, detail) in raw.items()
    }
    breakdown = SignalBreakdown(
        **signals,
        weighted_score=round(weighted, 1),
        floor_applied=floor if floor is not None and floor > weighted else None,
    )
    return int(round(min(100.0, final))), breakdown


def verdict_for(score: int, thresholds: Thresholds) -> Verdict:
    if score >= thresholds.dangerous:
        return Verdict.DANGEROUS
    if score >= thresholds.suspicious:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


ACTIONS = {Verdict.SAFE: RecommendedAction.PROCEED, Verdict.SUSPICIOUS: RecommendedAction.HOLD, Verdict.DANGEROUS: RecommendedAction.BLOCK}


def resolve_scam_type(verdict: Verdict, rule_result: RuleResult, llm: LLMOutcome) -> ScamType:
    if verdict is Verdict.SAFE:
        return ScamType.NONE
    llm_type = llm.analysis.scam_type if llm.status == "ok" and llm.analysis else None
    if llm_type not in (None, ScamType.NONE, ScamType.OTHER):
        return llm_type
    return rule_result.top_scam_type or ScamType.OTHER


def merge_flags(rule_flags: list[RedFlag], llm_flags: list[RedFlag]) -> list[RedFlag]:
    """Add grounded LLM flags that point at text the rules did not already mark."""
    spans = [(f.start, f.end) for f in rule_flags if f.start is not None and f.end is not None]
    extra = [f for f in llm_flags if not any(f.start < e and s < f.end for s, e in spans)]
    return rule_flags + extra


# ---------------------------------------------------------------------- guidance

GENERIC_STEPS = (
    "Do not send money, gift cards, crypto or one-time codes until you have verified the request.",
    "Contact the person or company through a phone number, app or website you already trust, not the details in this message.",
)

TYPE_STEPS: dict[ScamType, tuple[str, ...]] = {
    ScamType.FAMILY_IMPERSONATION: (
        "Call your family member on the number you already have saved, or ask a question only they would know.",
        "Agree on a family 'safe word' for any future money requests.",
    ),
    ScamType.CEO_INVOICE_FRAUD: (
        "Call the requester back on a number from your company directory, not one from this message.",
        "Follow the normal payment approval process: 'urgent' or 'confidential' is never a reason to skip it.",
        "Never change supplier bank details based on an email alone; confirm with a contact you already know.",
    ),
    ScamType.FAKE_DELIVERY: (
        "Track parcels only in the courier's official app or by typing their website address yourself.",
        "Do not enter card details on a link sent by text to pay a small 'redelivery' or 'customs' fee.",
    ),
    ScamType.BANK_IMPERSONATION: (
        "Hang up and call the number printed on the back of your card.",
        "Your bank will never ask you to move money to a 'safe account' or to read out a one-time code.",
    ),
    ScamType.INVESTMENT_SCAM: (
        "Check that the firm is registered with your financial regulator before investing anything.",
        "Treat guaranteed or daily returns, and withdrawals that need extra fees, as scam signs.",
    ),
    ScamType.TECH_SUPPORT: (
        "Never install remote-access apps for someone who contacted you first.",
        "Check charges and subscriptions in the official app or website you normally use.",
    ),
    ScamType.ACCOUNT_PHISHING: (
        "Open the official app or type the web address yourself instead of using the link.",
        "Never share one-time codes. If you already entered a password via the link, change it now.",
    ),
    ScamType.GOVERNMENT_IMPERSONATION: (
        "Government agencies don't collect fines or refunds through text-message links; check on the official website.",
        "Look up the agency's contact details yourself before responding.",
    ),
    ScamType.PRIZE_LOTTERY: ("You can't win a draw you never entered; never pay a 'fee' to claim a prize.",),
    ScamType.ROMANCE_SCAM: (
        "Never send money or crypto to someone you have only met online.",
        "Talk to a friend or family member before acting; scammers rely on secrecy.",
    ),
    ScamType.JOB_SCAM: ("Real employers never ask you to pay a deposit to start working or unlock tasks.",),
    ScamType.MARKETPLACE_SCAM: (
        "Check your payment app directly: emails 'confirming' a payment can be fake.",
        "Never refund an 'overpayment' before the original payment has fully cleared.",
    ),
}

AGENT_STEP = "Pause the automated agent and ask the account owner to confirm this payment directly."
PAYMENT_STEP = "Hold the payment until the payee's details are confirmed through a channel you already trust."
SAFE_STEPS = (
    "No strong warning signs were found. If money is involved, still confirm it through a channel you already trust.",
    "If anything changes, such as new bank details, sudden urgency or a request for secrecy, check again.",
)
MAX_STEPS = 5


def _dedupe(steps: list[str]) -> list[str]:
    seen, out = set(), []
    for step in steps:
        key = step.lower().strip(" .")
        if key and key not in seen:
            seen.add(key)
            out.append(step)
    return out


def safe_steps(verdict: Verdict, scam_type: ScamType, request: VerificationRequest, llm: LLMOutcome) -> list[str]:
    llm_steps = list(llm.analysis.safe_steps) if llm.status == "ok" and llm.analysis else []
    if verdict is Verdict.SAFE:
        return _dedupe([*SAFE_STEPS])[:MAX_STEPS]
    steps: list[str] = []
    if request.initiator is Initiator.AI_AGENT:
        steps.append(AGENT_STEP)
    steps += llm_steps[:3]
    steps += TYPE_STEPS.get(scam_type, ())
    if request.payment is not None:
        steps.append(PAYMENT_STEP)
    steps += GENERIC_STEPS
    return _dedupe(steps)[:MAX_STEPS]


def template_summary(verdict: Verdict, scam_type: ScamType, flags: list[RedFlag]) -> str:
    """Plain-language explanation used when the LLM layer is in mock/fallback mode."""
    reasons: list[str] = []
    for flag in flags:
        if flag.category == "combination" or flag.severity is Severity.LOW:
            continue
        title = flag.title[0].lower() + flag.title[1:]
        if title not in reasons:
            reasons.append(title)
        if len(reasons) == 3:
            break
    because = f" Warning signs: {'; '.join(reasons)}." if reasons else ""
    if verdict is Verdict.DANGEROUS:
        kind = scam_type.label.lower() if scam_type not in (ScamType.OTHER, ScamType.NONE) else "a scam or impersonation attempt"
        return f"High risk: this matches the pattern of {kind}.{because} Do not send money or codes until you have verified the request independently."
    if verdict is Verdict.SUSPICIOUS:
        return f"Some warning signs need checking before you act.{because} Verify the sender through a channel you already trust."
    return "No strong scam or impersonation signals were found in this message." + (f" Minor notes: {'; '.join(reasons)}." if reasons else "")
