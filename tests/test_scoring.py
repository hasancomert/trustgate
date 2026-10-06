import pytest

from trustgate.config import Thresholds, Weights
from trustgate.llm import LLMAnalysis, LLMOutcome
from trustgate.rules import RuleResult
from trustgate.schemas import Initiator, PaymentDetails, RedFlag, ScamType, Severity, Verdict, VerificationRequest
from trustgate.scoring import (
    AGENT_STEP,
    PAYMENT_STEP,
    fuse,
    merge_flags,
    resolve_scam_type,
    safe_steps,
    template_summary,
    verdict_for,
)

W = Weights(rules=0.45, ml=0.20, llm=0.35)
T = Thresholds(suspicious=35, dangerous=70)


def rule_result(score=0.0, floor=None, flags=None, type_scores=None):
    return RuleResult(score=score, floor=floor, red_flags=flags or [], link_findings=[], category_severity={}, scam_type_scores=type_scores or {})


def llm_ok(score=50, scam_type="other", steps=None, summary="LLM summary"):
    analysis = LLMAnalysis(risk_score=score, scam_type=scam_type, summary=summary, safe_steps=steps or [])
    return LLMOutcome(status="ok", model="m", analysis=analysis)


MOCK = LLMOutcome(status="mock", detail="mock")


def test_fuse_uses_all_layers_with_configured_weights():
    score, sig = fuse(W, rule_result(60), 40.0, llm_ok(80))
    assert score == round(0.45 * 60 + 0.20 * 40 + 0.35 * 80)
    assert sig.rules.effective_weight == 0.45 and sig.llm.status == "ok"
    assert sig.floor_applied is None


def test_fuse_redistributes_missing_layers():
    score, sig = fuse(W, rule_result(60), None, MOCK)
    assert score == 60
    assert sig.ml.status == "unavailable" and sig.ml.effective_weight == 0
    assert sig.llm.status == "mock" and sig.llm.score is None
    assert sig.rules.effective_weight == 1.0

    score, sig = fuse(W, rule_result(50), 100.0, MOCK)
    assert score == round((0.45 * 50 + 0.20 * 100) / 0.65)


def test_rule_floor_cannot_be_talked_down():
    score, sig = fuse(W, rule_result(30, floor=80), 2.0, llm_ok(0))
    assert score == 80
    assert sig.floor_applied == 80
    assert sig.weighted_score < 80


@pytest.mark.parametrize("score,verdict", [(0, Verdict.SAFE), (34, Verdict.SAFE), (35, Verdict.SUSPICIOUS), (69, Verdict.SUSPICIOUS), (70, Verdict.DANGEROUS), (100, Verdict.DANGEROUS)])
def test_verdict_thresholds(score, verdict):
    assert verdict_for(score, T) is verdict


def test_scam_type_resolution_prefers_specific_llm_type():
    rr = rule_result(type_scores={ScamType.FAKE_DELIVERY: 4.0})
    assert resolve_scam_type(Verdict.DANGEROUS, rr, llm_ok(scam_type="bank_impersonation")) is ScamType.BANK_IMPERSONATION
    assert resolve_scam_type(Verdict.DANGEROUS, rr, llm_ok(scam_type="other")) is ScamType.FAKE_DELIVERY
    assert resolve_scam_type(Verdict.DANGEROUS, rr, MOCK) is ScamType.FAKE_DELIVERY
    assert resolve_scam_type(Verdict.SUSPICIOUS, rule_result(), MOCK) is ScamType.OTHER
    assert resolve_scam_type(Verdict.SAFE, rr, llm_ok(scam_type="bank_impersonation")) is ScamType.NONE


def test_merge_flags_skips_llm_flags_overlapping_rule_spans():
    rule = RedFlag(rule_id="r", category="c", severity=Severity.HIGH, title="t", explanation="e", start=0, end=10)
    overlapping = RedFlag(rule_id="llm.insight", category="llm_insight", severity=Severity.MEDIUM, title="t", explanation="e", start=5, end=12, source="llm")
    separate = RedFlag(rule_id="llm.insight", category="llm_insight", severity=Severity.MEDIUM, title="t", explanation="e", start=20, end=25, source="llm")
    assert merge_flags([rule], [overlapping, separate]) == [rule, separate]


def test_safe_steps_for_agent_payment_and_type():
    req = VerificationRequest(message="x", initiator=Initiator.AI_AGENT, payment=PaymentDetails(amount=10))
    steps = safe_steps(Verdict.DANGEROUS, ScamType.BANK_IMPERSONATION, req, llm_ok(steps=["LLM step one."]))
    assert steps[0] == AGENT_STEP
    assert steps[1] == "LLM step one."
    assert len(steps) <= 5
    assert PAYMENT_STEP in steps or len(steps) == 5
    safe = safe_steps(Verdict.SAFE, ScamType.NONE, VerificationRequest(message="x"), MOCK)
    assert safe and "No strong warning signs" in safe[0]


def test_template_summary_mentions_reasons():
    flags = [RedFlag(rule_id="a", category="secrecy", severity=Severity.HIGH, title="Asks for secrecy", explanation="e")]
    text = template_summary(Verdict.DANGEROUS, ScamType.FAMILY_IMPERSONATION, flags)
    assert "family impersonation" in text.lower() and "asks for secrecy" in text
    assert template_summary(Verdict.SAFE, ScamType.NONE, []).startswith("No strong")


def test_skipped_llm_is_excluded_from_fusion():
    score, sig = fuse(W, rule_result(40), 60.0, LLMOutcome(status="skipped", detail="quick"))
    assert sig.llm.status == "skipped" and sig.llm.effective_weight == 0
    assert score == round((0.45 * 40 + 0.20 * 60) / 0.65)
