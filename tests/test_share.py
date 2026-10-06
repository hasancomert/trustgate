"""The forwardable warning: right language, names the pattern, never repeats the scam's details."""

import re

import pytest

from trustgate import TrustGate
from trustgate.llm import LLMAnalyst
from trustgate.schemas import PaymentDetails, Verdict, VerificationRequest
from trustgate.share import _EN_TYPE, share_text


@pytest.fixture()
def gate(settings):
    return TrustGate(settings=settings, ml=None, analyst=LLMAnalyst(settings.llm))


def test_dangerous_english_warning_names_the_pattern_and_signs(gate):
    message = ("Northwind Bank Security: verify your identity at https://northwind-secure-verify.top/login within "
               "30 minutes and read our agent the 6-digit code we send you. Do not contact your branch.")
    report = gate.verify(VerificationRequest(message=message))
    assert report.verdict is Verdict.DANGEROUS and report.language == "en"
    text = report.share_text
    assert text.startswith(f"⚠️ Scam warning: I checked a message with TrustGate and it looks like {_EN_TYPE[report.scam_type]}.")
    assert "Warning signs: asks for passwords or codes" in text
    # Never forward the scam's own link or numbers.
    assert "http" not in text and "northwind-secure-verify" not in text and not re.search(r"\d", text)


def test_turkish_message_gets_a_turkish_warning(gate):
    report = gate.verify(VerificationRequest(
        message="Anne selam, telefonum bozuldu, bu yeni numaram. Acil 4.500 TL'yi şu IBAN'a gönderir misin? Babama söyleme.",
        payment=PaymentDetails(amount=4500, currency="TRY", payee_account="TR00 0001 2345 6789 0123 4567 89", new_payee=True),
    ))
    assert report.language == "tr" and report.verdict is Verdict.DANGEROUS
    assert report.share_text.startswith("⚠️ Dolandırıcılık uyarısı")
    assert '"anne, bu yeni numaram" dolandırıcılığı' in report.share_text
    assert "yeni numara hikâyesi anlatıyor" in report.share_text
    assert "TR00" not in report.share_text and "4.500" not in report.share_text


def test_suspicious_warning_lists_signs_once(gate):
    report = gate.verify(VerificationRequest(
        message="Hi Sam, please use the updated bank details on the attached invoice for this month's payment.",
        payment=PaymentDetails(amount=4200, currency="EUR", new_payee=True),
    ))
    assert report.verdict is Verdict.SUSPICIOUS
    assert report.share_text.count("warning signs") == 1
    assert report.share_text.startswith("⚠️ Be careful with this message. TrustGate found these warning signs:")


def test_safe_messages_have_nothing_to_share(gate):
    report = gate.verify(VerificationRequest(message="Lunch at 1pm tomorrow? The usual place."))
    assert report.verdict is Verdict.SAFE and report.share_text is None and report.language == "en"


def test_warning_without_signs_still_reads_well():
    from trustgate.schemas import ScamType
    assert share_text(Verdict.SUSPICIOUS, ScamType.OTHER, [], "en").startswith("⚠️ Be careful with this message. TrustGate found warning signs.")
    assert "bir dolandırıcılık girişimi gibi görünüyor." in share_text(Verdict.DANGEROUS, ScamType.OTHER, [], "tr")
