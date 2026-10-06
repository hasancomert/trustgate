"""A short warning the user can forward to family or colleagues.

Plain text sized for a WhatsApp message, written in the language of the
checked message (English or Turkish). It names the scam pattern and the main
warning signs, and repeats the one safe action; it never repeats the scam's
links, numbers or account details.
"""

from __future__ import annotations

from typing import Literal

from trustgate.schemas import RedFlag, ScamType, Severity, Verdict

Language = Literal["en", "tr"]

MAX_SIGNS = 3

_EN_TYPE: dict[ScamType, str] = {
    ScamType.CEO_INVOICE_FRAUD: "CEO or invoice fraud",
    ScamType.FAMILY_IMPERSONATION: 'a "Hi Mum, new number" impersonation scam',
    ScamType.FAKE_DELIVERY: "a fake parcel-delivery scam",
    ScamType.BANK_IMPERSONATION: "a fake bank-security scam",
    ScamType.INVESTMENT_SCAM: "an investment or crypto scam",
    ScamType.TECH_SUPPORT: "a fake tech-support scam",
    ScamType.ACCOUNT_PHISHING: "an attempt to steal account details",
    ScamType.GOVERNMENT_IMPERSONATION: "a fake government or tax notice",
    ScamType.PRIZE_LOTTERY: "a fake prize or lottery win",
    ScamType.ROMANCE_SCAM: "a romance scam",
    ScamType.JOB_SCAM: "a fake job offer",
    ScamType.MARKETPLACE_SCAM: "a marketplace or overpayment scam",
}

_TR_TYPE: dict[ScamType, str] = {
    ScamType.CEO_INVOICE_FRAUD: "sahte fatura / CEO dolandırıcılığı",
    ScamType.FAMILY_IMPERSONATION: '"anne, bu yeni numaram" dolandırıcılığı',
    ScamType.FAKE_DELIVERY: "sahte kargo dolandırıcılığı",
    ScamType.BANK_IMPERSONATION: "sahte banka güvenlik birimi dolandırıcılığı",
    ScamType.INVESTMENT_SCAM: "sahte yatırım / kripto dolandırıcılığı",
    ScamType.TECH_SUPPORT: "sahte teknik destek dolandırıcılığı",
    ScamType.ACCOUNT_PHISHING: "hesap bilgilerini çalma girişimi",
    ScamType.GOVERNMENT_IMPERSONATION: "sahte resmi kurum / vergi bildirimi",
    ScamType.PRIZE_LOTTERY: "sahte ödül / çekiliş dolandırıcılığı",
    ScamType.ROMANCE_SCAM: "duygusal ilişki dolandırıcılığı",
    ScamType.JOB_SCAM: "sahte iş teklifi",
    ScamType.MARKETPLACE_SCAM: "ilan / kapora dolandırıcılığı",
}

# Turkish wording for the warning signs; the rule titles themselves are English.
_TR_SIGNS: dict[str, str] = {
    "urgency": "acele ettiriyor",
    "threat": "ceza veya kapatma ile korkutuyor",
    "authority": "resmi kurum ya da yetkili gibi davranıyor",
    "payment_change": "değişen hesap bilgisi veriyor",
    "secrecy": "kimseye söylememeni istiyor",
    "channel_avoidance": "telefonda konuşmaktan kaçınıyor",
    "new_contact": "yeni numara hikâyesi anlatıyor",
    "money_request": "para istiyor",
    "fee_request": "küçük bir ücret istiyor",
    "cash_pickup": "nakit ya da altını kuryeye vermeni istiyor",
    "overpayment": "fazla ödemeyi geri istiyor",
    "gift_card": "hediye kartı istiyor",
    "crypto": "kripto para istiyor",
    "irreversible_payment": "geri alınamayan ödeme yöntemi istiyor",
    "credential_request": "şifre ya da doğrulama kodu istiyor",
    "safe_account": '"güvenli hesaba" para aktarmanı istiyor',
    "remote_access": "telefonuna uygulama kurdurmak istiyor",
    "investment_promise": "garantili kazanç vaat ediyor",
    "prize": "ödül kazandığını söylüyor",
    "job_offer": "kolay para kazandıran iş vaat ediyor",
    "agent_manipulation": "yapay zekâ asistanlarına talimat veriyor",
    "link_lookalike": "taklit bir site linki içeriyor",
    "link_obfuscation": "linkin gerçek adresini gizliyor",
    "link_mismatch": "link gönderenin kurumuna ait değil",
    "sender_spoof": "gönderen adresi iddia ettiği kuruma ait değil",
    "payee_mismatch": "para gönderenden farklı birine gidiyor",
}


def _signs(flags: list[RedFlag], language: Language) -> list[str]:
    signs: list[str] = []
    for flag in flags:
        if flag.category == "combination" or flag.severity is Severity.LOW:
            continue
        if language == "tr":
            sign = _TR_SIGNS.get(flag.category)
        else:
            sign = flag.title[0].lower() + flag.title[1:]
        if sign and sign not in signs:
            signs.append(sign)
        if len(signs) == MAX_SIGNS:
            break
    return signs


def share_text(verdict: Verdict, scam_type: ScamType, flags: list[RedFlag], language: Language) -> str | None:
    """Warning text for a suspicious or dangerous message; None when the message looks safe."""
    if verdict is Verdict.SAFE:
        return None
    signs = _signs(flags, language)
    if language == "tr":
        if verdict is Verdict.DANGEROUS:
            kind = _TR_TYPE.get(scam_type, "bir dolandırıcılık girişimi")
            listed = f" Uyarı işaretleri: {', '.join(signs)}." if signs else ""
            return (f"⚠️ Dolandırıcılık uyarısı: Bir mesajı TrustGate ile kontrol ettim, {kind} gibi görünüyor.{listed} "
                    "Para, hediye kartı veya kod gönderme, içindeki linklere tıklama. Tanıdığımız biri olduğunu söylüyorsa "
                    "onu kayıtlı numarasından ara.")
        found = f"TrustGate şu uyarı işaretlerini buldu: {', '.join(signs)}." if signs else "TrustGate uyarı işaretleri buldu."
        return (f"⚠️ Bu mesaja dikkat. {found} Göndereni zaten bildiğin bir numaradan ya da uygulamadan teyit etmeden "
                "ödeme yapma, kod paylaşma.")
    if verdict is Verdict.DANGEROUS:
        kind = _EN_TYPE.get(scam_type, "a scam or impersonation attempt")
        listed = f" Warning signs: {'; '.join(signs)}." if signs else ""
        return (f"⚠️ Scam warning: I checked a message with TrustGate and it looks like {kind}.{listed} "
                "Don't send money, gift cards or codes, and don't tap its links. If it claims to be someone we know, "
                "call them on the number you already have.")
    found = f"TrustGate found these warning signs: {'; '.join(signs)}." if signs else "TrustGate found warning signs."
    return (f"⚠️ Be careful with this message. {found} Don't pay or share any codes until you have checked with "
            "the sender on a number or app you already trust.")
