"""Turkish manipulation-tactic patterns.

They extend the English rules (same rule ids and categories, so combinations,
floors and scoring work across languages). Patterns are written against the
engine's normalized text, where Turkish letters are folded to ASCII
(ı/İ→i, ş→s, ğ→g, ç→c, ö→o, ü→u): "hesabınız", "HESABINIZ" and the
phone-typed "hesabiniz" all match the same pattern.

Turkish negates verbs with a suffix ("paylaş-ma-yın", "söyle-me-yin"), so the
verb roots below refuse a following "ma"/"me". Protective advice such as
"bu kodu kimseyle paylaşmayın" therefore never reads as a request.
"""

from __future__ import annotations

import re
from dataclasses import replace

from trustgate.rules.text_rules import C, H, L, M, Pattern, TextRule, _p

# A request: imperative ("söyle", "söyleyin", "okuyun") or question ("söyler misiniz", "yazabilir misin").
# Past and first-person forms ("kodu yazdım") are statements, not requests.
_REQUEST_SUFFIX = r"(?:y?in(?:iz)?|y?un(?:uz)?|(?:a|e|i|u)?r\s?mi\w*|(?:y?a|y?e)bilir\s?mi\w*)?\b"


def _request(*roots: str) -> str:
    return "(?:" + "|".join(roots) + ")" + _REQUEST_SUFFIX


_SAY = _request("soyle", "ilet", "paylas", "gonder", "yaz", "oku", "ver", "gir", "bildir", "tusla")
_SEND = r"(?:gonder(?!m[ae])\w*|yolla(?!m[ae])\w*|yatir(?!m[ae])\w*|havale\w*|eft|fast|atar\s?mi\w*|atabilir\s?mi\w*|atsana|ativer\w*|aktar(?!m[ae])\w*)"
_MONEY = r"(?:(?<![\d.,])\d[\d.,]{0,20}\s*(?:tl|lira|try)\b|₺\s?\d[\d.,]{0,20})"  # bounded, see text_rules._MONEY
_CREDENTIAL = r"(?:kod\w*|sifre\w*|parola\w*|pin\b|cvv|cvc|kart bilgi\w*|kart numara\w*|tc kimlik\w*)"
# Credential words in the same clause: "kodu kimseyle paylaşmayın" is advice, not secrecy.
# "Kimseye söyleme, gelen kodu bana yaz" is two clauses, so the comma ends the look-ahead.
_PROTECTIVE_BEFORE = re.compile(_CREDENTIAL + r"[^.!?\n]{0,30}$", re.IGNORECASE)
_PROTECTIVE_AFTER = re.compile(r"^[^,;:]{0,30}?\b" + _CREDENTIAL, re.IGNORECASE)


TR_PATTERNS: dict[str, tuple[Pattern, ...]] = {
    "text.urgency": (
        _p(r"\b(acil|acilen|ivedi|ivedilikle|derhal|bir an (once|evvel)|vakit kaybetmeden|zaman kaybetmeden)\b", M),
        _p(r"\bhemen\s+(odeme|ode|gonder|yatir|tikla|giris|dogrula|islem|ara|at)\w*", M),
        _p(r"\b(son gun|son firsat|son uyari|son hatirlatma|son bildirim)\w*", M),
        _p(r"\b\d+\s*(saat|dakika|dk)\s*(icinde|icerisinde)\b", M),
        _p(r"\bbugun\s+(icinde|odenmezse|odemezseniz|odemeniz gereken)\b", M),
        _p(r"\b(gece yarisina|gun sonuna|mesai bitimine)\s+kadar\b", M),
    ),
    "text.threat": (
        _p(r"\b(hesab\w*|kart\w*|hatt\w*|uyelig\w*|abonelig\w*|sifre\w*)\b[^.!?\n]{0,30}\b(bloke (edil|ol|konul|koyul)\w*|askiya alin\w*|kapatil\w*|kapanacak\w*|dondurul\w*|iptal edil\w*|kisitlan\w*|kilitlen\w*|durdurul\w*|engellen\w*)", H),
        _p(r"\b(hakkiniz\w*|adiniz\w*|tarafiniz\w*)\b[^.!?\n]{0,40}\b(yasal (islem|takip|surec)|icra|haciz|dava|gozalti|yakalama karari|tutuklama)", H),
        _p(r"\b(yasal islem|icra takib|haciz|yakalama karar|tutuklama karar|trafikten men|men islem|el koyma)\w*\b[^.!?\n]{0,40}\b(baslat\w*|uygulan\w*|cikaril\w*|yapilacak\w*)", H),
        _p(r"\b(ceza|borc|faiz|tutar)\w*\s+(\w+\s+){0,2}(artacak|artirilacak|katlanacak|yukselecek|iki katina)\w*", M),
        _p(r"\b(gecikme|ek)\s+(ceza|faiz|ucret)\w*", M),
        _p(r"\baksi (halde|takdirde)\b", M),
    ),
    "text.authority": (
        _p(r"\b(savcilig|savcilik|cumhuriyet savcis|emniyet mudurlug|emniyet|siber suclar|masak|btk|vergi daire|gelir idare|jandarma)\w*", M),
        _p(r"\b(ben|biz)\b[^.!?\n]{0,15}\b(komiser|savci|polis|banka\w* guvenlik|guvenlik birimi|musteri temsilci\w*)", M),
        _p(r"\b(guvenlik|dolandiricilik|risk|uyum)\s+(birim\w*|ekib\w*|departman\w*|merkez\w*|sorumlu\w*|yetkili\w*)", M),
        _p(r"\b(genel mudur|mudur bey|mudur hanim|patron)\w*", L),
    ),
    "text.payment_change": (
        _p(r"\b(yeni|guncel|guncellenmis|degisen|farkli)\s+iban\w*", H),
        _p(r"\b(iban|hesap)\s+(bilgi\w*|numara\w*)\s+(degis\w*|guncellen\w*|yenilen\w*)", H),
        _p(r"\b(odeme\w*|havale\w*|eft)\b[^.!?\n]{0,30}\b(yeni|guncel|asagidaki|su)\s+(iban|hesab)\w*", H),
        _p(r"\b(eski|onceki)\s+(iban|hesab)\w*\s+(kullanmay\w*|gecersiz\w*|kapan\w*)", H),
    ),
    "text.secrecy": (
        _p(r"\b(kimseye|hic kimseye|kimseyle|babama|anneme|babana|annene|aileye|aileme|esime|esine|bankaya|polise)\b[^.!?\n]{0,20}\b(soyleme\w*|soylemey\w*|anlatma\w*|bahsetme\w*|haber verme\w*|duyurma\w*)",
           H, unless_before=_PROTECTIVE_BEFORE, unless_after=_PROTECTIVE_AFTER),
        _p(r"\b(gizli|aramizda)\s+(kalsin|kalmali|tutun|tutalim|tutmaniz)\w*", H),
        _p(r"\b(bu|islem|gorusme|konu|sorusturma|dosya)\s+(cok\s+)?gizli\w*", H),
    ),
    "text.channel_avoidance": (
        _p(r"\b(su an|simdi)\s+(konusamam|konusamiyorum|arayamam|acamam|musait degilim)\b", M),
        _p(r"\b(toplantidayim|toplantidayiz|toplantiya giriyorum)\b", M),
        _p(r"\b(subeye|bankaya|subenize|bankaniza|polise|karakola)\s+(gitmeyin\w*|gitme|haber vermeyin\w*|basvurmayin\w*|ugramayin\w*)", H),
        _p(r"\b(telefonu|aramayi)\s+(kapatmayin\w*)", M),
    ),
    "text.new_contact": (
        _p(r"\b(bu|bu benim|bu da)\s+yeni\s+(numaram|numara|telefonum|hattim)\b", H),
        _p(r"\byeni (numaram|numaramdan|hattim|hattimdan)\b", M),
        _p(r"\btelefonum\w*\s+(bozuldu|kirildi|kayboldu|calindi|suya dustu|ariza\w*)", H),
        _p(r"\b(numarami|bu numarayi|yeni numarami)\s+kaydet\w*", M),
        _p(r"\b(arkadasimin|baskasinin)\s+(telefonu\w*|numara\w*)", M),
    ),
    "text.money_request": (
        _p(r"\b(para|nakit|borc)\w*\s+" + _SEND, M),
        _p(r"\b(para|nakit)\s+(lazim|gerekiyor|ihtiyacim)\b", M),
        _p(_MONEY + r"[^.!?\n]{0,40}\b" + _SEND, M),
        _p(r"\b" + _SEND + r"[^.!?\n]{0,30}" + _MONEY, M),
        _p(r"\b(iban\w*|hesab\w*)\b[^.!?\n]{0,15}\b" + _SEND, M),
    ),
    "text.fee_request": (
        _p(r"\b(gumruk|kargo|teslimat|adres guncelleme|yeniden gonderim|hizmet|islem|dosya|aktivasyon|cekim)\s+(ucret\w*|bedel\w*|masraf\w*|vergi\w*)", M),
        _p(r"\b(odenmemis|eksik|kalan|gecikmis)\s+(\w+\s+){0,3}(ucret|borc|bedel|odeme|fatura|ceza)\w*", M),
        _p(r"\b(kapora\w*|kaparo\w*)", M),
    ),
    "text.cash_pickup": (
        _p(r"\b(kurye\w*|gorevli\w*|memur\w*|polis\w*|arkadasim\w*)\b[^.!?\n]{0,40}\b(alacak|gelecek|teslim al\w*|almaya gel\w*|kapiniza gel\w*|evinize gel\w*)", H),
        _p(r"\b(altin\w*|ziynet\w*|nakit\w*|doviz\w*|paranizi|paralarinizi)\b[^.!?\n]{0,40}\b(teslim edin\w*|gorevliye ver\w*|gorevlimize ver\w*|poset\w*)", H),
    ),
    "text.overpayment": (
        _p(r"\bfazla(dan)?\s+(odeme|gonder\w*|yatir\w*|para)\b", H),
        _p(r"\bfark\w*\s+(iade|geri gonder|geri yolla|geri ode)\w*", H),
    ),
    "text.gift_card": (
        _p(r"\b(al|alin|satin al\w*|alip)\b[^.!?\n]{0,30}\b(hediye\s*kart\w*|hediye cek\w*|e-?pin\w*|oyun kart\w*)", C),
        _p(r"\b(hediye\s*kart\w*|hediye ceki|oyun kart\w*|google play\s*kart\w*|itunes\s*kart\w*|steam\s*kart\w*|e-?pin\w*)", H),
    ),
    "text.crypto": (
        _p(r"\b(usdt|bitcoin|btc|kripto\w*)\b[^.!?\n]{0,30}\b" + _SEND, H),
        _p(r"\b" + _SEND + r"[^.!?\n]{0,30}\b(usdt|bitcoin|btc|kripto\w*)", H),
        _p(r"\b(cuzdan adres\w*|kripto cuzdan\w*)", H),
        _p(r"\b(kripto(\s*para)?\w*|tether)\b", M),
    ),
    "text.irreversible_payment": (
        _p(r"\b(papara|ininal)\b", M),
    ),
    "text.credential_request": (
        _p(r"\b(gelen|gonderilen|gonderdigimiz|ilettigimiz|size gelen|telefonunuza gelen|cebinize gelen)\s+(\d\s*(haneli)?\s*)?(kod\w*|sifre\w*|onay kod\w*|dogrulama kod\w*|sms kod\w*)\b[^.!?\n]{0,30}\b" + _SAY, C),
        _p(r"\b" + _CREDENTIAL + r"\b[^.!?\n]{0,25}\b" + _SAY, C),
        _p(r"\b(hesab\w*|bilgi\w*|kimlig\w*|kart\w*)\s+(dogrula|guncelle|onayla|aktiflestir|aktif ed)(yin|yiniz|in|iniz|maniz|meniz|man|men|mak icin|mek icin)\b", H),
        _p(r"\b(giris yap\w*|oturum ac\w*)\b[^.!?\n]{0,30}\b(link|baglanti|asagidaki|tiklay)\w*", M),
    ),
    "text.link_call_to_action": (
        _p(r"\b(linke|baglantiya|asagidaki linke|asagidaki baglantiya)\s+(tikla\w*|gir\w*)", L),
        _p(r"\btiklay(in|iniz|arak)\b", L),
    ),
    "text.safe_account": (
        _p(r"\b(guvenli|guvenlikli|korumali|koruma)\s+(hesab\w*|kasa\w*)", C),
        _p(r"\b(paranizi|birikimlerinizi|paralarinizi|altinlarinizi)\s+(koruma\w*|guvene|guvenceye)\s+al\w*", C),
    ),
    "text.remote_access": (
        _p(r"\b(uzaktan (erisim|baglanti|destek|kontrol)|ekran paylas\w*)", H),
        _p(r"\b(uygulama\w*|program\w*)\b[^.!?\n]{0,20}\b(indir|yukle|kur)(in|iniz|un|unuz)\b", M),
    ),
    "text.investment_promise": (
        _p(r"\b(garantili|garanti)\s+(kazanc|getiri|kar|gelir)\w*", H),
        _p(r"\b(gunluk|haftalik|aylik)\s+(%\s?\d+|yuzde\s*\d+)", H),
        _p(r"(%\s?\d+|\byuzde\s*\d+)\s+(gunluk|haftalik|aylik)\b", H),
        _p(r"\b(gunluk|haftalik)\s+(kazanc|getiri|kar)\w*", H),
        _p(r"\b(paran\w*|yatirim\w*)\s+(ikiye|uce|iki katina|katla)\w*", H),
        _p(r"\b(risksiz|zarar etmeden|kayip yasamadan)\w*", M),
        _p(r"\bzarar\s+(riski\s+|ihtimali\s+)?(yok|yoktur|olmaz|olmadan)\b", H),
        _p(r"\b(kazanc|kar|getiri)\w*\s+(%\s?\d+\s+)?(kesin|garantili|garanti)\w*", H),
        _p(r"%\s?\d{2,3}\s+(kazanc|kar|getiri)\w*", M),
        _p(r"\b(yatirim (firsat|grub|danisman)|sinyal (grub|kanal)|borsa (grub|kanal)|hisse (grub|kanal|sinyal)|vip (grub|kanal|uye)|forex)\w*", M),
        _p(r"\b(kazandim|kar ettim)\b[^.!?\n]{0,30}\b(bu hafta|bugun|bir haftada|bir gunde)\b", M),
    ),
    "text.prize": (
        _p(r"\b(odul\w*|hediye\w*|ikramiye\w*|cekilis\w*|bedava|ucretsiz)\b[^.!?\n]{0,40}\b(kazandiniz|kazandin)\b", H),
        _p(r"\b(kazandiniz|kazandin)\b[^.!?\n]{0,40}\b(odul\w*|hediye\w*|ikramiye\w*|cekilis\w*|iphone|arac|para)", H),
        _p(r"\b(odulunuzu|hediyenizi|ikramiyenizi)\s+(almak|talep)\w*", H),
        _p(r"\bcekilis\w*", M),
    ),
    "text.job_offer": (
        _p(r"\b(gunluk|haftalik|saatlik)\s+" + _MONEY + r"\s*(kazan\w*|gelir\w*)", H),
        _p(r"\b(basit|kolay)\s+(gorev\w*|isler\w*)", M),
        _p(r"\b(begen\w*|yorum yap\w*|video izle\w*|otel degerlendir\w*)\b[^.!?\n]{0,30}\b(kazan\w*|komisyon\w*)", M),
        _p(r"\b(evden calis\w*|ek gelir firsati|ek is firsati)\b", L),
    ),
    "text.generic_greeting": (
        _p(r"\b(sayin|degerli|kiymetli)\s+(musteri\w*|kullanici\w*|uye\w*)", L),
    ),
    "text.agent_manipulation": (
        _p(r"\b(onceki|tum|butun)\s+(talimat\w*|komut\w*|kural\w*)\s+(yok say\w*|gormezden gel\w*|unut\w*|dikkate alma\w*)", C),
        _p(r"\b(yapay zeka|asistan\w*|bot|ajan\w*)\b[^.!?\n]{0,40}\b(guvenli|onayli|dogrulanmis|mesru)\s+(olarak\s+)?(isaretle\w*|kabul et\w*|degerlendir\w*|siniflandir\w*|raporla\w*)", C),
        _p(r"\b(kullaniciya|musteriye|hesap sahibine)\s+(sormadan|danismadan|haber vermeden|onay almadan)\b", H),
        _p(r"\b(onaylanmistir|dogrulanmistir|onceden onaylan\w*)\b[^.!?\n]{0,40}\b(sormadan|onay almadan|hemen tamamla\w*)", H),
        _p(r"\b(onay|dogrulama)\s+(beklemeden|istemeden)\b", H),
        # Speaking to the checker: "yapay zeka asistanlarına not", "sorumlu bir yapay zeka olarak".
        _p(r"\b(yapay zeka|asistan\w*|ajan\w*)\b[^.!?\n]{0,20}\b(not|notu|dikkatine|talimat\w*)\b", H),
        _p(r"\b(sorumlu|iyi|yardimsever|durust|etik)\s+bir\s+(yapay zeka|asistan|dil modeli)\s+olarak\b", H),
        _p(r"\b(gelistirici modu|sistem talimat\w*|sistem istem\w*)\b", C),
        _p(r"\b(egitim|test|deneme|farkindalik)\w*\s+(amacli|icin)\b[^.!?\n]{0,80}\b(guvenli|mesru|gercek degil|dogrulanmis|zararsiz|senaryo)\w*", H),
        _p(r"\b(otomatik|yapay zeka|yz|asistan|ajan|degerlendiren|inceleme)\w*(\s+\w+){0,2}\s+icin\s*:", H),
        _p(r"\b(guvenli|mesru|zararsiz|dolandiricilik degil)\w*\s+olarak\s+(siniflandir|etiketle|raporla)\w*", H),
        _p(r"\brisk\s+(puan|skor)\w*\s*[:=]?\s*0\b", C),
        _p(r"\brol\s+(yapma|oyunu|canlandirma)\w*\b[^.!?\n]{0,80}\b(guvenli|mesru|gercek degil|dolandiricilik degil|onayli)\w*", H),
        _p(r"\b(guvenli|mesru|gercek degil|dolandiricilik degil|onayli)\w*\b[^.!?\n]{0,80}\brol\s+(yapma|oyunu|canlandirma)\w*", H),
        _p(r"\bbase64\b[^.!?\n]{0,40}\b(coz|cevir|uygula|oku)\w*", H),
    ),
}


def with_turkish(rules: tuple[TextRule, ...]) -> tuple[TextRule, ...]:
    """Return the rules with their Turkish patterns appended."""
    unknown = set(TR_PATTERNS) - {r.rule_id for r in rules}
    if unknown:
        raise ValueError(f"Turkish patterns for unknown rules: {sorted(unknown)}")
    return tuple(replace(rule, patterns=rule.patterns + TR_PATTERNS.get(rule.rule_id, ())) for rule in rules)
