import pytest

from trustgate.lang import is_turkish


@pytest.mark.parametrize("text", [
    "Anne selam, telefonum bozuldu, bu yeni numaram.",
    "Kuzeybank: 482913 doğrulama kodunuzdur. Bu kodu kimseyle paylaşmayın.",
    "anne bu yeni numaram acil para lazim kimseye soyleme",  # typed without Turkish letters
    "TELEFONUNUZA GELEN KODU SÖYLEYİN",
])
def test_detects_turkish(text):
    assert is_turkish(text)


@pytest.mark.parametrize("text", [
    "Hi Mum, my phone broke so this is my new number. Can you send me £400?",
    "Your parcel is waiting. Pay the customs fee at https://parcel.example/pay",
    "Ok da, see you tomorrow at the station",  # one shared short word is not enough
    "",
    "123456",
])
def test_does_not_flag_other_text(text):
    assert not is_turkish(text)
