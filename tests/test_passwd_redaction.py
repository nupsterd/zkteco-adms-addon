"""Unit tests de la redaccion del campo Passwd= en logs (§5.9.260, PR A.1)."""

from server import redact_passwd

# Snapshot USER tipico que el MB10-VL pushea antes del OPLOG de USER ADD/MODIFY.
USER_PACKET = (
    "USER PIN=42\tName=Pepito\tPri=0\tPasswd=secreto123\tCard=0\tGrp=1\t"
    "TZ=0\tVerify=0\tViceCard=\tStartDatetime=0\tEndDatetime=0"
)


def test_redacts_passwd_value():
    out = redact_passwd(USER_PACKET)
    assert "Passwd=<REDACTED>" in out
    assert "secreto123" not in out


def test_redaction_preserves_other_fields():
    out = redact_passwd(USER_PACKET)
    assert "PIN=42" in out
    assert "Name=Pepito" in out
    assert "Card=0" in out


def test_packet_without_passwd_unchanged():
    text = "1\t2026-06-24 10:00:00\t0\t1"
    assert redact_passwd(text) == text


def test_empty_passwd_stays_unchanged():
    # Decision de diseno: Passwd vacio no se toca (no hay secreto que filtrar).
    text = "USER PIN=42\tName=Pepito\tPasswd=\tCard=0"
    assert redact_passwd(text) == text
    assert "Passwd=<REDACTED>" not in redact_passwd(text)


def test_passwd_with_special_chars_redacted():
    text = "USER PIN=7\tPasswd=p@ss-w0rd.!\tCard=0"
    out = redact_passwd(text)
    # El valor original desaparece y queda el placeholder.
    assert "p@ss-w0rd" not in out
    assert "Passwd=<REDACTED>" in out
    # El campo siguiente (Card) se conserva.
    assert "Card=0" in out


def test_passwd_at_end_of_line():
    text = "USER PIN=7\tName=X\tPasswd=ultimo"
    out = redact_passwd(text)
    assert out.endswith("Passwd=<REDACTED>")


def test_empty_string_returns_empty():
    assert redact_passwd("") == ""
