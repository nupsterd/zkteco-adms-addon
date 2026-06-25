"""Tests de los parsers puros OPERLOG/USER/FP (PR A.4, Chat 4a S8).

Samples literales capturados Chat 4a 2026-06-25 (§2.4 del prompt PR A.4).
"""

from operlog_parser import (
    classify_operlog_line,
    parse_fp_template,
    parse_oplog_line,
    parse_user_snapshot,
)

# --- Samples literales (§2.4) -------------------------------------------------
OPLOG_30 = "OPLOG 30\t0\t2026-06-25 16:28:28\t4\t0\t0\t0"
OPLOG_9 = "OPLOG 9\t0\t2026-06-25 16:29:14\t4\t0\t0\t0"
OPLOG_6 = "OPLOG 6\t0\t2026-06-25 16:28:28\t4\t0\t0\t0"
OPLOG_4 = "OPLOG 4\t3\t2026-06-25 16:27:43\t3\t0\t0\t0"
OPLOG_70 = "OPLOG 70\t0\t2026-06-25 16:28:10\t4\t0\t0\t0"
USER_SNAPSHOT = (
    "USER PIN=4\tName=User3\tPri=0\tPasswd=<REDACTED>\tCard=\tGrp=1"
    "\tTZ=0000000100000000\tVerify=1\tViceCard=\tStartDatetime=0\tEndDatetime=0"
)
# tmp_b64 mock >1KB para validar que no se trunca (Test 11).
_FP_TMP = "QUJD" * 400  # 1600 chars
FP_TEMPLATE = f"FP PIN=4\tFID=6\tSize=1488\tValid=1\tTMP={_FP_TMP}"


# --- Test 1/2/3: OPLOG forwardeables ------------------------------------------
def test_parse_oplog_30_modify_completo():
    assert parse_oplog_line(OPLOG_30) == {
        "tipo": "oplog_30",
        "oplog_code": 30,
        "param": 0,
        "device_ts": "2026-06-25 16:28:28",
        "pin": 4,
        "raw_extra": ["0", "0", "0"],
    }


def test_parse_oplog_9_delete():
    parsed = parse_oplog_line(OPLOG_9)
    assert parsed["tipo"] == "oplog_9"
    assert parsed["oplog_code"] == 9
    assert parsed["device_ts"] == "2026-06-25 16:29:14"
    assert parsed["pin"] == 4


def test_parse_oplog_6_post_fp_commit():
    parsed = parse_oplog_line(OPLOG_6)
    assert parsed["tipo"] == "oplog_6"
    assert parsed["oplog_code"] == 6
    assert parsed["device_ts"] == "2026-06-25 16:28:28"


# --- Test 4/5: OPLOG descartados (lista negativa D2) --------------------------
def test_parse_oplog_4_admin_login_filtrado():
    assert parse_oplog_line(OPLOG_4) is None


def test_parse_oplog_70_precommit_filtrado():
    assert parse_oplog_line(OPLOG_70) is None


# --- Test 6/7: no-OPLOG / malformed -------------------------------------------
def test_parse_oplog_attlog_no_matchea():
    assert parse_oplog_line("1\t2026-06-25 16:00:00\t0\t1") is None
    assert parse_oplog_line("ATTLOG 1\t0\t2026-06-25 16:00:00\t4") is None


def test_parse_oplog_malformed_retorna_none():
    assert parse_oplog_line("") is None
    assert parse_oplog_line("OPLOG") is None
    assert parse_oplog_line("OPLOG abc\t0\t2026\t4") is None
    assert parse_oplog_line("OPLOG 30") is None  # sin campos suficientes


# --- Test 8/9: USER snapshot --------------------------------------------------
def test_parse_user_snapshot_diez_campos():
    parsed = parse_user_snapshot(USER_SNAPSHOT)
    assert parsed["tipo"] == "user_snapshot"
    assert parsed["pin"] == 4
    assert parsed["fields"] == {
        "name": "User3",
        "pri": "0",
        "passwd": "<REDACTED>",
        "card": "",
        "grp": "1",
        "tz": "0000000100000000",
        "verify": "1",
        "vice_card": "",
        "start_datetime": "0",
        "end_datetime": "0",
    }


def test_parse_user_snapshot_preserva_redacted():
    parsed = parse_user_snapshot(USER_SNAPSHOT)
    assert parsed["fields"]["passwd"] == "<REDACTED>"


def test_parse_user_snapshot_no_matchea_otras_lineas():
    assert parse_user_snapshot(OPLOG_30) is None
    assert parse_user_snapshot("") is None


# --- Test 10/11: FP template --------------------------------------------------
def test_parse_fp_template_completo():
    parsed = parse_fp_template(FP_TEMPLATE)
    assert parsed["tipo"] == "fingerprint_template"
    assert parsed["pin"] == 4
    assert parsed["fid"] == 6
    assert parsed["size"] == 1488
    assert parsed["valid"] == 1


def test_parse_fp_template_no_trunca_tmp():
    parsed = parse_fp_template(FP_TEMPLATE)
    assert parsed["tmp_b64"] == _FP_TMP
    assert len(parsed["tmp_b64"]) > 1024


def test_parse_fp_template_preserva_padding_base64():
    # base64 con '=' de padding: split por primer '=' debe preservar el resto.
    line = "FP PIN=7\tFID=1\tSize=10\tValid=1\tTMP=QUJDRA=="
    parsed = parse_fp_template(line)
    assert parsed["tmp_b64"] == "QUJDRA=="


def test_parse_fp_template_malformed_retorna_none():
    assert parse_fp_template("FP PIN=4\tFID=6") is None  # faltan Size/Valid
    assert parse_fp_template(OPLOG_30) is None


# --- Test 12: classify_operlog_line -------------------------------------------
def test_classify_clasifica_las_cinco_variedades():
    assert classify_operlog_line(OPLOG_30)[0] == "oplog_30"
    assert classify_operlog_line(OPLOG_9)[0] == "oplog_9"
    assert classify_operlog_line(OPLOG_6)[0] == "oplog_6"
    assert classify_operlog_line(USER_SNAPSHOT)[0] == "user_snapshot"
    assert classify_operlog_line(FP_TEMPLATE)[0] == "fingerprint_template"


def test_classify_retorna_tupla_tipo_y_dict():
    tipo, parsed = classify_operlog_line(OPLOG_30)
    assert tipo == "oplog_30"
    assert parsed["pin"] == 4


def test_classify_none_para_descartados_y_basura():
    assert classify_operlog_line(OPLOG_4) is None
    assert classify_operlog_line(OPLOG_70) is None
    assert classify_operlog_line("1\t2026-06-25 16:00:00\t0\t1") is None
    assert classify_operlog_line("") is None
    assert classify_operlog_line("basura random sin formato") is None
