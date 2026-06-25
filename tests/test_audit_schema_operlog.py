"""Tests de los builders del schema unificado para OPERLOG/USER/FP (PR A.4).

Validan que el record emitido es consumible por el ``parse_event`` del backend
(schema anidado: root con device_sn/received_ts; event.tipo canonico).
"""

import pytest

from audit_schema import (
    build_fp_template_record,
    build_operlog_record,
    build_oplog_record,
    build_user_snapshot_record,
)
from operlog_parser import (
    parse_fp_template,
    parse_oplog_line,
    parse_user_snapshot,
)

SN = "UDP3260500207"
OPLOG_30 = "OPLOG 30\t0\t2026-06-25 16:28:28\t4\t0\t0\t0"
USER_SNAPSHOT = (
    "USER PIN=4\tName=User3\tPri=0\tPasswd=<REDACTED>\tCard=\tGrp=1"
    "\tTZ=0000000100000000\tVerify=1\tViceCard=\tStartDatetime=0\tEndDatetime=0"
)
FP_TEMPLATE = "FP PIN=4\tFID=6\tSize=1488\tValid=1\tTMP=" + "QUJD" * 400


def _assert_envelope(record, sn):
    """Invariantes del sobre raiz comun (consumible por parse_event del backend)."""
    assert record["schema_version"] == "1.0"
    assert record["device_brand"] == "zkteco"
    assert record["device_model"] == "MB10-VL"
    assert record["device_sn"] == sn
    assert record["device_mac"] is None
    assert "received_ts" in record and record["received_ts"]
    assert isinstance(record["event"], dict)


def test_build_oplog_record_shape_unificado():
    parsed = parse_oplog_line(OPLOG_30)
    record = build_oplog_record(SN, parsed, OPLOG_30)
    _assert_envelope(record, SN)
    ev = record["event"]
    assert ev["tipo"] == "oplog_30"
    assert ev["oplog_code"] == 30
    assert ev["device_ts"] == "2026-06-25 16:28:28"
    assert ev["pin"] == 4
    assert ev["raw_extra"] == ["0", "0", "0"]
    assert ev["raw_line"] == OPLOG_30
    # OPLOG trae device_ts estable => NO es inferido (idempotencia B.3 lo usa).
    assert ev["inferred_timestamp"] is False


def test_build_user_snapshot_record_inferred_y_passwd_redactado():
    parsed = parse_user_snapshot(USER_SNAPSHOT)
    record = build_user_snapshot_record(SN, parsed, USER_SNAPSHOT)
    _assert_envelope(record, SN)
    ev = record["event"]
    assert ev["tipo"] == "user_snapshot"
    assert ev["pin"] == 4
    assert ev["fields"]["passwd"] == "<REDACTED>"
    assert ev["device_ts"] is None
    # USER snapshot sin device_ts => timestamp inferido (wall clock B.3).
    assert ev["inferred_timestamp"] is True


def test_build_fp_template_record_preserva_tmp():
    parsed = parse_fp_template(FP_TEMPLATE)
    record = build_fp_template_record(SN, parsed, FP_TEMPLATE)
    _assert_envelope(record, SN)
    ev = record["event"]
    assert ev["tipo"] == "fingerprint_template"
    assert ev["fid"] == 6
    assert ev["size"] == 1488
    assert ev["valid"] == 1
    assert ev["tmp_b64"] == "QUJD" * 400
    assert ev["device_ts"] is None
    assert ev["inferred_timestamp"] is True


def test_build_operlog_record_dispatcher_por_tipo():
    # Dispatcher elige el builder correcto segun parsed["tipo"].
    oplog = build_operlog_record(SN, parse_oplog_line(OPLOG_30), OPLOG_30)
    user = build_operlog_record(SN, parse_user_snapshot(USER_SNAPSHOT), USER_SNAPSHOT)
    fp = build_operlog_record(SN, parse_fp_template(FP_TEMPLATE), FP_TEMPLATE)
    assert oplog["event"]["tipo"] == "oplog_30"
    assert user["event"]["tipo"] == "user_snapshot"
    assert fp["event"]["tipo"] == "fingerprint_template"


def test_build_operlog_record_tipo_desconocido_raisea():
    with pytest.raises(ValueError):
        build_operlog_record(SN, {"tipo": "marciano"}, "raw")
