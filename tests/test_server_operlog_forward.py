"""Tests de integracion del forward OPERLOG/USER/FP en server.py (PR A.4).

Cubre los 3 ajustes del RFC aprobado Chat 4a:
  - feature flag (3 sub-tests dedicados: off / forwarder None / on operativo),
  - robustez ante enqueue raise inesperado (handler nunca propaga al MB10-VL),
  - seguridad: Passwd se redacta ANTES de forwardear.
Reusa el harness raw-TCP (_MockReader/_MockWriter) del fix §5.9.292.
"""

import logging

import pytest

import server
from command_queue import CommandQueue

OPLOG_30 = "OPLOG 30\t0\t2026-06-25 16:28:28\t4\t0\t0\t0"
SN = "UDP3260500207"


class _FakeForwarder:
    """Forwarder mock: registra los records encolados; opcionalmente raisea."""

    def __init__(self, raises: bool = False):
        self.calls: list[dict] = []
        self._raises = raises

    async def enqueue(self, record: dict) -> None:
        self.calls.append(record)
        if self._raises:
            raise RuntimeError("enqueue boom inesperado")


@pytest.fixture(autouse=True)
def reset_server_state():
    """Restaura los globals de server tocados por estos tests."""
    prev_flag = server.FORWARD_OPERLOG_ENABLED
    prev_fwd = server._forwarder
    server._command_queue = CommandQueue()
    yield
    server.FORWARD_OPERLOG_ENABLED = prev_flag
    server._forwarder = prev_fwd


class _MockReader:
    def __init__(self, chunks):
        self._chunks = list(chunks)
        self._buffer = b""

    async def read(self, n: int) -> bytes:
        if self._buffer:
            ret = self._buffer[:n]
            self._buffer = self._buffer[n:]
            return ret
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if len(chunk) <= n:
            return chunk
        self._buffer = chunk[n:]
        return chunk[:n]


class _MockWriter:
    def __init__(self):
        self.written = b""
        self.closed = False

    def write(self, data: bytes):
        self.written += data

    def close(self):
        self.closed = True

    async def drain(self):
        pass

    async def wait_closed(self):
        pass

    def get_extra_info(self, key: str):
        return ("127.0.0.1", 12345) if key == "peername" else None


def _cdata_request(body: str, sn: str = SN) -> bytes:
    """POST /iclock/cdata?SN=<sn> con Content-Length correcto."""
    body_b = body.encode()
    return (
        f"POST /iclock/cdata?SN={sn} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Length: {len(body_b)}\r\n"
        f"\r\n"
    ).encode() + body_b


# --- Ajuste 2: feature flag (3 sub-tests dedicados) ---------------------------
async def test_flag_off_no_enquela():
    """Flag off + forwarder OK => enqueue NO se llama."""
    fwd = _FakeForwarder()
    server.FORWARD_OPERLOG_ENABLED = False
    server._forwarder = fwd
    await server._maybe_forward_operlog(SN, OPLOG_30)
    assert fwd.calls == []


async def test_flag_on_forwarder_none_no_enquela_log_debug(caplog):
    """Flag on + forwarder None (sin url/token) => no enqueue, log DEBUG."""
    server.FORWARD_OPERLOG_ENABLED = True
    server._forwarder = None
    with caplog.at_level(logging.DEBUG, logger="server"):
        await server._maybe_forward_operlog(SN, OPLOG_30)
    assert any("operlog_forward_skipped_forwarder_none" in r.message for r in caplog.records)


async def test_flag_on_forwarder_operativo_enquela_record_correcto():
    """Flag on + forwarder operativo => enqueue con el record unificado correcto."""
    fwd = _FakeForwarder()
    server.FORWARD_OPERLOG_ENABLED = True
    server._forwarder = fwd
    await server._maybe_forward_operlog(SN, OPLOG_30)
    assert len(fwd.calls) == 1
    record = fwd.calls[0]
    assert record["device_sn"] == SN
    assert record["event"]["tipo"] == "oplog_30"
    assert record["event"]["oplog_code"] == 30
    assert record["event"]["pin"] == 4


# --- Ajuste 3: robustez ante enqueue raise ------------------------------------
async def test_enqueue_raise_no_propaga_unit():
    """_maybe_forward_operlog NO propaga si enqueue raisea (loggea ERROR)."""
    fwd = _FakeForwarder(raises=True)
    server.FORWARD_OPERLOG_ENABLED = True
    server._forwarder = fwd
    # No debe levantar.
    await server._maybe_forward_operlog(SN, OPLOG_30)
    assert len(fwd.calls) == 1  # se intento encolar


async def test_handle_client_enqueue_raise_responde_200():
    """handler /iclock/cdata sigue respondiendo 200 aunque enqueue raisee."""
    server.FORWARD_OPERLOG_ENABLED = True
    server._forwarder = _FakeForwarder(raises=True)
    reader = _MockReader([_cdata_request(OPLOG_30)])
    writer = _MockWriter()
    await server.handle_client(reader, writer)
    assert b"200" in writer.written


# --- Test 17: integracion end-to-end ------------------------------------------
async def test_handle_client_cdata_oplog_forwardea():
    """POST /iclock/cdata con OPLOG 30 => enqueue con record correcto (flag on)."""
    fwd = _FakeForwarder()
    server.FORWARD_OPERLOG_ENABLED = True
    server._forwarder = fwd
    reader = _MockReader([_cdata_request(OPLOG_30)])
    writer = _MockWriter()
    await server.handle_client(reader, writer)
    assert b"200" in writer.written
    assert len(fwd.calls) == 1
    ev = fwd.calls[0]["event"]
    assert ev["tipo"] == "oplog_30"
    assert ev["device_ts"] == "2026-06-25 16:28:28"
    assert fwd.calls[0]["device_sn"] == SN


async def test_handle_client_cdata_flag_off_no_forwardea():
    """Integracion: con flag off, una linea OPLOG no se forwardea (merge seguro)."""
    fwd = _FakeForwarder()
    server.FORWARD_OPERLOG_ENABLED = False
    server._forwarder = fwd
    reader = _MockReader([_cdata_request(OPLOG_30)])
    writer = _MockWriter()
    await server.handle_client(reader, writer)
    assert b"200" in writer.written
    assert fwd.calls == []


# --- Seguridad: redaccion de Passwd antes de forwardear -----------------------
async def test_forward_redacta_passwd_antes_de_enquela():
    """Un USER snapshot con Passwd en texto plano se redacta ANTES de forwardear."""
    fwd = _FakeForwarder()
    server.FORWARD_OPERLOG_ENABLED = True
    server._forwarder = fwd
    user_plain = (
        "USER PIN=4\tName=User3\tPri=0\tPasswd=secreto123\tCard=\tGrp=1"
        "\tTZ=0\tVerify=1\tViceCard=\tStartDatetime=0\tEndDatetime=0"
    )
    await server._maybe_forward_operlog(SN, user_plain)
    assert len(fwd.calls) == 1
    ev = fwd.calls[0]["event"]
    assert ev["fields"]["passwd"] == "<REDACTED>"
    assert "secreto123" not in fwd.calls[0]["event"]["raw_line"]
