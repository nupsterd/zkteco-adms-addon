"""Tests del fix §5.9.292: handle_client Content-Length aware HTTP read.

Bug: reader.read(8192) NO respetaba Content-Length, fallaba con clientes que
separan headers y body en TCP writes distintos (httpx con json=). Sintoma:
400 invalid_json aleatorio.

Estos tests drivan `handle_client` con reader/writer falsos (mismo espiritu que
el harness raw-TCP de test_server_control_endpoint.py) pero el reader entrega
los datos en chunks separados para reproducir la fragmentacion TCP.
"""

import json

import pytest

import server
from command_queue import CommandQueue

TOKEN = "token_de_prueba_largo_y_aleatorio_123456"


@pytest.fixture(autouse=True)
def reset_server_state():
    """Estado limpio del modulo server por test (enabled + token + queue fresca)."""
    server._command_queue = CommandQueue()
    server.CONTROL_ENDPOINT_ENABLED = True
    server.CONTROL_ENDPOINT_TOKEN = TOKEN
    yield


class _MockReader:
    """Reader mock que entrega datos en chunks separados (simula fragmentacion TCP).

    Respeta el parametro `n` de read(): si un chunk es mas grande que n, devuelve
    solo n bytes y guarda el resto para la proxima lectura.
    """

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
    """Writer mock que captura lo escrito y registra si se cerro la conexion."""

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
        if key == "peername":
            return ("127.0.0.1", 12345)
        return None


def _auth_request_bytes(body: str) -> bytes:
    """POST /control/enqueue con headers + Content-Length correctos."""
    return (
        f"POST /control/enqueue HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Type: application/json\r\n"
        f"X-Control-Token: {TOKEN}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
        f"{body}"
    ).encode()


async def test_handle_client_lee_body_completo_cuando_llega_en_un_chunk():
    """Caso base: curl/MB10-VL envia headers+body en un solo write."""
    body = json.dumps({"sn": "UDP3260500207", "payload": "DATA QUERY USERINFO PIN=1"})
    reader = _MockReader([_auth_request_bytes(body)])
    writer = _MockWriter()

    await server.handle_client(reader, writer)

    # El body completo debe haberse parseado => 201 (no 400 invalid_json).
    assert b"201" in writer.written
    assert b"invalid_json" not in writer.written


async def test_handle_client_lee_body_completo_cuando_llega_separado_de_headers():
    """Caso bug §5.9.292: httpx separa headers y body en TCP writes distintos."""
    body = json.dumps({"sn": "UDP3260500207", "payload": "DATA QUERY USERINFO PIN=1"})
    headers_chunk = (
        f"POST /control/enqueue HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Type: application/json\r\n"
        f"X-Control-Token: {TOKEN}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode()
    body_chunk = body.encode()

    reader = _MockReader([headers_chunk, body_chunk])  # 2 chunks separados
    writer = _MockWriter()

    await server.handle_client(reader, writer)

    # ANTES del fix: 400 invalid_json. Despues del fix: 201 OK.
    assert b"201" in writer.written
    assert b"invalid_json" not in writer.written


async def test_handle_client_get_sin_body_funciona():
    """GET sin Content-Length / sin body no debe esperar bytes."""
    reader = _MockReader([b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n"])
    writer = _MockWriter()

    await server.handle_client(reader, writer)

    assert b"200 OK" in writer.written


async def test_handle_client_cdata_grande_se_lee_completo():
    """Regresion M2: cdata del MB10-VL con body grande (>8192 bytes) debe leerse completo.

    Antes del fix, bodies grandes se truncaban silenciosamente (read(8192)).
    """
    attlog_line = "1\t2026-06-24 20:00:00\t1\t1\t0\t0\n"
    body = attlog_line * 600  # ~18 KB
    request = (
        f"POST /iclock/cdata?SN=UDP_TEST&table=ATTLOG HTTP/1.1\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
        f"{body}"
    ).encode()
    # 3 chunks: header+body fragmentados (cubre el camino del while de body).
    reader = _MockReader([request[:5000], request[5000:10000], request[10000:]])
    writer = _MockWriter()

    await server.handle_client(reader, writer)

    assert b"200 OK" in writer.written


async def test_handle_client_headers_too_large_cierra_conexion():
    """Defensa anti-DOS: headers >65536 bytes cierran la conexion."""
    huge_headers = b"X-Garbage: " + b"A" * 70000 + b"\r\n\r\n"
    reader = _MockReader([huge_headers])
    writer = _MockWriter()

    await server.handle_client(reader, writer)

    assert writer.closed
    # No debe haber response porque la conexion se cerro antes de parsear.
    assert b"200" not in writer.written


async def test_handle_client_content_length_negativo_rechazado():
    """Defensa: Content-Length negativo rechaza la conexion."""
    reader = _MockReader([b"POST /control/enqueue HTTP/1.1\r\nContent-Length: -100\r\n\r\n"])
    writer = _MockWriter()

    await server.handle_client(reader, writer)

    assert writer.closed
    assert writer.written == b""


async def test_handle_client_content_length_excesivo_rechazado():
    """Defensa: Content-Length >10MiB rechaza la conexion sin intentar leer el body."""
    reader = _MockReader([b"POST /control/enqueue HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n"])
    writer = _MockWriter()

    await server.handle_client(reader, writer)

    assert writer.closed
    assert writer.written == b""
