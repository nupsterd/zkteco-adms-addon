"""Integration tests del endpoint POST /control/enqueue (PR A.1, ADR-076).

Se testea el handler `_handle_control_enqueue` directamente (el server es raw
asyncio TCP: el handler devuelve la respuesta HTTP cruda como str, igual que el
resto de `handle_client`). Asi se evita el TLS y la red real.
"""

import json

import pytest

import server
from command_queue import CommandQueue

TOKEN = "token_de_prueba_largo_y_aleatorio_123456"


def _status_code(raw_response: str) -> int:
    """Extrae el codigo numerico de la status line 'HTTP/1.1 <code> <reason>'."""
    status_line = raw_response.split("\r\n", 1)[0]
    return int(status_line.split(" ")[1])


def _body(raw_response: str) -> str:
    """Devuelve el body (todo lo que sigue al primer '\r\n\r\n')."""
    return raw_response.split("\r\n\r\n", 1)[1]


@pytest.fixture(autouse=True)
def reset_server_state():
    """Estado limpio del modulo server por test (enabled + token + queue fresca)."""
    server._command_queue = CommandQueue()
    server.CONTROL_ENDPOINT_ENABLED = True
    server.CONTROL_ENDPOINT_TOKEN = TOKEN
    yield


def _auth_headers(token: str = TOKEN) -> dict:
    return {"Content-Type": "application/json", "X-Control-Token": token}


async def test_405_when_method_not_post():
    resp = await server._handle_control_enqueue(
        "GET", _auth_headers(), json.dumps({"sn": "SN1", "payload": "CHECK"})
    )
    assert _status_code(resp) == 405


async def test_404_when_endpoint_disabled():
    server.CONTROL_ENDPOINT_ENABLED = False
    resp = await server._handle_control_enqueue(
        "POST", _auth_headers(), json.dumps({"sn": "SN1", "payload": "CHECK"})
    )
    assert _status_code(resp) == 404


async def test_503_when_enabled_but_token_empty():
    server.CONTROL_ENDPOINT_TOKEN = ""
    resp = await server._handle_control_enqueue(
        "POST", {"X-Control-Token": "loquesea"}, json.dumps({"sn": "SN1", "payload": "CHECK"})
    )
    assert _status_code(resp) == 503


async def test_401_when_token_incorrect():
    resp = await server._handle_control_enqueue(
        "POST", _auth_headers("token_incorrecto"), json.dumps({"sn": "SN1", "payload": "CHECK"})
    )
    assert _status_code(resp) == 401


async def test_401_when_token_missing():
    resp = await server._handle_control_enqueue(
        "POST", {"Content-Type": "application/json"}, json.dumps({"sn": "SN1", "payload": "CHECK"})
    )
    assert _status_code(resp) == 401


async def test_400_when_json_malformed():
    resp = await server._handle_control_enqueue("POST", _auth_headers(), "{no es json")
    assert _status_code(resp) == 400


async def test_400_when_sn_empty():
    resp = await server._handle_control_enqueue(
        "POST", _auth_headers(), json.dumps({"sn": "", "payload": "CHECK"})
    )
    assert _status_code(resp) == 400


async def test_400_when_payload_empty():
    resp = await server._handle_control_enqueue(
        "POST", _auth_headers(), json.dumps({"sn": "SN1", "payload": ""})
    )
    assert _status_code(resp) == 400


async def test_400_when_payload_has_forbidden_chars():
    # newline prohibido (rompe la respuesta HTTP cruda / protocolo ADMS).
    resp = await server._handle_control_enqueue(
        "POST", _auth_headers(), json.dumps({"sn": "SN1", "payload": "CHECK\ninjected"})
    )
    assert _status_code(resp) == 400
    assert json.loads(_body(resp))["error"] == "payload_has_forbidden_chars"


async def test_400_when_body_empty():
    resp = await server._handle_control_enqueue("POST", _auth_headers(), "")
    assert _status_code(resp) == 400


async def test_201_when_ok_returns_cmd_id():
    resp = await server._handle_control_enqueue(
        "POST", _auth_headers(), json.dumps({"sn": "UDP3260500207", "payload": "CHECK"})
    )
    assert _status_code(resp) == 201
    payload = json.loads(_body(resp))
    assert payload["cmd_id"] == 1
    assert payload["sn"] == "UDP3260500207"
    assert isinstance(payload["enqueued_at"], str)
    # Y el comando quedo realmente en la cola.
    pending = await server._command_queue.get_next_pending("UDP3260500207")
    assert pending is not None
    assert pending.payload == "CHECK"


async def test_two_identical_requests_create_distinct_commands():
    body = json.dumps({"sn": "SN1", "payload": "CHECK"})
    r1 = await server._handle_control_enqueue("POST", _auth_headers(), body)
    r2 = await server._handle_control_enqueue("POST", _auth_headers(), body)
    id1 = json.loads(_body(r1))["cmd_id"]
    id2 = json.loads(_body(r2))["cmd_id"]
    assert id1 == 1
    assert id2 == 2
    assert id1 != id2


async def test_payload_accepts_real_adms_command():
    # Comando ADMS real: caracteres permitidos por el regex (= , espacio, : ).
    body = json.dumps({"sn": "SN1", "payload": "DATA UPDATE USERINFO PIN=42,Name=Pepito"})
    resp = await server._handle_control_enqueue("POST", _auth_headers(), body)
    assert _status_code(resp) == 201


# ---------------------------------------------------------------------------
# Harness raw-TCP para los handlers inline de handle_client (getrequest /
# devicecmd): se driva handle_client con reader/writer falsos y se captura la
# respuesta HTTP cruda escrita. Evita TLS y red real (mismo espiritu que arriba).
# ---------------------------------------------------------------------------


class _FakeReader:
    def __init__(self, data: bytes):
        self._data = data

    async def read(self, _n: int) -> bytes:
        data, self._data = self._data, b""
        return data


class _FakeWriter:
    def __init__(self):
        self.buf = b""

    def get_extra_info(self, _key):
        return ("127.0.0.1", 12345)

    def write(self, data: bytes):
        self.buf += data

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


def _raw_request(method: str, path: str, body: str = "", headers: dict | None = None) -> bytes:
    lines = [f"{method} {path} HTTP/1.1"]
    for key, val in (headers or {}).items():
        lines.append(f"{key}: {val}")
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines).encode("utf-8")


async def _run_handle_client(raw: bytes) -> str:
    writer = _FakeWriter()
    await server.handle_client(_FakeReader(raw), writer)
    return writer.buf.decode("utf-8")


# --- PR A.2: drain en GET /iclock/getrequest ------------------------------


async def test_getrequest_with_empty_queue_returns_ok():
    resp = await _run_handle_client(_raw_request("GET", "/iclock/getrequest?SN=X"))
    assert _status_code(resp) == 200
    assert _body(resp) == "OK"


async def test_getrequest_with_one_command_returns_C_format():
    cmd = await server._command_queue.enqueue("X", "DATA UPDATE USERINFO PIN=42")
    resp = await _run_handle_client(_raw_request("GET", "/iclock/getrequest?SN=X"))
    assert _body(resp) == f"C:{cmd.cmd_id}:DATA UPDATE USERINFO PIN=42"
    stored = await server._command_queue.get_status(cmd.cmd_id)
    assert stored.delivered_at is not None


async def test_getrequest_serves_two_commands_in_two_polls():
    c1 = await server._command_queue.enqueue("X", "CMD_A")
    c2 = await server._command_queue.enqueue("X", "CMD_B")
    r1 = await _run_handle_client(_raw_request("GET", "/iclock/getrequest?SN=X"))
    r2 = await _run_handle_client(_raw_request("GET", "/iclock/getrequest?SN=X"))
    r3 = await _run_handle_client(_raw_request("GET", "/iclock/getrequest?SN=X"))
    assert _body(r1) == f"C:{c1.cmd_id}:CMD_A"
    assert _body(r2) == f"C:{c2.cmd_id}:CMD_B"
    assert _body(r3) == "OK"


async def test_getrequest_isolation_by_sn():
    cmd = await server._command_queue.enqueue("A", "CMD_A")
    resp_b = await _run_handle_client(_raw_request("GET", "/iclock/getrequest?SN=B"))
    assert _body(resp_b) == "OK"
    resp_a = await _run_handle_client(_raw_request("GET", "/iclock/getrequest?SN=A"))
    assert _body(resp_a) == f"C:{cmd.cmd_id}:CMD_A"


async def test_getrequest_without_sn_does_not_crash():
    resp = await _run_handle_client(_raw_request("GET", "/iclock/getrequest"))
    assert _status_code(resp) == 200
    assert _body(resp) == "OK"


# --- PR A.3: parse ACK en POST /iclock/devicecmd --------------------------


async def test_devicecmd_with_valid_ID_marks_acked_and_stores_response():
    cmd = await server._command_queue.enqueue("X", "CMD_A")
    await server._command_queue.pop_for_delivery("X")
    resp = await _run_handle_client(
        _raw_request("POST", "/iclock/devicecmd?SN=X", body="ID=1&Return=0&CMD=DATA")
    )
    assert _status_code(resp) == 200
    stored = await server._command_queue.get_status(cmd.cmd_id)
    assert stored.acked_at is not None
    assert "ID=1&Return=0&CMD=DATA" in stored.ack_response


async def test_devicecmd_without_ID_logs_warning_no_crash():
    cmd = await server._command_queue.enqueue("X", "CMD_A")
    resp = await _run_handle_client(
        _raw_request("POST", "/iclock/devicecmd?SN=X", body="Return=0&CMD=DATA")
    )
    assert _status_code(resp) == 200
    stored = await server._command_queue.get_status(cmd.cmd_id)
    assert stored.acked_at is None


async def test_devicecmd_with_unknown_cmd_id_does_not_crash():
    cmd = await server._command_queue.enqueue("X", "CMD_A")
    resp = await _run_handle_client(
        _raw_request("POST", "/iclock/devicecmd?SN=X", body="ID=999&Return=0")
    )
    assert _status_code(resp) == 200
    stored = await server._command_queue.get_status(cmd.cmd_id)
    assert stored.acked_at is None


async def test_devicecmd_with_empty_body_does_not_crash():
    resp = await _run_handle_client(_raw_request("POST", "/iclock/devicecmd?SN=X", body=""))
    assert _status_code(resp) == 200


# --- PR A.3: GET /control/status ------------------------------------------


async def test_control_status_returns_200_with_full_dict():
    cmd = await server._command_queue.enqueue("SN1", "CHECK")
    resp = await server._handle_control_status("GET", _auth_headers(), {"cmd_id": str(cmd.cmd_id)})
    assert _status_code(resp) == 200
    payload = json.loads(_body(resp))
    for key in ("cmd_id", "sn", "payload", "enqueued_at", "delivered_at", "acked_at", "ack_response"):
        assert key in payload
    assert payload["cmd_id"] == cmd.cmd_id


async def test_control_status_returns_404_for_unknown_cmd_id():
    resp = await server._handle_control_status("GET", _auth_headers(), {"cmd_id": "99999"})
    assert _status_code(resp) == 404
    assert json.loads(_body(resp))["error"] == "cmd_id_not_found"


async def test_control_status_returns_400_missing_cmd_id():
    resp = await server._handle_control_status("GET", _auth_headers(), {})
    assert _status_code(resp) == 400
    assert json.loads(_body(resp))["error"] == "missing_cmd_id"


async def test_control_status_returns_400_invalid_cmd_id():
    resp = await server._handle_control_status("GET", _auth_headers(), {"cmd_id": "abc"})
    assert _status_code(resp) == 400
    assert json.loads(_body(resp))["error"] == "invalid_cmd_id"


async def test_control_status_returns_401_without_token():
    resp = await server._handle_control_status(
        "GET", {"Content-Type": "application/json"}, {"cmd_id": "1"}
    )
    assert _status_code(resp) == 401


async def test_control_status_returns_401_with_wrong_token():
    resp = await server._handle_control_status(
        "GET", _auth_headers("token_incorrecto"), {"cmd_id": "1"}
    )
    assert _status_code(resp) == 401


async def test_control_status_returns_404_when_disabled():
    server.CONTROL_ENDPOINT_ENABLED = False
    resp = await server._handle_control_status("GET", _auth_headers(), {"cmd_id": "1"})
    assert _status_code(resp) == 404


async def test_control_status_returns_503_when_enabled_but_token_empty():
    server.CONTROL_ENDPOINT_TOKEN = ""
    resp = await server._handle_control_status(
        "GET", {"X-Control-Token": "loquesea"}, {"cmd_id": "1"}
    )
    assert _status_code(resp) == 503


async def test_control_status_returns_405_on_post():
    resp = await server._handle_control_status("POST", _auth_headers(), {"cmd_id": "1"})
    assert _status_code(resp) == 405
