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
