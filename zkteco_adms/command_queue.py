"""CommandQueue in-memory para comandos ADMS dirigidos al device (PR A.1, ADR-076).

El MB10-VL es 1-way push por diseno (§5.9.252): el server NO puede activar
hardware, pero SI puede inyectar comandos ADMS estandar (`DATA UPDATE/DELETE
USERINFO`, etc.) que el device drena al polear `GET /iclock/getrequest`.

Este modulo es la pieza encolable AISLADA del flow: PR A.1 solo encola y expone
estado. El drain en `getrequest` es PR A.2 y el parseo de ACK en `devicecmd` es
PR A.3. Por eso `get_next_pending` / `mark_delivered` / `mark_acked` ya existen
pero todavia no se cablean al handler.

Diseno deliberado (§5.9.253): dict in-memory keyed por SN protegido por un
`asyncio.Lock` global, SIN persistencia entre restarts. El backend es la fuente
de verdad (ADR-066): si el add-on reinicia, los comandos no entregados se
re-encolan desde el backend al detectar timeout. Simplicidad sobre durabilidad.
"""

import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class Command:
    """Comando ADMS encolado para un device.

    El `payload` es el comando ZK literal SIN el prefijo `C:<id>:` — ese prefijo
    lo agrega el add-on al servir el comando en `getrequest` (PR A.2), usando el
    `cmd_id` para correlacionar el ACK del device (PR A.3).
    """

    cmd_id: int                       # ID unico asignado por el add-on (autoincrement in-memory)
    sn: str                           # SN del device destino
    payload: str                      # comando ZK literal sin el prefijo "C:<id>:"
    enqueued_at: datetime             # cuando entro al queue
    delivered_at: datetime | None = None  # cuando fue servido en getrequest (None = no entregado)
    acked_at: datetime | None = None      # cuando llego el ACK del device (None = no ACKeado)

    def to_dict(self) -> dict:
        """Serializacion JSON-friendly (timestamps a ISO 8601)."""
        return {
            "cmd_id": self.cmd_id,
            "sn": self.sn,
            "payload": self.payload,
            "enqueued_at": self.enqueued_at.isoformat(),
            "delivered_at": self.delivered_at.isoformat() if self.delivered_at else None,
            "acked_at": self.acked_at.isoformat() if self.acked_at else None,
        }


class CommandQueue:
    """Cola in-memory de comandos ADMS keyed por SN del device.

    Thread/task-safe via un unico `asyncio.Lock` global (el server.py es full
    asyncio, no hay threads). Sin persistencia: ver docstring del modulo.
    """

    def __init__(self):
        # Una deque FIFO por SN. defaultdict para no chequear existencia al encolar.
        self._queues: dict[str, deque] = defaultdict(deque)
        # Indice plano cmd_id -> Command para lookups O(1) en mark_*/get_status.
        self._by_id: dict[int, Command] = {}
        # Contador autoincrement global (unico across SNs).
        self._next_cmd_id = 0
        self._lock = asyncio.Lock()

    async def enqueue(self, sn: str, payload: str) -> Command:
        """Agrega un comando al queue del SN y retorna el Command con cmd_id asignado."""
        async with self._lock:
            self._next_cmd_id += 1
            cmd = Command(
                cmd_id=self._next_cmd_id,
                sn=sn,
                payload=payload,
                enqueued_at=datetime.now(),
            )
            self._queues[sn].append(cmd)
            self._by_id[cmd.cmd_id] = cmd
            return cmd

    async def get_next_pending(self, sn: str) -> Command | None:
        """Retorna el siguiente comando NO entregado del SN (FIFO), sin marcarlo.

        El marcado como entregado lo hara PR A.2 (drain en getrequest) llamando a
        `mark_delivered` recien cuando el comando se escriba en la respuesta.
        """
        async with self._lock:
            for cmd in self._queues.get(sn, ()):
                if cmd.delivered_at is None:
                    return cmd
            return None

    async def mark_delivered(self, cmd_id: int) -> None:
        """Marca un comando como entregado (servido en getrequest). Idempotente."""
        async with self._lock:
            cmd = self._by_id.get(cmd_id)
            if cmd is not None and cmd.delivered_at is None:
                cmd.delivered_at = datetime.now()

    async def mark_acked(self, cmd_id: int) -> None:
        """Marca un comando como ACKeado por el device. Idempotente."""
        async with self._lock:
            cmd = self._by_id.get(cmd_id)
            if cmd is not None and cmd.acked_at is None:
                cmd.acked_at = datetime.now()

    async def get_status(self, cmd_id: int) -> Command | None:
        """Retorna el Command (para el endpoint /control/status de PR A.3) o None."""
        async with self._lock:
            return self._by_id.get(cmd_id)
