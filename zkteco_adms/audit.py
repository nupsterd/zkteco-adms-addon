"""Audit log local en JSON Lines para el add-on ZKTeco ADMS (v1.7.0).

Paridad arquitectonica con el add-on Hikvision (ADR-004 Opcion C): TODOS los
eventos se persisten localmente ANTES del fan-out al backend, asi el audit local
es la red de seguridad / fuente de reconciliacion si el fan-out cae.

Asyncio-nativo (el server.py es full asyncio): usa ``aiofiles`` para no bloquear
el event loop. Fail-silent total: si la escritura falla, loguea y CONTINUA
(jamas rompe el flujo principal ni el reenvio a HA).
"""

import json
import logging
import os

import aiofiles

logger = logging.getLogger(__name__)


class AuditLogger:
    """Escribe records (dict) como JSON Lines a un archivo local."""

    def __init__(self, path: str):
        self._path = path
        # Asegura el directorio una sola vez (sync, en el arranque).
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    async def write(self, record: dict) -> None:
        """Append de una linea JSON. Nunca levanta (fail-silent)."""
        try:
            async with aiofiles.open(self._path, "a", encoding="utf-8") as fh:
                await fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            logger.exception("AuditLogger write failed (continuing)")
