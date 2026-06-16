"""Fan-out async de audit records al backend pv-backend (v1.7.0).

BackendForwarder asyncio-nativo (ADR-032): el server.py de ZKTeco es full
asyncio, asi que el patron natural es asyncio.Queue + asyncio.create_task +
aiohttp.ClientSession (NO thread+queue como el Hikvision v1.2.0, que es sync).
Mismo contrato conceptual: opt-in, reintentos con backoff, drop si la cola se
llena, fail-silent total.
"""

import asyncio
import logging

import aiohttp

logger = logging.getLogger(__name__)


class BackendForwarder:
    """Fan-out async de audit records al backend pv-backend.

    Patron analogo al BackendForwarder del Hikvision v1.2.0 pero asyncio-nativo
    (el server.py de ZKTeco es full asyncio, no sync).
    """

    def __init__(self, url: str, token: str, queue_maxsize: int, timeout_seconds: float):
        self._url = url
        self._token = token
        self._timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=queue_maxsize)
        self._session: aiohttp.ClientSession | None = None
        self._task: asyncio.Task | None = None
        self._enabled = bool(url) and bool(token)

    async def start(self) -> None:
        if not self._enabled:
            logger.info("BackendForwarder disabled (no url or token configured)")
            return
        self._session = aiohttp.ClientSession(timeout=self._timeout)
        self._task = asyncio.create_task(self._worker_loop(), name="zkteco_forwarder")
        logger.info(f"BackendForwarder enabled -> {self._url}")

    async def enqueue(self, record: dict) -> None:
        if not self._enabled or self._task is None:
            return
        try:
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            logger.warning("BackendForwarder queue full, dropping record")

    async def _worker_loop(self) -> None:
        while True:
            try:
                record = await self._queue.get()
                await self._post_with_retries(record)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Unexpected error in BackendForwarder worker loop")

    async def _post_with_retries(self, record: dict) -> None:
        assert self._session is not None
        backoffs = [0, 0.5, 1.0, 2.0]  # 4 intentos: immediate + 3 retries
        for attempt, delay in enumerate(backoffs):
            if delay > 0:
                await asyncio.sleep(delay)
            try:
                async with self._session.post(
                    self._url,
                    json=record,
                    headers={"X-PV-ZKTeco-Token": self._token},
                ) as resp:
                    if 200 <= resp.status < 300:
                        return
                    if 400 <= resp.status < 500:
                        text = await resp.text()
                        logger.error(f"BackendForwarder 4xx (no retry): {resp.status} {text[:200]}")
                        return
                    logger.warning(f"BackendForwarder 5xx attempt {attempt + 1}: {resp.status}")
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"BackendForwarder error attempt {attempt + 1}: {e}")
        logger.error(f"BackendForwarder gave up after {len(backoffs)} attempts")
