"""Passive discovery: listen to Tuya UDP broadcasts (6666 / 6667 / 7000).

Nothing is ever sent. Devices announce {"ip", "gwId", "version", "productKey"}
every few seconds; we decrypt it with the well-known broadcast key.
No Home Assistant imports — testable standalone.
"""
from __future__ import annotations

import asyncio
import json
import logging
import struct
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .protocol import PREFIX_55AA, PREFIX_6699, ecb_decrypt, strip_retcode

_LOGGER = logging.getLogger(__name__)

UDP_KEY = bytes.fromhex("6c1ec8e2bb9bb59ab50b0daf649b410a")  # md5("yGAdlopoPVldABfn")
PORTS = (6666, 6667, 7000)


def decode_broadcast(data: bytes) -> dict[str, Any] | None:
    try:
        if data[:4] == PREFIX_6699:
            length = struct.unpack(">I", data[14:18])[0]
            pt = AESGCM(UDP_KEY).decrypt(data[18:30], data[30 : 18 + length], data[4:18])
            _, pt = strip_retcode(pt)
        elif data[:4] == PREFIX_55AA:
            length = struct.unpack(">I", data[12:16])[0]
            body = data[20 : 16 + length - 8]
            pt = body if body[:1] == b"{" else ecb_decrypt(UDP_KEY, body)
        else:
            return None
        obj = json.loads(pt.decode())
        return obj if isinstance(obj, dict) else None
    except Exception:  # noqa: BLE001
        return None


class TuyaDiscovery(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.devices: dict[str, dict[str, Any]] = {}
        self.started_at = 0.0
        self._transports: list[asyncio.BaseTransport] = []

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self.started_at = time.monotonic()
        for port in PORTS:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: self, local_addr=("0.0.0.0", port), reuse_port=True
                )
                self._transports.append(transport)
            except OSError as err:
                _LOGGER.warning("cannot listen on UDP %s: %s", port, err)

    def close(self) -> None:
        for transport in self._transports:
            transport.close()
        self._transports.clear()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        info = decode_broadcast(data)
        if not info or "gwId" not in info:
            return
        info.setdefault("ip", addr[0])
        info["last_seen"] = time.monotonic()
        if info["gwId"] not in self.devices:
            _LOGGER.debug("discovered %s at %s (v%s)", info["gwId"], info["ip"], info.get("version"))
        self.devices[info["gwId"]] = info

    def host_of(self, device_id: str) -> str | None:
        info = self.devices.get(device_id)
        return info["ip"] if info else None
