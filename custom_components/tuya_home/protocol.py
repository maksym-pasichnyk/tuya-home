from __future__ import annotations

import asyncio
import binascii
from collections.abc import Callable
import hashlib
import hmac
import json
import logging
import os
import struct
import time
from typing import Any, NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_LOGGER = logging.getLogger(__name__)

PORT = 6668
SUPPORTED_VERSIONS = ("3.3", "3.4", "3.5")

PREFIX_55AA = bytes.fromhex("000055aa")
SUFFIX_55AA = bytes.fromhex("0000aa55")
PREFIX_6699 = bytes.fromhex("00006699")
SUFFIX_6699 = bytes.fromhex("00009966")

SESS_KEY_NEG_START = 0x03
SESS_KEY_NEG_RESP = 0x04
SESS_KEY_NEG_FINISH = 0x05
CONTROL = 0x07
STATUS = 0x08
HEART_BEAT = 0x09
DP_QUERY = 0x0A
CONTROL_NEW = 0x0D
DP_QUERY_NEW = 0x10

# Commands whose plaintext is NOT prefixed with the "3.x" + 12 byte header.
_NO_VERSION_HEADER = {
    DP_QUERY,
    DP_QUERY_NEW,
    HEART_BEAT,
    SESS_KEY_NEG_START,
    SESS_KEY_NEG_RESP,
    SESS_KEY_NEG_FINISH,
    0x12,
}

HEARTBEAT_INTERVAL = 10
READ_TIMEOUT = 30  # no frame (incl. heartbeat replies) for this long => dead
REQUEST_TIMEOUT = 5
CONNECT_TIMEOUT = 8


class TuyaError(Exception):
    """Protocol or connection error."""


class TuyaAuthError(TuyaError):
    """Wrong local key (handshake / HMAC / GCM tag mismatch)."""


class Frame(NamedTuple):
    seq: int
    cmd: int
    retcode: int | None
    payload: bytes


def ecb_encrypt(key: bytes, data: bytes, pad: bool = True) -> bytes:
    if pad:
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def ecb_decrypt(key: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    raw = dec.update(data) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(raw) + unpadder.finalize()
    except ValueError:
        return raw


def strip_retcode(data: bytes) -> tuple[int | None, bytes]:
    """Device replies may start with a 4-byte return code (0x000000xx)."""
    if len(data) >= 4 and data[:3] == b"\x00\x00\x00":
        return data[3], data[4:]
    return None, data


def strip_version(data: bytes) -> bytes:
    if len(data) >= 15 and data[:3] in (b"3.3", b"3.4", b"3.5"):
        return data[15:]
    return data


def parse_dps(payload: bytes) -> dict[str, Any] | None:
    """Extract the dps dict from a status / query reply (3.3 or 3.4+ shape)."""
    try:
        obj = json.loads(payload)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    if isinstance(obj.get("dps"), dict):
        return obj["dps"]
    data = obj.get("data")
    if isinstance(data, dict) and isinstance(data.get("dps"), dict):
        return data["dps"]
    return None


class Codec:
    """Frame packing / unpacking for one connection."""

    def __init__(self, version: str, local_key: bytes) -> None:
        self.version = version
        self.local_key = local_key
        self.key = local_key  # replaced by the session key on 3.4 / 3.5

    def pack(self, seq: int, cmd: int, plaintext: bytes) -> bytes:
        if self.version == "3.5":
            if cmd not in _NO_VERSION_HEADER:
                plaintext = b"3.5" + bytes(12) + plaintext
            iv = os.urandom(12)
            length = 12 + len(plaintext) + 16
            header = PREFIX_6699 + struct.pack(">HIII", 0, seq, cmd, length)
            ct = AESGCM(self.key).encrypt(iv, plaintext, header[4:])
            return header + iv + ct + SUFFIX_6699

        if self.version == "3.4":
            if cmd not in _NO_VERSION_HEADER:
                plaintext = b"3.4" + bytes(12) + plaintext
            payload = ecb_encrypt(self.key, plaintext)
            header = PREFIX_55AA + struct.pack(">III", seq, cmd, len(payload) + 36)
            mac = hmac.new(self.key, header + payload, hashlib.sha256).digest()
            return header + payload + mac + SUFFIX_55AA

        # 3.3: version header sits *outside* the encrypted part
        payload = ecb_encrypt(self.key, plaintext)
        if cmd not in _NO_VERSION_HEADER:
            payload = b"3.3" + bytes(12) + payload
        header = PREFIX_55AA + struct.pack(">III", seq, cmd, len(payload) + 8)
        crc = binascii.crc32(header + payload) & 0xFFFFFFFF
        return header + payload + struct.pack(">I", crc) + SUFFIX_55AA

    def unpack(self, buf: bytearray) -> Frame | None:
        """Pop one complete frame from the front of ``buf``; None if incomplete."""
        i55, i66 = buf.find(PREFIX_55AA), buf.find(PREFIX_6699)
        found = [i for i in (i55, i66) if i >= 0]
        if not found:
            del buf[:-3]  # keep a possible partial prefix
            return None
        if (start := min(found)) > 0:
            del buf[:start]

        if buf[:4] == PREFIX_6699:
            if len(buf) < 18:
                return None
            _, seq, cmd, length = struct.unpack(">HIII", buf[4:18])
            total = 18 + length + 4
            if len(buf) < total:
                return None
            raw = bytes(buf[:total])
            del buf[:total]
            try:
                pt = AESGCM(self.key).decrypt(raw[18:30], raw[30 : 18 + length], raw[4:18])
            except InvalidTag as err:
                raise TuyaAuthError("GCM tag mismatch (wrong local key?)") from err
            ret, pt = strip_retcode(pt)
            return Frame(seq, cmd, ret, strip_version(pt))

        if len(buf) < 16:
            return None
        seq, cmd, length = struct.unpack(">III", buf[4:16])
        total = 16 + length
        if len(buf) < total:
            return None
        raw = bytes(buf[:total])
        del buf[:total]

        if self.version == "3.4":
            body, mac = raw[16:-36], raw[-36:-4]
            if hmac.new(self.key, raw[:-36], hashlib.sha256).digest() != mac:
                raise TuyaAuthError("HMAC mismatch (wrong local key?)")
        else:
            body = raw[16:-8]

        ret, body = strip_retcode(body)
        body = strip_version(body)
        if not body or body[:1] == b"{":
            return Frame(seq, cmd, ret, body)
        return Frame(seq, cmd, ret, strip_version(ecb_decrypt(self.key, body)))


class TuyaDevice:
    """Persistent local connection to one Tuya device."""

    def __init__(
        self,
        device_id: str,
        local_key: str,
        version: str,
        host: str,
        host_resolver: Callable[[], str | None] | None = None,
    ) -> None:
        if version not in SUPPORTED_VERSIONS:
            raise ValueError(f"unsupported protocol version {version}")
        key = local_key.encode("utf-8")
        if len(key) != 16:
            raise ValueError("local key must be 16 bytes")
        self.device_id = device_id
        self.version = version
        self.host = host
        self.dps: dict[str, Any] = {}
        self.available = False
        self.last_error: str | None = None

        self._local_key = key
        self._host_resolver = host_resolver
        self._listeners: list[Callable[[], None]] = []
        self._codec: Codec | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._buf = bytearray()
        self._seq = 0
        self._waiters: dict[int, asyncio.Future[Frame]] = {}
        self._lock = asyncio.Lock()
        self._tasks: list[asyncio.Task] = []
        self._lost: asyncio.Event = asyncio.Event()
        self._available_evt = asyncio.Event()
        self._closing = False

    # ---------- listeners ----------
    def add_listener(self, cb: Callable[[], None]) -> Callable[[], None]:
        self._listeners.append(cb)
        return lambda: self._listeners.remove(cb)

    def _notify(self) -> None:
        for cb in list(self._listeners):
            try:
                cb()
            except Exception:  # noqa: BLE001
                _LOGGER.exception("listener failed")

    def _set_available(self, value: bool) -> None:
        if value:
            self._available_evt.set()
        else:
            self._available_evt.clear()
        if self.available != value:
            self.available = value
            self._notify()

    async def wait_available(self) -> None:
        await self._available_evt.wait()

    # ---------- connection ----------
    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, PORT), CONNECT_TIMEOUT
        )
        self._codec = Codec(self.version, self._local_key)
        self._buf = bytearray()
        self._lost = asyncio.Event()
        if self.version in ("3.4", "3.5"):
            await self._negotiate_session_key()
        self._tasks = [
            asyncio.create_task(self._read_loop(), name=f"tuya_home read {self.device_id}"),
            asyncio.create_task(self._heartbeat_loop(), name=f"tuya_home hb {self.device_id}"),
        ]

    async def disconnect(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._tasks = []
        for fut in self._waiters.values():
            if not fut.done():
                fut.set_exception(TuyaError("disconnected"))
        self._waiters.clear()
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        self._reader = self._writer = None

    async def _negotiate_session_key(self) -> None:
        assert self._codec is not None
        lk = self._local_key
        local_nonce = os.urandom(16)
        await self._send(SESS_KEY_NEG_START, local_nonce)
        while True:
            frame = await self._read_frame(CONNECT_TIMEOUT)
            if frame.cmd == SESS_KEY_NEG_RESP:
                break
        remote_nonce, their_hmac = frame.payload[:16], frame.payload[16:48]
        if their_hmac != hmac.new(lk, local_nonce, hashlib.sha256).digest():
            raise TuyaAuthError("session key negotiation failed (wrong local key?)")
        await self._send(SESS_KEY_NEG_FINISH, hmac.new(lk, remote_nonce, hashlib.sha256).digest())
        mixed = bytes(a ^ b for a, b in zip(local_nonce, remote_nonce))
        if self.version == "3.4":
            self._codec.key = ecb_encrypt(lk, mixed, pad=False)
        else:
            self._codec.key = AESGCM(lk).encrypt(local_nonce[:12], mixed, None)[:16]

    async def _send(self, cmd: int, payload: bytes) -> None:
        if self._writer is None or self._codec is None:
            raise TuyaError("not connected")
        self._seq += 1
        self._writer.write(self._codec.pack(self._seq, cmd, payload))
        await self._writer.drain()

    async def _read_frame(self, timeout: float) -> Frame:
        assert self._reader is not None and self._codec is not None
        while True:
            frame = self._codec.unpack(self._buf)
            if frame is not None:
                return frame
            chunk = await asyncio.wait_for(self._reader.read(4096), timeout)
            if not chunk:
                raise TuyaError("connection closed by device")
            self._buf += chunk

    async def _read_loop(self) -> None:
        try:
            while True:
                self._dispatch(await self._read_frame(READ_TIMEOUT))
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001
            self.last_error = f"{type(err).__name__}: {err}"
            _LOGGER.debug("%s: connection lost: %s", self.device_id, self.last_error)
            self._lost.set()

    async def _heartbeat_loop(self) -> None:
        payload = (
            json.dumps({"gwId": self.device_id, "devId": self.device_id}).encode()
            if self.version == "3.3"
            else b"{}"
        )
        try:
            while True:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                await self._send(HEART_BEAT, payload)
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001
            self.last_error = f"heartbeat: {err}"
            self._lost.set()

    def _dispatch(self, frame: Frame) -> None:
        _LOGGER.debug("%s: recv cmd=0x%02x %r", self.device_id, frame.cmd, frame.payload[:200])
        if frame.cmd in (STATUS, DP_QUERY, DP_QUERY_NEW) and frame.payload:
            dps = parse_dps(frame.payload)
            if dps:
                self.dps.update(dps)
                self._notify()
        fut = self._waiters.pop(frame.cmd, None)
        if fut is not None and not fut.done():
            fut.set_result(frame)

    async def _request(self, cmd: int, payload: bytes, reply_cmd: int) -> Frame:
        async with self._lock:
            fut: asyncio.Future[Frame] = asyncio.get_running_loop().create_future()
            self._waiters[reply_cmd] = fut
            try:
                await self._send(cmd, payload)
                return await asyncio.wait_for(fut, REQUEST_TIMEOUT)
            finally:
                self._waiters.pop(reply_cmd, None)

    # ---------- public API ----------
    async def status(self) -> dict[str, Any]:
        """Read all DPs with a query command (never with a control command)."""
        if self.version == "3.3":
            t = str(int(time.time()))
            body = {"gwId": self.device_id, "devId": self.device_id, "uid": self.device_id, "t": t}
            frame = await self._request(DP_QUERY, _json(body), DP_QUERY)
        else:
            frame = await self._request(DP_QUERY_NEW, b"{}", DP_QUERY_NEW)
        if parse_dps(frame.payload) is None:
            raise TuyaError(f"device rejected status query: {frame.payload[:60]!r}")
        return dict(self.dps)

    async def set_dps(self, dps: dict[str, Any]) -> None:
        t = int(time.time())
        if self.version == "3.3":
            body = {"devId": self.device_id, "uid": self.device_id, "t": str(t), "dps": dps}
            await self._request(CONTROL, _json(body), CONTROL)
        else:
            body = {"protocol": 5, "t": t, "data": {"dps": dps}}
            await self._request(CONTROL_NEW, _json(body), CONTROL_NEW)

    async def run(self) -> None:
        """Keep the connection alive forever, reconnecting with backoff."""
        self._closing = False
        delay = 5
        auth_failures = 0
        while not self._closing:
            try:
                if self._host_resolver is not None and (new_host := self._host_resolver()):
                    if new_host != self.host:
                        _LOGGER.info("%s: IP changed %s -> %s", self.device_id, self.host, new_host)
                        self.host = new_host
                await self.connect()
                await self.status()
                self.last_error = None
                self._set_available(True)
                delay, auth_failures = 5, 0
                await self._lost.wait()
            except asyncio.CancelledError:
                await self.disconnect()
                self._set_available(False)
                raise
            except TuyaAuthError as err:
                # A single handshake failure happens occasionally (e.g. the
                # phone app talks to the device at the same moment); only a
                # repeated one means a wrong key.
                auth_failures += 1
                self.last_error = str(err)
                log = _LOGGER.error if auth_failures >= 3 else _LOGGER.debug
                log("%s: %s (attempt %s)", self.device_id, err, auth_failures)
            except (OSError, asyncio.TimeoutError, TuyaError) as err:
                self.last_error = f"{type(err).__name__}: {err}"
                _LOGGER.debug("%s: %s", self.device_id, self.last_error)
            await self.disconnect()
            self._set_available(False)
            if self._closing:
                break
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)

    async def stop(self) -> None:
        self._closing = True
        await self.disconnect()
        self._set_available(False)


def _json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


async def probe(device_id: str, local_key: str, version: str, host: str) -> dict[str, Any]:
    """One-shot: connect, read status, disconnect. Used by the config flow."""
    device = TuyaDevice(device_id, local_key, version, host)
    try:
        await device.connect()
        return await device.status()
    finally:
        await device.disconnect()
