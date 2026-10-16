"""A minimal Chrome DevTools Protocol client over a standard-library WebSocket.

Only for local test automation against 127.0.0.1. No third-party package: the project is
standard-library only (D4, D5) and no browser-automation framework is installed or approved.
The client never connects anywhere but the loopback DevTools port of a browser that the
harness started itself.
"""

import base64
import json
import os
import socket
import struct
import time
from collections import deque
from urllib.parse import urlparse


class CdpError(RuntimeError):
    pass


class WebSocket:
    """RFC 6455 client: text frames, masking, fragmentation, ping/pong. Loopback only."""

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "ws" or parsed.hostname not in ("127.0.0.1", "localhost"):
            raise CdpError("the DevTools socket must be on loopback")
        self.sock = socket.create_connection((parsed.hostname, parsed.port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (f"GET {parsed.path} HTTP/1.1\r\nHost: {parsed.hostname}:{parsed.port}\r\nUpgrade: websocket\r\n"
                   f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(request.encode())
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise CdpError("DevTools closed the connection during the handshake")
            response += chunk
        head, _, self._buffer = response.partition(b"\r\n\r\n")
        if not head.startswith(b"HTTP/1.1 101"):
            raise CdpError("DevTools refused the WebSocket upgrade")

    def _read(self, n: int) -> bytes:
        while len(self._buffer) < n:
            chunk = self.sock.recv(max(65536, n - len(self._buffer)))
            if not chunk:
                raise CdpError("DevTools closed the connection")
            self._buffer += chunk
        data, self._buffer = self._buffer[:n], self._buffer[n:]
        return data

    def send(self, text: str) -> None:
        payload = text.encode("utf-8")
        header = bytearray([0x81])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack("!H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", n)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + mask + masked)

    def _control(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        self.sock.sendall(bytes([0x80 | opcode, 0x80 | len(payload)]) + mask
                          + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def recv(self) -> str:
        message = b""
        while True:
            first, second = self._read(2)
            opcode, length = first & 0x0F, second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read(8))[0]
            mask = self._read(4) if second & 0x80 else None
            payload = self._read(length)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x9:  # ping
                self._control(0xA, payload)
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode == 0x8:
                raise CdpError("DevTools closed the WebSocket")
            message += payload
            if first & 0x80:
                return message.decode("utf-8")

    def close(self) -> None:
        try:
            self._control(0x8, b"")
        except OSError:
            pass
        self.sock.close()


class Cdp:
    """Commands and events over one browser connection (flattened target sessions)."""

    def __init__(self, ws_url: str) -> None:
        self.ws = WebSocket(ws_url)
        self._next = 0
        self.events: deque[dict] = deque(maxlen=20000)

    def send(self, method: str, params: dict | None = None, session: str | None = None, timeout: float = 30.0) -> dict:
        self._next += 1
        message = {"id": self._next, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        self.ws.send(json.dumps(message))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            reply = json.loads(self.ws.recv())
            if reply.get("id") == self._next:
                if "error" in reply:
                    raise CdpError(f"{method}: {reply['error'].get('message')}")
                return reply.get("result", {})
            if "method" in reply:
                self.events.append(reply)
        raise CdpError(f"{method}: no reply")

    def close(self) -> None:
        self.ws.close()
