"""Transport abstractions so TlsClient and MerchantServer never share memory."""

from __future__ import annotations

import socket
import threading
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field


class Transport(ABC):
    """Bidirectional byte pipe between two TLS peers."""

    @abstractmethod
    def send(self, data: bytes) -> None: ...

    @abstractmethod
    def recv(self, max_bytes: int = 65536) -> bytes: ...

    @abstractmethod
    def close(self) -> None: ...


@dataclass
class MemoryPipe:
    """One direction of an in-process lock-protected queue."""

    _q: deque[bytes] = field(default_factory=deque)
    _cv: threading.Condition = field(default_factory=threading.Condition)
    _closed: bool = False

    def write(self, data: bytes) -> None:
        with self._cv:
            if self._closed:
                raise BrokenPipeError("pipe closed")
            if data:
                self._q.append(data)
                self._cv.notify()

    def read(self, max_bytes: int = 65536) -> bytes:
        with self._cv:
            while not self._q and not self._closed:
                self._cv.wait(timeout=5.0)
            if not self._q:
                return b""
            chunk = self._q.popleft()
            if len(chunk) > max_bytes:
                self._q.appendleft(chunk[max_bytes:])
                return chunk[:max_bytes]
            return chunk

    def close(self) -> None:
        with self._cv:
            self._closed = True
            self._cv.notify_all()


class MemoryTransport(Transport):
    """Paired in-process transport (still separate peer objects / threads)."""

    def __init__(self, outbound: MemoryPipe, inbound: MemoryPipe) -> None:
        self._out = outbound
        self._in = inbound

    def send(self, data: bytes) -> None:
        self._out.write(data)

    def recv(self, max_bytes: int = 65536) -> bytes:
        return self._in.read(max_bytes)

    def close(self) -> None:
        self._out.close()
        self._in.close()

    @staticmethod
    def pair() -> tuple[MemoryTransport, MemoryTransport]:
        a_to_b = MemoryPipe()
        b_to_a = MemoryPipe()
        return MemoryTransport(a_to_b, b_to_a), MemoryTransport(b_to_a, a_to_b)


class SocketTransport(Transport):
    """TCP socket wrapper for true process isolation demos."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._sock.settimeout(10.0)

    def send(self, data: bytes) -> None:
        self._sock.sendall(data)

    def recv(self, max_bytes: int = 65536) -> bytes:
        return self._sock.recv(max_bytes)

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()

    @staticmethod
    def connect_loopback(port: int) -> SocketTransport:
        s = socket.create_connection(("127.0.0.1", port), timeout=10.0)
        return SocketTransport(s)

    @staticmethod
    def serve_once(port: int = 0) -> tuple[SocketTransport, int]:
        """Listen on ``port`` (0 = ephemeral); accept one client; return (transport, port)."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        bound = srv.getsockname()[1]
        srv.settimeout(10.0)
        conn, _ = srv.accept()
        srv.close()
        return SocketTransport(conn), bound
