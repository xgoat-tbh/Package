"""Regression tests for dashboard-side hardening.

Covers the two boundaries that were wrong in the original tree: private file
routes accepted anonymous requests, and the WebSocket reader accepted frames
that violate RFC 6455.
"""

import os
import tempfile
import unittest

from syspy import httpd, ws
from syspy.server.api import Api


class _FakeHub:
    def __init__(self, folder):
        self.folder = folder

    def agent_folder(self, _agent):
        return self.folder


class TestPrivateFileRoutes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "sample.txt")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("private")

        api = Api.__new__(Api)                 # skip __init__: no MQTT needed
        api.app = httpd.Application()
        api.hub = _FakeHub(self.tmp.name)
        api.authenticate = lambda request: (
            request.headers.get("Authorization") == "Bearer test-token"
        )
        api._register_routes()
        self.api = api

    def _get(self, path, headers=None):
        return self.api.app.dispatch(httpd.Request("GET", path, {}, headers or {}, b""))

    def test_file_route_rejects_anonymous(self):
        self.assertEqual(self._get("/files/agent/sample.txt").status, 401)

    def test_file_route_allows_authenticated(self):
        response = self._get("/files/agent/sample.txt",
                             {"Authorization": "Bearer test-token"})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, b"private")

    def test_received_route_rejects_anonymous(self):
        self.assertEqual(self._get("/received/agent/sample.txt").status, 401)

    def test_traversal_still_rejected(self):
        response = self._get("/files/agent/../../etc/passwd",
                             {"Authorization": "Bearer test-token"})
        self.assertIn(response.status, (403, 404))


class _Reader:
    def __init__(self, data):
        self.data = bytearray(data)

    def read(self, count):
        chunk = bytes(self.data[:count])
        del self.data[:count]
        return chunk


class _Writer:
    def write(self, _data):
        return None

    def flush(self):
        return None


class TestWebSocketFraming(unittest.TestCase):
    def test_unmasked_client_frame_rejected(self):
        # FIN + text opcode, mask bit deliberately clear.
        socket = ws.WebSocket(_Reader(b"\x81\x01x"), _Writer())
        self.assertIsNone(socket.receive())
        self.assertTrue(socket.closed)

    def test_oversized_frame_rejected_from_header_alone(self):
        size = ws.MAX_FRAME_BYTES + 1
        header = b"\x81\xff" + size.to_bytes(8, "big")
        socket = ws.WebSocket(_Reader(header), _Writer())
        self.assertIsNone(socket.receive())
        self.assertTrue(socket.closed)

    def test_oversized_control_frame_rejected(self):
        # Ping with 126-byte payload violates the 125-byte control limit.
        header = b"\x89\xfe" + (126).to_bytes(2, "big") + b"\x00\x00\x00\x00"
        socket = ws.WebSocket(_Reader(header + b"x" * 126), _Writer())
        self.assertIsNone(socket.receive())
        self.assertTrue(socket.closed)

    def test_reserved_bit_rejected(self):
        socket = ws.WebSocket(_Reader(b"\xc1\x81\x00\x00\x00\x00x"), _Writer())
        self.assertIsNone(socket.receive())
        self.assertTrue(socket.closed)

    def test_masked_text_frame_accepted(self):
        socket = ws.WebSocket(_Reader(b"\x81\x81\x00\x00\x00\x00x"), _Writer())
        frame = socket.receive()
        self.assertIsNotNone(frame)
        self.assertEqual(frame, (ws.OP_TEXT, b"x"))


class TestPasswordComparison(unittest.TestCase):
    def test_non_ascii_password_does_not_raise(self):
        from syspy.server.api import _verify_password
        self.assertTrue(_verify_password("pässwörd", "pässwörd"))
        self.assertFalse(_verify_password("pässwörd", "pässwörd2"))


if __name__ == "__main__":
    unittest.main()
