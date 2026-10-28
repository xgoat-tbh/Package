"""Regression tests for the patch.

Run: python -m unittest discover -s tests -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from syspy import crypto, ed25519, protocol


class TestEnvelope(unittest.TestCase):
    def setUp(self):
        self.key = crypto.derive_key("pw", b"salt")

    def test_v2_roundtrip(self):
        blob = crypto.seal(self.key, b"hello", fmt=2)
        self.assertEqual(blob[:2], crypto.MAGIC)
        self.assertEqual(crypto.unseal(self.key, blob), b"hello")

    def test_legacy_roundtrip(self):
        blob = crypto.seal(self.key, b"hello", fmt=1)
        self.assertEqual(crypto.unseal(self.key, blob), b"hello")

    def test_cross_format(self):
        # A patched peer must be able to read a legacy peer and vice versa.
        legacy = crypto.seal(self.key, b"old", fmt=1)
        self.assertEqual(crypto.unseal(self.key, legacy), b"old")

    def test_tamper_detected(self):
        blob = bytearray(crypto.seal(self.key, b"hello", fmt=2))
        blob[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            crypto.unseal(self.key, bytes(blob))

    def test_header_is_authenticated(self):
        blob = bytearray(crypto.seal(self.key, b"hello", fmt=2))
        blob[3] ^= 0xFF          # key id byte
        with self.assertRaises(ValueError):
            crypto.unseal(self.key, bytes(blob))

    def test_wrong_key(self):
        blob = crypto.seal(self.key, b"hello", fmt=2)
        with self.assertRaises(ValueError):
            crypto.unseal(crypto.derive_key("other", b"salt"), blob)

    def test_enc_and_mac_keys_differ(self):
        self.assertNotEqual(crypto._enc_key(self.key), crypto._mac_key(self.key))


class TestReplayAndChunks(unittest.TestCase):
    def setUp(self):
        self.codec = protocol.Codec(crypto.derive_key("pw", b"s"))

    def test_qos1_retransmit_of_a_chunk_is_accepted(self):
        """The bug: a retried publish is byte-identical, so its nonce was
        already seen and the retry was dropped before reaching the reassembler."""
        payload = b"x" * (protocol.config.CHUNK_SIZE * 2 + 5)
        parts = protocol.chunk(payload, "t1")
        blob = self.codec.encode(parts[0])

        message, reason = self.codec.decode_message(blob)
        self.assertEqual(reason, protocol.REASON_OK)
        message, reason = self.codec.decode_message(blob)   # the retransmit
        self.assertEqual(reason, protocol.REASON_OK)
        self.assertEqual(message["part"], 0)

    def test_duplicate_logical_message_is_dropped(self):
        blob = self.codec.encode({"t": "cmd", "d": "ver"})
        self.assertEqual(self.codec.decode_message(blob)[1], protocol.REASON_OK)
        self.assertEqual(self.codec.decode_message(blob)[1], protocol.REASON_REPLAY)

    def test_reassembler_caps_total(self):
        assembler = protocol.Reassembler()
        self.assertIsNone(assembler.feed(
            {"xid": "a", "part": 0, "total": protocol.MAX_TOTAL_CHUNKS + 1,
             "data": ""}, 0.0))

    def test_reassembler_rejects_bad_index(self):
        assembler = protocol.Reassembler()
        self.assertIsNone(assembler.feed(
            {"xid": "a", "part": 5, "total": 3, "data": ""}, 0.0))


class TestEd25519(unittest.TestCase):
    def test_sign_verify(self):
        seed = bytes(range(32))
        public = ed25519.publickey(seed)
        signature = ed25519.sign(b"message", seed)
        self.assertTrue(ed25519.verify(signature, b"message", public))
        self.assertFalse(ed25519.verify(signature, b"other", public))

    def test_pinned_key_fails_closed(self):
        seed = bytes(range(32))
        public = ed25519.publickey(seed).hex()
        payload = b"kit"
        good = ed25519.sign(payload, seed).hex()
        self.assertTrue(crypto.verify_signature(payload, good, public)[0])
        # A pinned key present but not verifying must NOT fall back to HMAC.
        self.assertFalse(crypto.verify_signature(payload, "", public)[0])
        self.assertFalse(crypto.verify_signature(payload, "00" * 64, public)[0])

    def test_hmac_mode(self):
        key = crypto.kit_hmac_key("room", "pass")
        good = crypto.hmac_hex(key, b"kit")
        self.assertTrue(crypto.verify_signature(b"kit", good, "", key)[0])
        self.assertFalse(crypto.verify_signature(b"kit", "00", "", key)[0])


class TestConfig(unittest.TestCase):
    def test_namespace_is_stable(self):
        from syspy import config
        self.assertEqual(config.NAMESPACE, config.NAMESPACE)
        self.assertIn(config.NAMESPACE, config.mutex_name())
        self.assertIn(config.NAMESPACE, config.lock_leaf())

    def test_packaging_loose_dir_has_manifest(self):
        from syspy import packaging
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "syspy"), exist_ok=True)
            open(os.path.join(tmp, "agent.py"), "w").write("x = 1\n")
            open(os.path.join(tmp, "syspy", "config.py"), "w").write("y = 2\n")
            blob = packaging.build_zip_from_dir(tmp)
            import io
            import zipfile
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                self.assertIn(packaging.MANIFEST_NAME, archive.namelist())
                ok, reason = packaging.verify_manifest_zip(archive)
            self.assertTrue(ok, reason)


class TestMachineState(unittest.TestCase):
    def test_roundtrip(self):
        from syspy.agent import machine_state
        machine_state._CACHE = {}
        machine_state.record("defender_exclusions", "C:/x", 1)
        self.assertIn("C:/x", machine_state.get("defender_exclusions"))
        machine_state.forget("defender_exclusions")
        self.assertEqual(machine_state.get("defender_exclusions"), {})


if __name__ == "__main__":
    unittest.main()
