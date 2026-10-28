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
            with open(os.path.join(tmp, "agent.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            with open(os.path.join(tmp, "syspy", "config.py"), "w", encoding="utf-8") as f:
                f.write("y = 2\n")
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


class TestHubLegacyInteroperability(unittest.TestCase):
    def test_send_to_legacy_and_modern_agents(self):
        from syspy.server.hub import Hub
        from syspy import config, crypto, protocol

        class DummyClient:
            def __init__(self):
                self.alive = True
                self.published = []
            def publish_wait(self, topic, payload, qos=1, timeout=6.0):
                self.published.append((topic, payload))
                return True

        master_key = crypto.derive_key(config.PASSPHRASE, config.KEY_SALT, config.KDF_ITERATIONS)
        with tempfile.TemporaryDirectory() as tmp:
            hub = Hub(master_key, tmp)
            dummy = DummyClient()
            hub._client = dummy

            # 1. Register a legacy agent (v5.1.1)
            remote_id = "test-legacy-123"
            agent_id = "agent:" + remote_id
            hub._register(agent_id, remote_id, {"t": "hello", "ver": "5.1.1", "name": "LEGACY-PC"})
            agent = hub.get(agent_id)
            self.assertTrue(agent.use_master_key)

            # Send a command to legacy agent
            hub.send(agent_id, {"t": "cmd", "d": "info"})
            topic, payload = dummy.published.pop()

            # Old agent decodes with master_key fmt=1
            old_agent_codec = protocol.Codec(master_key, fmt=1)
            msg, reason = old_agent_codec.decode_message(payload)
            self.assertEqual(reason, protocol.REASON_OK)
            self.assertEqual(msg.get("d"), "info")

            # 2. Register a modern agent (v5.2.0)
            remote_id_v2 = "test-modern-456"
            agent_id_v2 = "agent:" + remote_id_v2
            hub._register(agent_id_v2, remote_id_v2, {"t": "hello", "ver": "5.2.0", "proto": 2, "fmt": 2, "name": "MODERN-PC"})
            agent_v2 = hub.get(agent_id_v2)
            self.assertFalse(agent_v2.use_master_key)

            # Send a command to modern agent
            hub.send(agent_id_v2, {"t": "cmd", "d": "shot"})
            topic2, payload2 = dummy.published.pop()

            # Modern agent decodes with subkey fmt=2
            sub = crypto.subkey(master_key, remote_id_v2)
            new_agent_codec = protocol.Codec(sub, fmt=2)
            msg2, reason2 = new_agent_codec.decode_message(payload2)
            self.assertEqual(reason2, protocol.REASON_OK)
            self.assertEqual(msg2.get("d"), "shot")


if __name__ == "__main__":
    unittest.main()
