"""Unit tests for MLS engine crypto operations and backup module."""

from __future__ import annotations

import base64
import json

import pytest

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Backup tests (pure Python, require cryptography)
# ---------------------------------------------------------------------------


class TestBackup:
    @pytest.fixture(autouse=True)
    def _import_backup(self):
        pytest.importorskip("cryptography")
        from vox_sdk.crypto.backup import decrypt_backup, encrypt_backup

        self.encrypt_backup = encrypt_backup
        self.decrypt_backup = decrypt_backup

    def test_backup_round_trip(self):
        """Encrypt then decrypt, verify data matches."""
        data = b"secret MLS state data for backup test"
        passphrase = "correct-horse-battery-staple"

        blob = self.encrypt_backup(data, passphrase)
        assert isinstance(blob, str)

        recovered = self.decrypt_backup(blob, passphrase)
        assert recovered == data

    def test_backup_wrong_passphrase(self):
        """Decrypt with wrong passphrase raises."""
        data = b"some state"
        blob = self.encrypt_backup(data, "right-passphrase")

        with pytest.raises(Exception):
            self.decrypt_backup(blob, "wrong-passphrase")

    def test_backup_invalid_version(self):
        """Tamper version field, verify ValueError."""
        data = b"some state"
        blob = self.encrypt_backup(data, "passphrase")

        # Decode envelope, change version, re-encode
        envelope = json.loads(base64.b64decode(blob))
        envelope["v"] = 99
        tampered = base64.b64encode(json.dumps(envelope).encode()).decode()

        with pytest.raises(ValueError, match="Unsupported backup format version"):
            self.decrypt_backup(tampered, "passphrase")


# ---------------------------------------------------------------------------
# MLS engine tests (require vox_mls native extension)
# ---------------------------------------------------------------------------


class TestMlsEngine:
    @pytest.fixture(autouse=True)
    def _import_mls(self):
        vox_mls = pytest.importorskip("vox_mls")
        self.MlsEngine = vox_mls.MlsEngine

    def test_generate_identity(self):
        """Create engine, generate identity, verify identity_key() returns bytes."""
        engine = self.MlsEngine(db_path=None)
        assert engine.identity_key() is None

        engine.generate_identity(1, "device-a")
        ik = engine.identity_key()
        assert isinstance(ik, bytes)
        assert len(ik) > 0

    def test_two_user_encrypt_decrypt(self):
        """Alice creates group with Bob's key package, Bob joins, round-trip."""
        alice = self.MlsEngine(db_path=None)
        alice.generate_identity(1, "alice-device")

        bob = self.MlsEngine(db_path=None)
        bob.generate_identity(2, "bob-device")

        # Bob generates a key package for Alice to use
        bob_kps = bob.generate_key_packages(1)
        assert len(bob_kps) == 1

        # Alice creates a group and adds Bob
        welcome, commit = alice.create_group("test-group", [bytes(bob_kps[0])])
        assert welcome is not None

        # Bob joins from the Welcome
        group_id = bob.join_group(bytes(welcome))
        assert group_id == "test-group"

        # Alice encrypts, Bob decrypts
        plaintext = b"hello from alice"
        ciphertext = alice.encrypt("test-group", plaintext)
        decrypted = bob.decrypt("test-group", bytes(ciphertext))
        assert bytes(decrypted) == plaintext

    def test_multiple_messages(self):
        """Send 5 messages, all decrypt correctly."""
        alice = self.MlsEngine(db_path=None)
        alice.generate_identity(1, "alice-device")

        bob = self.MlsEngine(db_path=None)
        bob.generate_identity(2, "bob-device")

        bob_kps = bob.generate_key_packages(1)
        welcome, commit = alice.create_group("multi-msg", [bytes(bob_kps[0])])
        bob.join_group(bytes(welcome))

        for i in range(5):
            msg = f"message number {i}".encode()
            ct = alice.encrypt("multi-msg", msg)
            pt = bob.decrypt("multi-msg", bytes(ct))
            assert bytes(pt) == msg

    def test_group_exists_and_list(self):
        """Create group, verify group_exists() and list_groups()."""
        import json

        engine = self.MlsEngine(db_path=None)
        engine.generate_identity(1, "device-a")

        assert not engine.group_exists("my-group")
        assert len(engine.list_groups()) == 0

        # Create group with no additional members
        engine.create_group("my-group", [])

        assert engine.group_exists("my-group")
        groups = engine.list_groups()
        assert len(groups) == 1
        # list_groups returns serialized openmls GroupId; decode to verify
        decoded = bytes(json.loads(groups[0])["value"]["vec"]).decode()
        assert decoded == "my-group"

    def test_state_export_import(self):
        """Create group, export_state(), new engine, import_state(), verify."""
        engine = self.MlsEngine(db_path=None)
        engine.generate_identity(1, "device-a")
        engine.create_group("export-test", [])

        original_ik = engine.identity_key()
        state = engine.export_state()
        assert isinstance(bytes(state), bytes)
        assert len(state) > 0

        # New engine, import state
        engine2 = self.MlsEngine(db_path=None)
        engine2.import_state(bytes(state))

        assert engine2.identity_key() == original_ik
        assert engine2.group_exists("export-test")

    def test_identity_export_import(self):
        """export_identity(), new engine, import_identity(), verify match."""
        engine = self.MlsEngine(db_path=None)
        engine.generate_identity(1, "device-a")
        original_ik = engine.identity_key()

        identity = engine.export_identity()
        assert isinstance(bytes(identity), bytes)

        engine2 = self.MlsEngine(db_path=None)
        engine2.import_identity(bytes(identity), 1, "device-a")
        assert engine2.identity_key() == original_ik
