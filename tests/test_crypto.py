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
        engine = self.MlsEngine(db_path=None)
        engine.generate_identity(1, "device-a")

        assert not engine.group_exists("my-group")
        assert len(engine.list_groups()) == 0

        # Create group with no additional members
        engine.create_group("my-group", [])

        assert engine.group_exists("my-group")
        groups = engine.list_groups()
        assert len(groups) == 1
        assert groups[0] == "my-group"

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

    def test_encrypt_after_state_import(self):
        """Encrypt/decrypt still works after export_state + import_state."""
        alice = self.MlsEngine(db_path=None)
        alice.generate_identity(1, "alice-device")

        bob = self.MlsEngine(db_path=None)
        bob.generate_identity(2, "bob-device")

        bob_kps = bob.generate_key_packages(1)
        welcome, _commit = alice.create_group("restore-group", [bytes(bob_kps[0])])
        bob.join_group(bytes(welcome))

        # Alice encrypts a message before export
        msg1 = b"before export"
        ct1 = alice.encrypt("restore-group", msg1)

        # Alice exports state, creates new engine, imports state
        state = alice.export_state()
        alice2 = self.MlsEngine(db_path=None)
        alice2.import_state(bytes(state))

        # Alice encrypts a second message on the restored engine
        msg2 = b"after import"
        ct2 = alice2.encrypt("restore-group", msg2)

        # Bob decrypts both messages
        assert bytes(bob.decrypt("restore-group", bytes(ct1))) == msg1
        assert bytes(bob.decrypt("restore-group", bytes(ct2))) == msg2

    def test_add_member_post_creation(self):
        """Create 2-person group, add a third member, verify encrypt/decrypt for all."""
        alice = self.MlsEngine(db_path=None)
        alice.generate_identity(1, "alice-device")

        bob = self.MlsEngine(db_path=None)
        bob.generate_identity(2, "bob-device")

        charlie = self.MlsEngine(db_path=None)
        charlie.generate_identity(3, "charlie-device")

        # Alice creates group with Bob
        bob_kps = bob.generate_key_packages(1)
        welcome, _commit = alice.create_group("add-test", [bytes(bob_kps[0])])
        bob.join_group(bytes(welcome))

        # Alice adds Charlie
        charlie_kps = charlie.generate_key_packages(1)
        welcome2, commit2 = alice.add_member("add-test", bytes(charlie_kps[0]))
        charlie.join_group(bytes(welcome2))
        bob.process_message("add-test", bytes(commit2))

        # Alice encrypts, Bob and Charlie both decrypt
        msg = b"hello everyone"
        ct = alice.encrypt("add-test", msg)
        assert bytes(bob.decrypt("add-test", bytes(ct))) == msg
        assert bytes(charlie.decrypt("add-test", bytes(ct))) == msg

    def test_remove_member(self):
        """Create 3-person group, remove one, verify removed member cannot decrypt."""
        alice = self.MlsEngine(db_path=None)
        alice.generate_identity(1, "alice-device")

        bob = self.MlsEngine(db_path=None)
        bob.generate_identity(2, "bob-device")

        charlie = self.MlsEngine(db_path=None)
        charlie.generate_identity(3, "charlie-device")

        # Alice creates group with Bob and Charlie
        bob_kps = bob.generate_key_packages(1)
        charlie_kps = charlie.generate_key_packages(1)
        welcome, _commit = alice.create_group(
            "remove-test", [bytes(bob_kps[0]), bytes(charlie_kps[0])]
        )
        bob.join_group(bytes(welcome))
        charlie.join_group(bytes(welcome))

        # Alice removes Charlie (leaf index 2)
        commit = alice.remove_member("remove-test", 2)
        bob.process_message("remove-test", bytes(commit))

        # Alice encrypts a new message
        msg = b"after removal"
        ct = alice.encrypt("remove-test", msg)

        # Bob can still decrypt
        assert bytes(bob.decrypt("remove-test", bytes(ct))) == msg

        # Charlie cannot decrypt (her group state is stale)
        with pytest.raises(Exception):
            charlie.decrypt("remove-test", bytes(ct))

    def test_process_commit(self):
        """Alice adds Charlie, Bob processes the commit, Bob can still encrypt/decrypt."""
        alice = self.MlsEngine(db_path=None)
        alice.generate_identity(1, "alice-device")

        bob = self.MlsEngine(db_path=None)
        bob.generate_identity(2, "bob-device")

        charlie = self.MlsEngine(db_path=None)
        charlie.generate_identity(3, "charlie-device")

        # Alice creates group with Bob
        bob_kps = bob.generate_key_packages(1)
        welcome, _commit = alice.create_group("commit-test", [bytes(bob_kps[0])])
        bob.join_group(bytes(welcome))

        # Alice adds Charlie
        charlie_kps = charlie.generate_key_packages(1)
        welcome2, commit2 = alice.add_member("commit-test", bytes(charlie_kps[0]))
        charlie.join_group(bytes(welcome2))

        # Bob processes the commit
        result = bob.process_message("commit-test", bytes(commit2))
        assert result.kind == "commit"

        # Bob encrypts, Alice and Charlie decrypt
        msg = b"bob says hi"
        ct = bob.encrypt("commit-test", msg)
        assert bytes(alice.decrypt("commit-test", bytes(ct))) == msg
        assert bytes(charlie.decrypt("commit-test", bytes(ct))) == msg

    def test_decrypt_wrong_group(self):
        """Attempt decrypt with wrong group ID, expect PyKeyError."""
        engine = self.MlsEngine(db_path=None)
        engine.generate_identity(1, "device-a")
        engine.create_group("real-group", [])

        with pytest.raises(KeyError):
            engine.decrypt("nonexistent-group", b"fake-ciphertext")

    def test_encrypt_without_identity(self):
        """Create engine without identity, attempt encrypt, expect error."""
        engine = self.MlsEngine(db_path=None)

        with pytest.raises(RuntimeError):
            engine.encrypt("some-group", b"hello")
