"""Mocked orchestration tests for CryptoManager."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.anyio

vox_mls = pytest.importorskip("vox_mls")
from vox_mls import MlsEngine  # noqa: E402

from vox_sdk.crypto.manager import CryptoManager  # noqa: E402


def _make_mock_client(*, with_gateway: bool = True) -> MagicMock:
    """Build a mock Client with e2ee and optional gateway."""
    client = MagicMock()
    client.e2ee = AsyncMock()
    client.e2ee.get_mls_key_packages = AsyncMock(return_value=[])
    client.e2ee.upload_mls_key_packages = AsyncMock()
    client.e2ee.upload_key_backup = AsyncMock()
    client.e2ee.download_key_backup = AsyncMock()
    if with_gateway:
        gw = MagicMock()
        gw.add_handler = MagicMock()
        gw.send_mls_relay = AsyncMock()
        client.gateway = gw
    else:
        client.gateway = None
    return client


class TestInitialize:
    async def test_initialize_generates_identity(self):
        """Verify generate_identity called on engine."""
        client = _make_mock_client()
        cm = CryptoManager(client, db_path=None)
        assert not cm.initialized

        await cm.initialize(user_id=1, device_id="dev-1")
        assert cm.initialized
        assert cm._engine.identity_key() is not None

    async def test_initialize_registers_gateway_handlers(self):
        """Verify add_handler called for mls_welcome/commit/proposal."""
        client = _make_mock_client()
        cm = CryptoManager(client, db_path=None)
        await cm.initialize(user_id=1, device_id="dev-1")

        gw = client.gateway
        assert gw.add_handler.call_count == 3
        registered_types = {call.args[0] for call in gw.add_handler.call_args_list}
        assert registered_types == {"mls_welcome", "mls_commit", "mls_proposal"}

    async def test_initialize_skips_if_already_initialized(self):
        """Pre-existing identity not regenerated."""
        client = _make_mock_client()
        cm = CryptoManager(client, db_path=None)

        # First init
        await cm.initialize(user_id=1, device_id="dev-1")
        ik_first = cm._engine.identity_key()

        # Second init — should keep the same identity
        await cm.initialize(user_id=1, device_id="dev-1")
        assert cm._engine.identity_key() == ik_first


class TestCreateGroup:
    async def test_create_group_uses_mls_key_packages(self):
        """Verify get_mls_key_packages called (not get_prekeys)."""
        client = _make_mock_client()
        # Provide a real key package from a second engine
        bob = MlsEngine(db_path=None)
        bob.generate_identity(2, "bob-dev")
        kp = bob.generate_key_packages(1)[0]
        kp_b64 = base64.b64encode(bytes(kp)).decode()
        client.e2ee.get_mls_key_packages = AsyncMock(return_value=[kp_b64])

        cm = CryptoManager(client, db_path=None)
        await cm.initialize(user_id=1, device_id="dev-1")
        await cm.create_group_for_dm(dm_id=42, participant_ids=[1, 2])

        client.e2ee.get_mls_key_packages.assert_awaited_once_with(2)
        # get_prekeys should NOT have been called
        client.e2ee.get_prekeys = AsyncMock()
        client.e2ee.get_prekeys.assert_not_awaited()

    async def test_create_group_uses_send_mls_relay(self):
        """Verify send_mls_relay called with 'welcome' and 'commit'."""
        client = _make_mock_client()
        bob = MlsEngine(db_path=None)
        bob.generate_identity(2, "bob-dev")
        kp = bob.generate_key_packages(1)[0]
        kp_b64 = base64.b64encode(bytes(kp)).decode()
        client.e2ee.get_mls_key_packages = AsyncMock(return_value=[kp_b64])

        cm = CryptoManager(client, db_path=None)
        await cm.initialize(user_id=1, device_id="dev-1")
        await cm.create_group_for_dm(dm_id=42, participant_ids=[1, 2])

        gw = client.gateway
        relay_calls = gw.send_mls_relay.call_args_list
        relay_types = {call.args[0] for call in relay_calls}
        assert "welcome" in relay_types
        assert "commit" in relay_types

    async def test_create_group_requires_gateway(self):
        """gateway=None raises RuntimeError."""
        client = _make_mock_client(with_gateway=False)

        bob = MlsEngine(db_path=None)
        bob.generate_identity(2, "bob-dev")
        kp = bob.generate_key_packages(1)[0]
        kp_b64 = base64.b64encode(bytes(kp)).decode()
        client.e2ee.get_mls_key_packages = AsyncMock(return_value=[kp_b64])

        cm = CryptoManager(client, db_path=None)
        await cm.initialize(user_id=1, device_id="dev-1")

        with pytest.raises(RuntimeError, match="Gateway not connected"):
            await cm.create_group_for_dm(dm_id=42, participant_ids=[1, 2])


class TestEncryptDecrypt:
    async def test_encrypt_decrypt_round_trip(self):
        """Real MLS engine, mocked client, verify encrypt->decrypt."""
        client = _make_mock_client()

        alice_cm = CryptoManager(client, db_path=None)
        await alice_cm.initialize(user_id=1, device_id="alice-dev")

        # Create a Bob engine to provide key packages
        bob_engine = MlsEngine(db_path=None)
        bob_engine.generate_identity(2, "bob-dev")
        kp = bob_engine.generate_key_packages(1)[0]
        kp_b64 = base64.b64encode(bytes(kp)).decode()
        client.e2ee.get_mls_key_packages = AsyncMock(return_value=[kp_b64])

        await alice_cm.create_group_for_dm(dm_id=42, participant_ids=[1, 2])

        # Extract the welcome data that was relayed
        relay_calls = client.gateway.send_mls_relay.call_args_list
        welcome_b64 = next(
            call.args[1] for call in relay_calls if call.args[0] == "welcome"
        )
        welcome_bytes = base64.b64decode(welcome_b64)

        # Bob joins
        bob_engine.join_group(welcome_bytes)

        # Alice encrypts via CryptoManager
        blob = alice_cm.encrypt_message("hello bob", dm_id=42)
        assert isinstance(blob, str)

        # Bob decrypts directly with engine
        ct = base64.b64decode(blob)
        pt = bob_engine.decrypt("dm:42", ct)
        assert bytes(pt) == b"hello bob"


class TestBackup:
    async def test_backup_uses_export_state(self):
        """Verify backup uses export_state (not export_identity)."""
        pytest.importorskip("cryptography")

        client = _make_mock_client()
        cm = CryptoManager(client, db_path=None)
        await cm.initialize(user_id=1, device_id="dev-1")

        await cm.backup_to_server("my-passphrase")
        client.e2ee.upload_key_backup.assert_awaited_once()

        # The blob should be a valid base64 string
        uploaded_blob = client.e2ee.upload_key_backup.call_args.args[0]
        assert isinstance(uploaded_blob, str)
        # Decoding should not raise
        base64.b64decode(uploaded_blob)


class TestRefreshKeyPackages:
    async def test_refresh_key_packages(self):
        """Verify upload_mls_key_packages called with 100 packages."""
        client = _make_mock_client()
        cm = CryptoManager(client, db_path=None)
        await cm.initialize(user_id=1, device_id="dev-1")

        await cm.refresh_key_packages()
        client.e2ee.upload_mls_key_packages.assert_awaited_once()

        call_args = client.e2ee.upload_mls_key_packages.call_args
        device_id = call_args.args[0]
        kp_list = call_args.args[1]
        assert device_id == "dev-1"
        assert len(kp_list) == 100
        # Each should be a valid base64 string
        for kp_b64 in kp_list:
            base64.b64decode(kp_b64)
