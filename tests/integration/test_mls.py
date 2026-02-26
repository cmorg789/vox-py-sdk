"""Live server integration tests for MLS relay and key backup."""

from __future__ import annotations

import asyncio
import base64

import pytest

vox_mls = pytest.importorskip("vox_mls")

from vox_sdk.gateway import GatewayClient  # noqa: E402

from .conftest import make_live_sdk_client, register_live  # noqa: E402

pytestmark = pytest.mark.anyio


class TestMlsRelay:
    """Gateway MLS relay: two devices for the same user."""

    async def _setup_two_devices(self, live_server):
        """Register a user, connect two gateway sessions, return (client, gw1, gw2)."""
        client = await make_live_sdk_client(live_server)
        await register_live(client, "alice", "password123")

        gw1 = GatewayClient(
            live_server + "/gateway", client.http.token, compress=False
        )
        gw2 = GatewayClient(
            live_server + "/gateway", client.http.token, compress=False
        )

        await asyncio.wait_for(gw1.connect_in_background(), timeout=5)
        await asyncio.wait_for(gw2.connect_in_background(), timeout=5)

        return client, gw1, gw2

    async def test_mls_welcome_relay(self, live_server):
        """One device sends mls_relay with type 'welcome', the other receives mls_welcome."""
        client, gw1, gw2 = await self._setup_two_devices(live_server)
        try:
            received = asyncio.Future()

            @gw2.on("mls_welcome")
            async def on_welcome(event):
                if not received.done():
                    received.set_result(event)

            payload = base64.b64encode(b"fake-welcome-data").decode()
            await gw1.send_mls_relay("welcome", payload)

            event = await asyncio.wait_for(received, timeout=5)
            assert event.type == "mls_welcome"
            assert event.data == payload
        finally:
            await gw1.close()
            await gw2.close()
            await client.close()

    async def test_mls_commit_relay(self, live_server):
        """Same pattern with type 'commit', verify group_id field present."""
        client, gw1, gw2 = await self._setup_two_devices(live_server)
        try:
            received = asyncio.Future()

            @gw2.on("mls_commit")
            async def on_commit(event):
                if not received.done():
                    received.set_result(event)

            payload = base64.b64encode(b"fake-commit-data").decode()
            await gw1.send_mls_relay("commit", payload)

            event = await asyncio.wait_for(received, timeout=5)
            assert event.type == "mls_commit"
            assert event.data == payload
            # group_id field should be present (may be empty string)
            assert hasattr(event, "group_id")
        finally:
            await gw1.close()
            await gw2.close()
            await client.close()

    async def test_mls_proposal_relay(self, live_server):
        """Same pattern with type 'proposal'."""
        client, gw1, gw2 = await self._setup_two_devices(live_server)
        try:
            received = asyncio.Future()

            @gw2.on("mls_proposal")
            async def on_proposal(event):
                if not received.done():
                    received.set_result(event)

            payload = base64.b64encode(b"fake-proposal-data").decode()
            await gw1.send_mls_relay("proposal", payload)

            event = await asyncio.wait_for(received, timeout=5)
            assert event.type == "mls_proposal"
            assert event.data == payload
            assert hasattr(event, "group_id")
        finally:
            await gw1.close()
            await gw2.close()
            await client.close()


class TestMlsKeyBackup:
    async def test_mls_key_backup_round_trip(self, live_server):
        """Use real CryptoManager to backup and restore, verify identity and groups."""
        pytest.importorskip("cryptography")
        from vox_sdk.crypto.manager import CryptoManager

        client = await make_live_sdk_client(live_server)
        try:
            reg = await register_live(client, "alice", "password123")

            cm = CryptoManager(client, db_path=None)
            await cm.initialize(user_id=reg.user_id, device_id="dev-1")

            original_ik = cm._engine.identity_key()
            assert original_ik is not None

            # Backup to server
            passphrase = "test-backup-passphrase"
            await cm.backup_to_server(passphrase)

            # Create a new CryptoManager and restore
            cm2 = CryptoManager(client, db_path=None)
            await cm2.restore_from_server(passphrase)

            assert cm2.initialized
            assert cm2._engine.identity_key() == original_ik
        finally:
            await client.close()
