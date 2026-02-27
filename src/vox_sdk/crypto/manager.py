"""High-level MLS crypto orchestrator for the Vox SDK."""

from __future__ import annotations

import asyncio
import base64
import logging
from typing import TYPE_CHECKING, Any

from vox_sdk.crypto.backup import decrypt_backup, encrypt_backup

if TYPE_CHECKING:
    from vox_sdk.client import Client

log = logging.getLogger(__name__)

try:
    from vox_mls import MlsEngine
except ImportError:
    MlsEngine = None  # type: ignore[assignment, misc]


def _require_mls() -> None:
    if MlsEngine is None:
        raise RuntimeError(
            "The 'vox-mls' package is required for E2EE. "
            "Install it with: pip install vox-mls"
        )


def _group_id_for_feed(feed_id: int) -> str:
    return f"feed:{feed_id}"


def _group_id_for_dm(dm_id: int) -> str:
    return f"dm:{dm_id}"


class CryptoManager:
    """Orchestrates MLS encryption using vox-mls and the Vox E2EE API.

    Usage::

        crypto = CryptoManager(client)
        await crypto.initialize(user_id=123, device_id="abc")
        await crypto.register_device("My Laptop")
        await crypto.upload_key_packages()

        # Create encrypted group for a DM
        await crypto.create_group_for_dm(dm_id=42, participant_ids=[123, 456])

        # Encrypt/decrypt messages
        blob = crypto.encrypt_message(dm_id=42, plaintext="hello")
        text = crypto.decrypt_message(dm_id=42, opaque_blob=blob)
    """

    def __init__(
        self,
        client: Client,
        db_path: str | None = None,
        encryption_key: bytes | None = None,
    ) -> None:
        _require_mls()
        self._client = client
        self._engine: MlsEngine = MlsEngine(
            db_path=db_path, encryption_key=encryption_key
        )
        self._device_id: str | None = None
        self._user_id: int | None = None
        self._registered_gateway_id: int | None = None
        # If identity was restored from SQLite, mark as initialized
        self._initialized = self._engine.identity_key() is not None
        if self._initialized:
            stored = self._engine.get_stored_identity()
            if stored is not None:
                self._user_id, self._device_id = stored

    @property
    def initialized(self) -> bool:
        return self._initialized

    # --- Device setup ---

    async def initialize(self, user_id: int, device_id: str) -> None:
        """Generate an MLS identity for this user/device.

        If the engine already has an identity (e.g. restored from SQLite),
        this records user_id/device_id without generating a new one.

        Also registers gateway event handlers for MLS messages if the
        gateway is connected.
        """
        self._user_id = user_id
        self._device_id = device_id
        if not self._initialized:
            self._engine.generate_identity(user_id, device_id)
            self._initialized = True
            log.info("MLS identity initialized for user=%d device=%s", user_id, device_id)
        else:
            log.info("MLS identity already present (restored from storage)")

        self._register_gateway_handlers()

    async def register_device(self, device_name: str) -> str:
        """Register this device with the server."""
        self._require_initialized()
        if self._device_id is None:
            raise RuntimeError("device_id not set — call initialize() first")
        resp = await self._client.e2ee.add_device(self._device_id, device_name)
        log.info("Device registered: %s", resp.device_id)
        return resp.device_id

    async def upload_key_packages(self, count: int = 100) -> None:
        """Generate and upload key packages to the server."""
        self._require_initialized()
        if self._device_id is None:
            raise RuntimeError("device_id not set — call initialize() first")
        if count < 1:
            raise ValueError("count must be >= 1")

        key_packages = self._engine.generate_key_packages(count)
        kp_b64_list = [base64.b64encode(bytes(kp)).decode() for kp in key_packages]

        await self._client.e2ee.upload_mls_key_packages(self._device_id, kp_b64_list)
        log.info("Uploaded %d MLS key packages", count)

    # --- Group lifecycle ---

    async def create_group_for_feed(self, feed_id: int, member_user_ids: list[int]) -> None:
        """Create an MLS group for a feed channel and add members."""
        group_id = _group_id_for_feed(feed_id)
        await self._create_group(group_id, member_user_ids)

    async def create_group_for_dm(self, dm_id: int, participant_ids: list[int]) -> None:
        """Create an MLS group for a DM and add participants."""
        group_id = _group_id_for_dm(dm_id)
        # Filter out self — we're already the group creator
        other_ids = [uid for uid in participant_ids if uid != self._user_id]
        await self._create_group(group_id, other_ids)

    async def _create_group(self, group_id: str, member_user_ids: list[int]) -> None:
        """Create an MLS group and add members by fetching their key packages.

        Each user's devices contribute separate leaf nodes via their key
        packages, so a single user with N devices produces N leaves.
        """
        self._require_initialized()

        # Fetch MLS key packages for all members concurrently (one per device)
        async def _fetch_kps(uid: int) -> list[bytes]:
            kp_b64_list = await self._client.e2ee.get_mls_key_packages(uid)
            return [base64.b64decode(kp_b64) for kp_b64 in kp_b64_list]

        results = await asyncio.gather(*[_fetch_kps(uid) for uid in member_user_ids])
        member_kps: list[bytes] = [kp for batch in results for kp in batch]

        log.debug(
            "Creating group %s with %d key packages from %d users",
            group_id,
            len(member_kps),
            len(member_user_ids),
        )

        # Verify gateway connectivity before mutating MLS state
        if member_kps:
            gw = self._client.gateway
            if gw is None:
                raise RuntimeError(
                    "Gateway not connected — cannot relay MLS Welcome/Commit. "
                    "Call connect_gateway() before creating encrypted groups."
                )
        else:
            gw = self._client.gateway

        welcome, commit = self._engine.create_group(group_id, member_kps)

        # Relay welcome and commit via gateway
        if welcome or commit:
            if gw is None:
                raise RuntimeError(
                    "Gateway not connected — cannot relay MLS Welcome/Commit. "
                    "Call connect_gateway() before creating encrypted groups."
                )
            if welcome:
                await gw.send_mls_relay(
                    "welcome", base64.b64encode(bytes(welcome)).decode()
                )
            if commit:
                await gw.send_mls_relay(
                    "commit", base64.b64encode(bytes(commit)).decode()
                )

        log.info("Created group %s with %d members", group_id, len(member_user_ids))

    async def join_group(self, welcome_data: bytes) -> str:
        """Join a group from a Welcome message. Returns the group ID."""
        self._require_initialized()
        group_id = self._engine.join_group(welcome_data)
        log.info("Joined group %s", group_id)
        return group_id

    async def process_commit(self, commit_data: bytes, group_id: str) -> None:
        """Process an incoming MLS commit."""
        self._require_initialized()
        self._engine.process_message(group_id, commit_data)

    async def process_proposal(self, proposal_data: bytes, group_id: str) -> None:
        """Process an incoming MLS proposal."""
        self._require_initialized()
        self._engine.process_message(group_id, proposal_data)

    # --- Message encryption ---

    def encrypt_message(
        self,
        plaintext: str,
        *,
        feed_id: int | None = None,
        dm_id: int | None = None,
    ) -> str:
        """Encrypt a message for a feed or DM. Returns a base64 opaque_blob."""
        self._require_initialized()
        group_id = self._resolve_group_id(feed_id, dm_id)
        ciphertext = self._engine.encrypt(group_id, plaintext.encode())
        return base64.b64encode(bytes(ciphertext)).decode()

    def decrypt_message(
        self,
        opaque_blob: str,
        *,
        feed_id: int | None = None,
        dm_id: int | None = None,
    ) -> str:
        """Decrypt an opaque_blob from a feed or DM message."""
        self._require_initialized()
        group_id = self._resolve_group_id(feed_id, dm_id)
        ciphertext = base64.b64decode(opaque_blob)
        plaintext = self._engine.decrypt(group_id, ciphertext)
        return bytes(plaintext).decode()

    def has_group(
        self, *, feed_id: int | None = None, dm_id: int | None = None
    ) -> bool:
        """Check if we have an MLS group for a feed or DM."""
        group_id = self._resolve_group_id(feed_id, dm_id)
        return self._engine.group_exists(group_id)

    # --- Key management ---

    async def refresh_key_packages(self) -> None:
        """Upload a fresh batch of key packages to the server.

        Call periodically (e.g. on gateway reconnect) to ensure other
        users can always initiate encrypted sessions with this device.
        """
        # TODO: query server for remaining key package count and skip
        # upload if sufficient packages remain.
        self._require_initialized()
        await self.upload_key_packages(count=100)

    # --- Backup ---

    async def backup_to_server(self, passphrase: str) -> None:
        """Encrypt and upload full MLS state (identity + groups) to the server."""
        self._require_initialized()
        state_data = self._engine.export_state()
        encrypted = encrypt_backup(bytes(state_data), passphrase)
        await self._client.e2ee.upload_key_backup(encrypted)
        log.info("Full state backup uploaded")

    async def restore_from_server(self, passphrase: str) -> None:
        """Download and decrypt full MLS state from the server.

        Restores identity, all group memberships, and registers gateway
        event handlers if not already registered. After this call the
        manager is fully operational.
        """
        resp = await self._client.e2ee.download_key_backup()
        data = decrypt_backup(resp.encrypted_blob, passphrase)
        self._engine.import_state(data)
        self._initialized = True

        # Repopulate user_id and device_id from the restored database
        stored = self._engine.get_stored_identity()
        if stored is not None:
            self._user_id, self._device_id = stored

        self._register_gateway_handlers()
        log.info("Full state backup restored")

    # --- Gateway event handlers ---

    async def handle_mls_welcome(self, data: str) -> None:
        """Handle an mls_welcome gateway event."""
        welcome_bytes = base64.b64decode(data)
        await self.join_group(welcome_bytes)

    async def handle_mls_commit(self, data: str, group_id: str) -> None:
        """Handle an mls_commit gateway event."""
        commit_bytes = base64.b64decode(data)
        await self.process_commit(commit_bytes, group_id)

    async def handle_mls_proposal(self, data: str, group_id: str) -> None:
        """Handle an mls_proposal gateway event."""
        proposal_bytes = base64.b64decode(data)
        await self.process_proposal(proposal_bytes, group_id)

    # --- Internal helpers ---

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise RuntimeError("CryptoManager not initialized — call initialize() first")

    def _register_gateway_handlers(self) -> None:
        """Register MLS event handlers on the gateway if connected.

        Tracks the gateway instance by ``id()`` so handlers are re-registered
        when the gateway reconnects (new instance) but not duplicated on
        repeated calls against the same gateway.
        """
        gw = self._client.gateway
        if gw is None:
            log.debug("Gateway not connected — MLS event handlers not registered")
            return

        if id(gw) == self._registered_gateway_id:
            return

        async def _on_welcome(event: Any) -> None:
            await self.handle_mls_welcome(event.data)

        async def _on_commit(event: Any) -> None:
            await self.handle_mls_commit(event.data, event.group_id)

        async def _on_proposal(event: Any) -> None:
            await self.handle_mls_proposal(event.data, event.group_id)

        gw.add_handler("mls_welcome", _on_welcome)
        gw.add_handler("mls_commit", _on_commit)
        gw.add_handler("mls_proposal", _on_proposal)
        self._registered_gateway_id = id(gw)
        log.info("MLS gateway event handlers registered")

    def _resolve_group_id(
        self, feed_id: int | None, dm_id: int | None
    ) -> str:
        if feed_id is not None:
            return _group_id_for_feed(feed_id)
        if dm_id is not None:
            return _group_id_for_dm(dm_id)
        raise ValueError("Either feed_id or dm_id must be provided")
