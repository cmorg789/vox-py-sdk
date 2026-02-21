"""Permission bit flags and helpers for the Vox protocol.

Mirrors the server-side permission constants defined in PROTOCOL.md §7.
Provides a :class:`Permissions` wrapper for convenient bitfield manipulation.
"""

from __future__ import annotations


# --- Bit flags (keep in sync with server vox/permissions.py) ---

VIEW_SPACE         = 1 << 0
SEND_MESSAGES      = 1 << 1
SEND_EMBEDS        = 1 << 2
ATTACH_FILES       = 1 << 3
ADD_REACTIONS      = 1 << 4
READ_HISTORY       = 1 << 5
MENTION_EVERYONE   = 1 << 6
CONNECT            = 1 << 8
SPEAK              = 1 << 9
VIDEO              = 1 << 10
MUTE_MEMBERS       = 1 << 11
DEAFEN_MEMBERS     = 1 << 12
MOVE_MEMBERS       = 1 << 13
PRIORITY_SPEAKER   = 1 << 14
STREAM             = 1 << 15
STAGE_MODERATOR    = 1 << 16
CREATE_THREADS     = 1 << 17
MANAGE_THREADS     = 1 << 18
SEND_IN_THREADS    = 1 << 19
MANAGE_SPACES      = 1 << 24
MANAGE_ROLES       = 1 << 25
MANAGE_EMOJI       = 1 << 26
MANAGE_WEBHOOKS    = 1 << 27
MANAGE_SERVER      = 1 << 28
KICK_MEMBERS       = 1 << 29
BAN_MEMBERS        = 1 << 30
CREATE_INVITES     = 1 << 31
CHANGE_NICKNAME    = 1 << 32
MANAGE_NICKNAMES   = 1 << 33
VIEW_AUDIT_LOG     = 1 << 34
MANAGE_MESSAGES    = 1 << 35
VIEW_REPORTS       = 1 << 36
MANAGE_2FA         = 1 << 37
MANAGE_REPORTS     = 1 << 38
ADMINISTRATOR      = 1 << 62

ALL_PERMISSIONS = (1 << 63) - 1

EVERYONE_DEFAULTS = (
    VIEW_SPACE | SEND_MESSAGES | READ_HISTORY | ADD_REACTIONS
    | CONNECT | SPEAK | CREATE_INVITES | CHANGE_NICKNAME
    | CREATE_THREADS | SEND_IN_THREADS
)

# Reverse lookup: bit value -> name
_BIT_NAMES: dict[int, str] = {
    VIEW_SPACE: "VIEW_SPACE",
    SEND_MESSAGES: "SEND_MESSAGES",
    SEND_EMBEDS: "SEND_EMBEDS",
    ATTACH_FILES: "ATTACH_FILES",
    ADD_REACTIONS: "ADD_REACTIONS",
    READ_HISTORY: "READ_HISTORY",
    MENTION_EVERYONE: "MENTION_EVERYONE",
    CONNECT: "CONNECT",
    SPEAK: "SPEAK",
    VIDEO: "VIDEO",
    MUTE_MEMBERS: "MUTE_MEMBERS",
    DEAFEN_MEMBERS: "DEAFEN_MEMBERS",
    MOVE_MEMBERS: "MOVE_MEMBERS",
    PRIORITY_SPEAKER: "PRIORITY_SPEAKER",
    STREAM: "STREAM",
    STAGE_MODERATOR: "STAGE_MODERATOR",
    CREATE_THREADS: "CREATE_THREADS",
    MANAGE_THREADS: "MANAGE_THREADS",
    SEND_IN_THREADS: "SEND_IN_THREADS",
    MANAGE_SPACES: "MANAGE_SPACES",
    MANAGE_ROLES: "MANAGE_ROLES",
    MANAGE_EMOJI: "MANAGE_EMOJI",
    MANAGE_WEBHOOKS: "MANAGE_WEBHOOKS",
    MANAGE_SERVER: "MANAGE_SERVER",
    KICK_MEMBERS: "KICK_MEMBERS",
    BAN_MEMBERS: "BAN_MEMBERS",
    CREATE_INVITES: "CREATE_INVITES",
    CHANGE_NICKNAME: "CHANGE_NICKNAME",
    MANAGE_NICKNAMES: "MANAGE_NICKNAMES",
    VIEW_AUDIT_LOG: "VIEW_AUDIT_LOG",
    MANAGE_MESSAGES: "MANAGE_MESSAGES",
    VIEW_REPORTS: "VIEW_REPORTS",
    MANAGE_2FA: "MANAGE_2FA",
    MANAGE_REPORTS: "MANAGE_REPORTS",
    ADMINISTRATOR: "ADMINISTRATOR",
}


class Permissions:
    """Wraps a permission bitfield with convenient accessors.

    Can be constructed from a raw ``int``, from keyword flags, or by combining
    instances with ``|``, ``&``, ``~``, ``-``.

    Examples::

        from vox_sdk.permissions import Permissions, SEND_MESSAGES, ATTACH_FILES

        # From raw int (e.g. from API response)
        perms = Permissions(role.permissions)
        if perms.has(SEND_MESSAGES):
            ...

        # Build from flags
        perms = Permissions(SEND_MESSAGES | ATTACH_FILES)

        # Keyword constructor
        perms = Permissions.from_kwargs(send_messages=True, attach_files=True)

        # Combine
        combined = perms | Permissions(ADMINISTRATOR)

        # Check multiple at once
        perms.has(SEND_MESSAGES | ATTACH_FILES)  # True only if BOTH set

        # Iterate set flags
        for name in perms:
            print(name)  # "SEND_MESSAGES", "ATTACH_FILES", ...
    """

    __slots__ = ("_value",)

    def __init__(self, value: int = 0) -> None:
        self._value = int(value)

    # --- Factories ---

    @classmethod
    def none(cls) -> Permissions:
        """Return an empty permission set."""
        return cls(0)

    @classmethod
    def all(cls) -> Permissions:
        """Return a permission set with every bit set."""
        return cls(ALL_PERMISSIONS)

    @classmethod
    def everyone_defaults(cls) -> Permissions:
        """Return the default @everyone permission set."""
        return cls(EVERYONE_DEFAULTS)

    @classmethod
    def from_kwargs(cls, **flags: bool) -> Permissions:
        """Build from keyword arguments matching flag names (lowercase).

        Example::

            Permissions.from_kwargs(send_messages=True, administrator=True)
        """
        _name_to_bit = {name.lower(): bit for bit, name in _BIT_NAMES.items()}
        value = 0
        for key, enabled in flags.items():
            if key not in _name_to_bit:
                raise ValueError(f"Unknown permission flag: {key!r}")
            if enabled:
                value |= _name_to_bit[key]
        return cls(value)

    # --- Core accessors ---

    @property
    def value(self) -> int:
        """The raw integer bitfield."""
        return self._value

    def has(self, permissions: int | Permissions) -> bool:
        """Return ``True`` if *all* bits in ``permissions`` are set.

        If the ADMINISTRATOR bit is set, always returns ``True``.
        """
        if self._value & ADMINISTRATOR:
            return True
        required = permissions._value if isinstance(permissions, Permissions) else int(permissions)
        return (self._value & required) == required

    def has_any(self, permissions: int | Permissions) -> bool:
        """Return ``True`` if *any* bit in ``permissions`` is set."""
        if self._value & ADMINISTRATOR:
            return True
        required = permissions._value if isinstance(permissions, Permissions) else int(permissions)
        return bool(self._value & required)

    # --- Bitwise operators ---

    def __or__(self, other: int | Permissions) -> Permissions:
        other_val = other._value if isinstance(other, Permissions) else int(other)
        return Permissions(self._value | other_val)

    def __and__(self, other: int | Permissions) -> Permissions:
        other_val = other._value if isinstance(other, Permissions) else int(other)
        return Permissions(self._value & other_val)

    def __sub__(self, other: int | Permissions) -> Permissions:
        """Remove bits: ``perms - SEND_MESSAGES``."""
        other_val = other._value if isinstance(other, Permissions) else int(other)
        return Permissions(self._value & ~other_val)

    def __invert__(self) -> Permissions:
        return Permissions(~self._value & ALL_PERMISSIONS)

    def __contains__(self, flag: int) -> bool:
        """Support ``SEND_MESSAGES in perms``."""
        return self.has(flag)

    # --- Override helpers ---

    def apply_override(self, *, allow: int | Permissions, deny: int | Permissions) -> Permissions:
        """Apply a permission override pair, returning new Permissions.

        Follows the standard override formula: ``(base & ~deny) | allow``.
        """
        allow_val = allow._value if isinstance(allow, Permissions) else int(allow)
        deny_val = deny._value if isinstance(deny, Permissions) else int(deny)
        return Permissions((self._value & ~deny_val) | allow_val)

    # --- Iteration & display ---

    def __iter__(self):
        """Yield the name of each set permission flag."""
        for bit, name in _BIT_NAMES.items():
            if self._value & bit:
                yield name

    def __repr__(self) -> str:
        if self._value == 0:
            return "Permissions(0)"
        names = list(self)
        if len(names) <= 5:
            return f"Permissions({' | '.join(names)})"
        return f"Permissions({' | '.join(names[:4])} | ... +{len(names) - 4} more)"

    def __str__(self) -> str:
        return repr(self)

    def to_list(self) -> list[str]:
        """Return a list of set permission flag names."""
        return list(self)

    # --- Equality & hashing ---

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Permissions):
            return self._value == other._value
        if isinstance(other, int):
            return self._value == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)

    def __int__(self) -> int:
        return self._value

    def __bool__(self) -> bool:
        return self._value != 0
