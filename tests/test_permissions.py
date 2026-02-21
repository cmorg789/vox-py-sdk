"""Tests for the permissions helper module."""

import pytest

from vox_sdk.permissions import (
    ADMINISTRATOR,
    ALL_PERMISSIONS,
    ATTACH_FILES,
    BAN_MEMBERS,
    CONNECT,
    EVERYONE_DEFAULTS,
    KICK_MEMBERS,
    MANAGE_ROLES,
    MANAGE_SERVER,
    MANAGE_SPACES,
    READ_HISTORY,
    SEND_EMBEDS,
    SEND_MESSAGES,
    VIEW_SPACE,
    Permissions,
)


class TestBitConstants:
    def test_view_space_is_bit_0(self):
        assert VIEW_SPACE == 1

    def test_administrator_is_bit_62(self):
        assert ADMINISTRATOR == 1 << 62

    def test_all_permissions(self):
        assert ALL_PERMISSIONS == (1 << 63) - 1

    def test_everyone_defaults_include_expected(self):
        assert EVERYONE_DEFAULTS & VIEW_SPACE
        assert EVERYONE_DEFAULTS & SEND_MESSAGES
        assert EVERYONE_DEFAULTS & READ_HISTORY
        assert not (EVERYONE_DEFAULTS & ADMINISTRATOR)
        assert not (EVERYONE_DEFAULTS & BAN_MEMBERS)


class TestPermissionsInit:
    def test_from_int(self):
        p = Permissions(SEND_MESSAGES | ATTACH_FILES)
        assert p.value == SEND_MESSAGES | ATTACH_FILES

    def test_default_zero(self):
        p = Permissions()
        assert p.value == 0

    def test_none_factory(self):
        assert Permissions.none().value == 0

    def test_all_factory(self):
        assert Permissions.all().value == ALL_PERMISSIONS

    def test_everyone_defaults_factory(self):
        assert Permissions.everyone_defaults().value == EVERYONE_DEFAULTS

    def test_from_kwargs(self):
        p = Permissions.from_kwargs(send_messages=True, attach_files=True, view_space=False)
        assert p.value == SEND_MESSAGES | ATTACH_FILES

    def test_from_kwargs_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown permission flag"):
            Permissions.from_kwargs(not_a_real_flag=True)


class TestHas:
    def test_has_single(self):
        p = Permissions(SEND_MESSAGES | ATTACH_FILES)
        assert p.has(SEND_MESSAGES)
        assert not p.has(BAN_MEMBERS)

    def test_has_multiple(self):
        p = Permissions(SEND_MESSAGES | ATTACH_FILES)
        assert p.has(SEND_MESSAGES | ATTACH_FILES)
        assert not p.has(SEND_MESSAGES | BAN_MEMBERS)

    def test_administrator_bypasses(self):
        p = Permissions(ADMINISTRATOR)
        assert p.has(SEND_MESSAGES)
        assert p.has(BAN_MEMBERS | KICK_MEMBERS | MANAGE_SERVER)

    def test_has_with_permissions_instance(self):
        p = Permissions(SEND_MESSAGES | ATTACH_FILES)
        required = Permissions(SEND_MESSAGES)
        assert p.has(required)

    def test_has_any_single(self):
        p = Permissions(SEND_MESSAGES)
        assert p.has_any(SEND_MESSAGES | BAN_MEMBERS)
        assert not p.has_any(BAN_MEMBERS | KICK_MEMBERS)

    def test_has_any_administrator(self):
        p = Permissions(ADMINISTRATOR)
        assert p.has_any(BAN_MEMBERS)


class TestOperators:
    def test_or_permissions(self):
        a = Permissions(SEND_MESSAGES)
        b = Permissions(ATTACH_FILES)
        c = a | b
        assert c.value == SEND_MESSAGES | ATTACH_FILES

    def test_or_int(self):
        p = Permissions(SEND_MESSAGES) | ATTACH_FILES
        assert p.value == SEND_MESSAGES | ATTACH_FILES

    def test_and(self):
        p = Permissions(SEND_MESSAGES | ATTACH_FILES) & Permissions(SEND_MESSAGES | BAN_MEMBERS)
        assert p.value == SEND_MESSAGES

    def test_sub(self):
        p = Permissions(SEND_MESSAGES | ATTACH_FILES) - ATTACH_FILES
        assert p.value == SEND_MESSAGES

    def test_invert(self):
        p = ~Permissions(ALL_PERMISSIONS)
        assert p.value == 0

    def test_contains(self):
        p = Permissions(SEND_MESSAGES | ATTACH_FILES)
        assert SEND_MESSAGES in p
        assert BAN_MEMBERS not in p


class TestApplyOverride:
    def test_basic_override(self):
        base = Permissions(SEND_MESSAGES | READ_HISTORY)
        result = base.apply_override(allow=ATTACH_FILES, deny=SEND_MESSAGES)
        assert result.has(ATTACH_FILES)
        assert result.has(READ_HISTORY)
        assert not result.has(SEND_MESSAGES)

    def test_override_with_permissions_instances(self):
        base = Permissions(SEND_MESSAGES)
        result = base.apply_override(
            allow=Permissions(ATTACH_FILES),
            deny=Permissions(SEND_MESSAGES),
        )
        assert result.value == ATTACH_FILES


class TestIteration:
    def test_iter_names(self):
        p = Permissions(SEND_MESSAGES | ATTACH_FILES)
        names = list(p)
        assert "SEND_MESSAGES" in names
        assert "ATTACH_FILES" in names
        assert len(names) == 2

    def test_to_list(self):
        p = Permissions(VIEW_SPACE)
        assert p.to_list() == ["VIEW_SPACE"]

    def test_empty_iter(self):
        assert list(Permissions()) == []


class TestRepr:
    def test_zero(self):
        assert repr(Permissions()) == "Permissions(0)"

    def test_single(self):
        assert "SEND_MESSAGES" in repr(Permissions(SEND_MESSAGES))

    def test_truncated(self):
        p = Permissions(ALL_PERMISSIONS)
        r = repr(p)
        assert "..." in r or "more" in r


class TestEquality:
    def test_eq_permissions(self):
        assert Permissions(SEND_MESSAGES) == Permissions(SEND_MESSAGES)

    def test_eq_int(self):
        assert Permissions(SEND_MESSAGES) == SEND_MESSAGES

    def test_ne(self):
        assert Permissions(SEND_MESSAGES) != Permissions(ATTACH_FILES)

    def test_hash(self):
        assert hash(Permissions(42)) == hash(42)

    def test_int_conversion(self):
        assert int(Permissions(SEND_MESSAGES)) == SEND_MESSAGES

    def test_bool_truthy(self):
        assert bool(Permissions(SEND_MESSAGES))
        assert not bool(Permissions(0))
