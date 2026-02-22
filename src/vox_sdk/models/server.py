from vox_sdk.models.base import VoxModel
from vox_sdk.models.enums import FeedType, OverrideTargetType, RoomType


class ServerInfoResponse(VoxModel):
    name: str
    icon: str | None = None
    description: str | None = None
    member_count: int = 0


class PermissionOverrideData(VoxModel):
    target_type: OverrideTargetType
    target_id: int
    allow: int
    deny: int


class FeedInfo(VoxModel):
    feed_id: int
    name: str
    type: FeedType
    topic: str | None = None
    category_id: int | None = None
    position: int = 0
    permission_overrides: list[PermissionOverrideData] = []


class RoomInfo(VoxModel):
    room_id: int
    name: str
    type: RoomType
    category_id: int | None = None
    position: int = 0
    permission_overrides: list[PermissionOverrideData] = []


class CategoryInfo(VoxModel):
    category_id: int
    name: str
    position: int


class ServerLayoutResponse(VoxModel):
    categories: list[CategoryInfo] = []
    feeds: list[FeedInfo] = []
    rooms: list[RoomInfo] = []


class GatewayInfoResponse(VoxModel):
    url: str
    media_url: str
    protocol_version: int
    min_version: int
    max_version: int
