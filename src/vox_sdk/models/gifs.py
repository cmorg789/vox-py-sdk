"""GIF search response models."""

from __future__ import annotations

from vox_sdk.models.base import VoxModel


class GifMediaFormat(VoxModel):
    url: str
    width: int
    height: int


class GifResult(VoxModel):
    id: str
    title: str
    media_formats: dict[str, GifMediaFormat]


class GifSearchResponse(VoxModel):
    results: list[GifResult]
    next: str | None = None
