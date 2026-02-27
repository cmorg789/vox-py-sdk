"""GIF search API methods."""

from __future__ import annotations

from typing import TYPE_CHECKING

from vox_sdk.models.gifs import GifSearchResponse

if TYPE_CHECKING:
    from vox_sdk.http import HTTPClient


class GifsAPI:
    def __init__(self, http: HTTPClient) -> None:
        self._http = http

    async def search(self, query: str, limit: int = 20) -> GifSearchResponse:
        r = await self._http.get("/api/v1/gifs/search", params={"q": query, "limit": limit})
        return GifSearchResponse.model_validate(r.json())

    async def trending(self, limit: int = 20) -> GifSearchResponse:
        r = await self._http.get("/api/v1/gifs/trending", params={"limit": limit})
        return GifSearchResponse.model_validate(r.json())
