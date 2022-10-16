from typing import TYPE_CHECKING, Literal

from .types import *
from .utils import MISSING

if TYPE_CHECKING:
    from .client import NginxProxyManagerClient


class Nginx:
    """Houses all nginx-related endpoints."""

    def __init__(self, client: "NginxProxyManagerClient") -> None:
        self._client: "NginxProxyManagerClient" = client

    # /nginx/proxy-hosts

    # GET /nginx/proxy-hosts

    def get_proxy_hosts(self) -> list[ProxyHostProperties]:
        """Get all proxy hosts."""

        with self._client.request("GET", "api/nginx/proxy-hosts") as response:
            return [ProxyHostProperties(**proxy_host) for proxy_host in response.json()]

    async def async_get_proxy_hosts(self) -> list[ProxyHostProperties]:
        """Get all proxy hosts."""

        async with self._client.arequest("GET", "api/nginx/proxy-hosts") as response:
            return [ProxyHostProperties(**proxy_host) for proxy_host in await response.json()]

    # POST /nginx/proxy-hosts

    def create_proxy_host(
            self,
            domain_names: list[str],
            forward_scheme: Scheme,
            forward_host: str,
            forward_post: int,
            *,
            certificate_id: int | None = None,
            ssl_forced: bool | None = None,
            hsts_enabled: bool | None = None,
            http2_support: bool | None = None,
            block_exploits: bool | None = None,
            caching_enabled: bool | None = None,
            allow_websocket_upgrade: bool | None = None,
            access_list_id: int | None = None,
            advanced_config: str | None = None,
            enabled: bool | None = None,
            meta: dict | None = None,
            locations: list[Location] | None = None,
    ) -> ProxyHostProperties:
        """Create a proxy host"""

        with self._client.request("POST", "api/nginx/proxy-hosts", json={
            "domain_names": domain_names,
            "forward_scheme": forward_scheme,
            "forward_host": forward_host,
            "forward_port": forward_post,
            "certificate_id": certificate_id,
            "ssl_forced": ssl_forced,
            "hsts_enabled": hsts_enabled,
            "http2_support": http2_support,
            "block_exploits": block_exploits,
            "caching_enabled": caching_enabled,
            "allow_websocket_upgrade": allow_websocket_upgrade,
            "access_list_id": access_list_id,
            "advanced_config": advanced_config,
            "enabled": enabled,
            "meta": meta,
            "locations": locations,
        }) as response:
            return ProxyHostProperties(**response.json())

    async def async_create_proxy_host(
            self,
            domain_names: list[str],
            forward_scheme: Scheme,
            forward_host: str,
            forward_post: int,
            *,
            certificate_id: int | None = None,
            ssl_forced: bool | None = None,
            hsts_enabled: bool | None = None,
            http2_support: bool | None = None,
            block_exploits: bool | None = None,
            caching_enabled: bool | None = None,
            allow_websocket_upgrade: bool | None = None,
            access_list_id: int | None = None,
            advanced_config: str | None = None,
            enabled: bool | None = None,
            meta: dict | None = None,
            locations: list[Location] | None = None,
    ) -> ProxyHostProperties:
        """Create a proxy host"""

        async with self._client.arequest("POST", "api/nginx/proxy-hosts", json={
            "domain_names": domain_names,
            "forward_scheme": forward_scheme,
            "forward_host": forward_host,
            "forward_port": forward_post,
            "certificate_id": certificate_id,
            "ssl_forced": ssl_forced,
            "hsts_enabled": hsts_enabled,
            "http2_support": http2_support,
            "block_exploits": block_exploits,
            "caching_enabled": caching_enabled,
            "allow_websocket_upgrade": allow_websocket_upgrade,
            "access_list_id": access_list_id,
            "advanced_config": advanced_config,
            "enabled": enabled,
            "meta": meta,
            "locations": locations,
        }) as response:
            return ProxyHostProperties(**await response.json())

    # GET /nginx/proxy-hosts/{id}

    def get_proxy_host(self, proxy_host_id: int) -> ProxyHostProperties:
        """Get a proxy host."""

        with self._client.request("GET", f"api/nginx/proxy-hosts/{proxy_host_id}") as response:
            return ProxyHostProperties(**response.json())

    async def async_get_proxy_host(self, proxy_host_id: int) -> ProxyHostProperties:
        """Get a proxy host."""

        async with self._client.arequest("GET", f"api/nginx/proxy-hosts/{proxy_host_id}") as response:
            return ProxyHostProperties(**await response.json())

    # PUT /nginx/proxy-hosts/{id}

    def update_proxy_host(
            self,
            proxy_host_id: int,
            *,
            domain_names: list[str],
            forward_scheme: Scheme,
            forward_host: str,
            forward_port: int,
            certificate_id: int | Literal["0"],
            ssl_forced: bool,
            hsts_enabled: bool,
            hsts_subdomains: bool,
            http2_support: bool,
            block_exploits: bool,
            caching_enabled: bool,
            allow_websocket_upgrade: bool,
            access_list_id: int | Literal["0"],
            advanced_config: str,
            enabled: bool,
            meta: dict,
            locations: list[Location],
    ) -> ProxyHostProperties:
        """Update a proxy host."""

        with self._client.request("PUT", f"api/nginx/proxy-hosts/{proxy_host_id}", json={
            "domain_names": domain_names,
            "forward_scheme": forward_scheme,
            "forward_host": forward_host,
            "forward_port": forward_port,
            "certificate_id": certificate_id,
            "ssl_forced": ssl_forced,
            "hsts_enabled": hsts_enabled,
            "hsts_subdomains": hsts_subdomains,
            "http2_support": http2_support,
            "block_exploits": block_exploits,
            "caching_enabled": caching_enabled,
            "allow_websocket_upgrade": allow_websocket_upgrade,
            "access_list_id": access_list_id,
            "advanced_config": advanced_config,
            "enabled": enabled,
            "meta": meta,
            "locations": locations,
        }) as response:
            return ProxyHostProperties(**response.json())

    async def async_update_proxy_host(
            self,
            proxy_host_id: int,
            *,
            domain_names: list[str],
            forward_scheme: Scheme,
            forward_host: str,
            forward_port: int,
            certificate_id: int | Literal["0"],
            ssl_forced: bool,
            hsts_enabled: bool,
            hsts_subdomains: bool,
            http2_support: bool,
            block_exploits: bool,
            caching_enabled: bool,
            allow_websocket_upgrade: bool,
            access_list_id: int | Literal["0"],
            advanced_config: str,
            enabled: bool,
            meta: dict,
            locations: list[Location],
    ) -> ProxyHostProperties:
        """Update a proxy host."""

        async with self._client.arequest("PUT", f"api/nginx/proxy-hosts/{proxy_host_id}", json={
            "domain_names": domain_names,
            "forward_scheme": forward_scheme,
            "forward_host": forward_host,
            "forward_port": forward_port,
            "certificate_id": certificate_id,
            "ssl_forced": ssl_forced,
            "hsts_enabled": hsts_enabled,
            "hsts_subdomains": hsts_subdomains,
            "http2_support": http2_support,
            "block_exploits": block_exploits,
            "caching_enabled": caching_enabled,
            "allow_websocket_upgrade": allow_websocket_upgrade,
            "access_list_id": access_list_id,
            "advanced_config": advanced_config,
            "enabled": enabled,
            "meta": meta,
            "locations": locations,
        }) as response:
            return ProxyHostProperties(**await response.json())

    # HELPER

    def helper_modify_proxy_host(
            self,
            proxy_host_id: int,
            *,
            domain_names: list[str] = MISSING,
            forward_scheme: Scheme = MISSING,
            forward_host: str = MISSING,
            forward_port: int = MISSING,
            certificate_id: int | Literal["0"] = MISSING,
            ssl_forced: bool = MISSING,
            hsts_enabled: bool = MISSING,
            hsts_subdomains: bool = MISSING,
            http2_support: bool = MISSING,
            block_exploits: bool = MISSING,
            caching_enabled: bool = MISSING,
            allow_websocket_upgrade: bool = MISSING,
            access_list_id: int | Literal["0"] = MISSING,
            advanced_config: str = MISSING,
            enabled: bool = MISSING,
            meta: dict = MISSING,
            locations: list[Location] = MISSING,
    ) -> ProxyHostProperties:
        """Update a proxy host."""

        current: ProxyHostProperties = self.get_proxy_host(proxy_host_id)

        json_out: dict = {
            "domain_names": domain_names if domain_names is not MISSING else current["domain_names"],
            "forward_scheme": forward_scheme if forward_scheme is not MISSING else current["forward_scheme"],
            "forward_host": forward_host if forward_host is not MISSING else current["forward_host"],
            "forward_port": forward_port if forward_port is not MISSING else current["forward_port"],
            "certificate_id": certificate_id if certificate_id is not MISSING else current["certificate_id"],
            "ssl_forced": ssl_forced if ssl_forced is not MISSING else bool(current["ssl_forced"]),
            "hsts_enabled": hsts_enabled if hsts_enabled is not MISSING else bool(current["hsts_enabled"]),
            "hsts_subdomains": hsts_subdomains if hsts_subdomains is not MISSING else bool(current["hsts_subdomains"]),
            "http2_support": http2_support if http2_support is not MISSING else bool(current["http2_support"]),
            "block_exploits": block_exploits if block_exploits is not MISSING else bool(current["block_exploits"]),
            "caching_enabled": caching_enabled if caching_enabled is not MISSING else bool(current["caching_enabled"]),
            "allow_websocket_upgrade": allow_websocket_upgrade if allow_websocket_upgrade is not MISSING else bool(
                current["allow_websocket_upgrade"]),
            "access_list_id": access_list_id if access_list_id is not MISSING else current["access_list_id"],
            "advanced_config": advanced_config if advanced_config is not MISSING else current["advanced_config"],
            "enabled": enabled if enabled is not MISSING else bool(current["enabled"]),
            "meta": meta if meta is not MISSING else current["meta"],
            "locations": locations if locations is not MISSING else current["locations"],
        }

        with self._client.request("PUT", f"api/nginx/proxy-hosts/{proxy_host_id}", json=json_out) as response:
            return ProxyHostProperties(**response.json())

    async def async_helper_modify_proxy_host(
            self,
            proxy_host_id: int,
            *,
            domain_names: list[str] = MISSING,
            forward_scheme: Scheme = MISSING,
            forward_host: str = MISSING,
            forward_port: int = MISSING,
            certificate_id: int | Literal["0"] = MISSING,
            ssl_forced: bool = MISSING,
            hsts_enabled: bool = MISSING,
            hsts_subdomains: bool = MISSING,
            http2_support: bool = MISSING,
            block_exploits: bool = MISSING,
            caching_enabled: bool = MISSING,
            allow_websocket_upgrade: bool = MISSING,
            access_list_id: int | Literal["0"] = MISSING,
            advanced_config: str = MISSING,
            enabled: bool = MISSING,
            meta: dict = MISSING,
            locations: list[Location] = MISSING,
    ) -> ProxyHostProperties:
        """Update a proxy host."""

        current: ProxyHostProperties = await self.async_get_proxy_host(proxy_host_id)

        json_out: dict = {
            "domain_names": domain_names if domain_names is not MISSING else current["domain_names"],
            "forward_scheme": forward_scheme if forward_scheme is not MISSING else current["forward_scheme"],
            "forward_host": forward_host if forward_host is not MISSING else current["forward_host"],
            "forward_port": forward_port if forward_port is not MISSING else current["forward_port"],
            "certificate_id": certificate_id if certificate_id is not MISSING else current["certificate_id"],
            "ssl_forced": ssl_forced if ssl_forced is not MISSING else bool(current["ssl_forced"]),
            "hsts_enabled": hsts_enabled if hsts_enabled is not MISSING else bool(current["hsts_enabled"]),
            "hsts_subdomains": hsts_subdomains if hsts_subdomains is not MISSING else bool(current["hsts_subdomains"]),
            "http2_support": http2_support if http2_support is not MISSING else bool(current["http2_support"]),
            "block_exploits": block_exploits if block_exploits is not MISSING else bool(current["block_exploits"]),
            "caching_enabled": caching_enabled if caching_enabled is not MISSING else bool(current["caching_enabled"]),
            "allow_websocket_upgrade": allow_websocket_upgrade if allow_websocket_upgrade is not MISSING else bool(
                current["allow_websocket_upgrade"]),
            "access_list_id": access_list_id if access_list_id is not MISSING else current["access_list_id"],
            "advanced_config": advanced_config if advanced_config is not MISSING else current["advanced_config"],
            "enabled": enabled if enabled is not MISSING else bool(current["enabled"]),
            "meta": meta if meta is not MISSING else current["meta"],
            "locations": locations if locations is not MISSING else current["locations"],
        }

        async with self._client.arequest("PUT", f"api/nginx/proxy-hosts/{proxy_host_id}", json=json_out) as response:
            return ProxyHostProperties(**await response.json())

    # DELETE /nginx/proxy-hosts/{id}

    def delete_proxy_host(self, proxy_host_id: int) -> bool:
        """Delete a proxy host."""

        with self._client.request("DELETE", f"api/nginx/proxy-hosts/{proxy_host_id}") as response:
            return response.ok

    async def async_delete_proxy_host(self, proxy_host_id: int) -> bool:
        """Delete a proxy host."""

        async with self._client.arequest("DELETE", f"api/nginx/proxy-hosts/{proxy_host_id}") as response:
            return response.ok

    # POST /nginx/proxy-hosts/{id}/enable

    def enable_proxy_host(self, proxy_host_id: int) -> bool:
        """Enable a proxy host."""

        with self._client.request("POST", f"api/nginx/proxy-hosts/{proxy_host_id}/enable") as response:
            return response.ok

    async def async_enable_proxy_host(self, proxy_host_id: int) -> bool:
        """Enable a proxy host."""

        async with self._client.arequest("POST", f"api/nginx/proxy-hosts/{proxy_host_id}/enable") as response:
            return response.ok

    # POST /nginx/proxy-hosts/{id}/disable

    def disable_proxy_host(self, proxy_host_id: int) -> bool:
        """Disable a proxy host."""

        with self._client.request("POST", f"api/nginx/proxy-hosts/{proxy_host_id}/disable") as response:
            return response.ok

    async def async_disable_proxy_host(self, proxy_host_id: int) -> bool:
        """Disable a proxy host."""

        async with self._client.arequest("POST", f"api/nginx/proxy-hosts/{proxy_host_id}/disable") as response:
            return response.ok

    # /nginx/redirection-hosts

    # TODO

    # /nginx/dead-hosts

    # TODO

    # /nginx/streams

    # TODO

    # /nginx/access-lists

    # TODO

    # /nginx/certificates

    # TODO


__all__: list[str] = ["Nginx"]
