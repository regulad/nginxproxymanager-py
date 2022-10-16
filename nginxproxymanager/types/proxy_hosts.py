from typing import Literal, TypedDict

Scheme = Literal["http", "https"]


class Location(TypedDict):
    id: int | None
    path: str
    forward_scheme: Scheme
    forward_host: str
    forward_port: int
    advanced_config: str


class BaseOwner(TypedDict):
    name: str
    nickname: str
    avatar: str
    is_disabled: Literal[0, 1]


class Certificate(TypedDict):
    domain_names: list[str]
    expires_on: str  # datetime
    meta: dict
    nice_name: str
    owner_user_id: int
    provider: str


class AccessList(TypedDict):
    pass  # todo


class ProxyHostProperties(TypedDict):
    id: int
    created_on: str  # datetime
    modified_on: str  # datetime
    domain_names: list[str]
    forward_scheme: Scheme
    forward_host: str
    forward_port: int
    certificate_id: int | Literal["0"]
    ssl_forced: Literal[0, 1]
    hsts_enabled: Literal[0, 1]
    hsts_subdomains: Literal[0, 1]
    http2_support: Literal[0, 1]
    block_exploits: Literal[0, 1]
    caching_enabled: Literal[0, 1]
    allow_websocket_upgrade: Literal[0, 1]
    access_list_id: int | Literal["0"]
    advanced_config: str
    enabled: Literal[0, 1]
    meta: dict
    locations: list[Location]
    # expanded
    certificate: Certificate | None
    access_list: AccessList | None
    owner: BaseOwner


__all__: list[str] = ["ProxyHostProperties", "Location", "Scheme", "BaseOwner"]
