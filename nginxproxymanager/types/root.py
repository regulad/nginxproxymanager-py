from typing import TypedDict, Any, Literal


class APIVersion(TypedDict):
    """API version information."""

    major: int
    minor: int
    revision: int


class TokenOut(TypedDict):
    """Token output."""

    token: str
    expires: str


class AuditLogUser(TypedDict):
    """Audit log user information."""

    avatar: str
    email: str
    is_deleted: int
    is_disabled: int
    name: str
    nickname: str


class AuditLogEntry(TypedDict):
    """Audit log entry."""

    action: str  # fixme: literal
    created_on: str
    id: int
    meta: dict
    modified_on: str
    object_id: int
    object_type: str  # fixme: literal
    user: AuditLogUser
    user_id: int


class HostsInfo(TypedDict):
    """Hosts information."""

    dead: int
    proxy: int
    redirection: int
    stream: int


class Setting(TypedDict):
    """Setting."""

    description: str
    id: str
    meta: dict
    name: str
    value: Any


UserId = int | Literal["me"]

Permission = Literal[
    "visibility", "access_lists", "dead_hosts", "proxy_hosts", "redirection_hosts", "streams", "certificates"]
Visibility = Literal["all", "user"]
PermissionState = Literal["hidden", "view", "manage"]


class User(TypedDict):
    """User."""

    id: UserId
    created_on: str
    modified_on: str
    is_disabled: int
    email: str
    name: str
    nickname: str
    avatar: str
    roles: list[str]  # fixme: literal


class UserLoginUpdate(TokenOut):
    """User login update."""

    user: User


__all__: list[str] = [
    "APIVersion",
    "TokenOut",
    "AuditLogEntry",
    "AuditLogUser",
    "HostsInfo",
    "Setting",
    "UserId",
    "User",
    "UserLoginUpdate",
    "Permission",
    "Visibility",
    "PermissionState",
]
