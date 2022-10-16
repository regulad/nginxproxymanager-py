from logging import getLogger, Logger
from typing import Iterable, Any, TYPE_CHECKING
from urllib.parse import urljoin

from aiohttp import ClientSession, ClientTimeout
from multidict import CIMultiDict
from requests import Session
from requests.adapters import HTTPAdapter, Response, CaseInsensitiveDict
from urllib3 import Retry
from yarl import URL

from .nginx import *
from .types import *

if TYPE_CHECKING:
    from aiohttp.client import _RequestContextManager

logger: Logger = getLogger(__name__)


def http_adapter(backoff_factor: int, retries: int, extra_retry_codes: Iterable) -> HTTPAdapter:
    """Borrowed from https://github.com/iambuki/pydactyl/"""

    retry_codes: list = [429] + list(extra_retry_codes)
    retries: Retry = Retry(
        total=retries, status_forcelist=retry_codes,
        backoff_factor=backoff_factor,
        method_whitelist=['DELETE', 'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT'])
    adapter: HTTPAdapter = HTTPAdapter(max_retries=retries)
    return adapter


class NginxProxyManagerClient:
    """Client for the Nginx-Proxy-Manager API."""

    @property
    def default_headers(self) -> dict[str, str]:
        """Get the default headers."""

        return {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json",
            "Origin": self._host,
            "Referer": self._host,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            # This is probably unnecessary
        }

    def __init__(
            self,
            host: str,
            token: str | None = None,
            *,
            backoff_factor: int = 1,
            retries: int = 3,
            timeout: float = 5.0 * 60.0,  # five minute timeout
            extra_retry_codes: Iterable | None = None,
    ) -> None:
        """
        Initialize the client.

        :param should_init_async is for internal use only. Please use the async_init method.
        """

        if extra_retry_codes is None:
            extra_retry_codes = []

        self._host: str = host

        self._token: str | None = token
        self._backoff_factor: int = backoff_factor
        self._retries: int = retries
        self._timeout: float = timeout
        self._extra_retry_codes: Iterable = extra_retry_codes

        self._session: Session = Session()
        self._session.headers.update(self.default_headers)
        self._adapter: HTTPAdapter = http_adapter(self._backoff_factor, self._retries, self._extra_retry_codes)
        self._session.mount('https://', self._adapter)
        self._session.mount('http://', self._adapter)

        # async stuff
        self._asession: ClientSession | None = None
        # aiohttp has no built-in retry logic, but this library exists: https://github.com/inyutin/aiohttp_retry
        # possibly add it later.

    def close(self) -> None:
        """Close the session."""

        self._session.close()

    def __enter__(self) -> "NginxProxyManagerClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    async def aclose(self) -> None:
        """Close the async session."""

        if self._asession is not None:
            await self._asession.close()
            self._asession = None

    async def __aenter__(self) -> "NginxProxyManagerClient":
        await self._aprep()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.aclose()

    async def _aprep(self) -> None:
        """Async preparation."""

        if self._asession is None:
            self._asession = ClientSession(headers=self.default_headers, timeout=ClientTimeout(total=self._timeout))

    @classmethod
    async def async_init(cls, *args, **kwargs) -> "NginxProxyManagerClient":
        """Async initialization. This is not needed if using "async with" syntax."""

        self = cls(*args, **kwargs)
        await self._aprep()
        return self

    def request(self, method: str, path: str, *, raise_for_status: bool = True, **kwargs) -> Response:
        """Make a request."""

        full_path: str = urljoin(self._host, path)

        copy_dict: CaseInsensitiveDict = self._session.headers.copy()

        copy_dict['Authorization'] = f'Bearer {self._token or "null"}'

        response: Response = self._session.request(method, full_path, headers=copy_dict, timeout=self._timeout,
                                                   **kwargs)

        if raise_for_status:
            response.raise_for_status()

        return response

    def arequest(self, method: str, path: str, *, raise_for_status: bool = True, **kwargs) -> "_RequestContextManager":
        """Make an async request."""

        if self._asession is None:
            raise RuntimeError("Async session is not initialized.")

        full_path: str = urljoin(self._host, path)

        copy_dict: CIMultiDict = self._asession.headers.copy()

        copy_dict['Authorization'] = f'Bearer {self._token or "null"}'

        # following code is a little nasty. just a little.

        host_yarl_url: URL = URL(self._host)

        self._asession.cookie_jar.update_cookies(
            self._session.cookies.get_dict(
                host_yarl_url.host,
                host_yarl_url.path
            ),
            host_yarl_url
        )
        # todo: there is no way to sync the other way around,
        #  this could be a problem? any cookie changes would be overwritten.

        # end nasty code.

        return self._asession.request(method, full_path, headers=copy_dict, raise_for_status=raise_for_status, **kwargs)

    @property
    def nginx(self) -> Nginx:
        """Get the Nginx object."""

        return Nginx(self)

    # start api methods

    def api_status(self) -> tuple[str, APIVersion]:
        """Get the API status."""

        with self.request('GET', 'api') as response:
            json_out: dict[str, Any] = response.json()

            return json_out['status'], json_out['version']

    async def async_api_status(self) -> tuple[str, APIVersion]:
        """Get the API status."""

        async with self.arequest('GET', 'api') as response:
            json_out: dict[str, Any] = await response.json()

            return json_out['status'], json_out['version']

    # /tokens

    def authenticate(self, email: str, password: str, *, keep_token: bool = True) -> TokenOut:
        """
        Authenticate with the API.
        """
        with self.request("POST", "api/tokens", json={"identity": email, "secret": password}) as response:
            json_out: TokenOut = response.json()
            if keep_token:
                self._token = json_out["token"]
            return json_out

    async def async_authenticate(self, email: str, password: str, *, keep_token: bool = True) -> TokenOut:
        """
        Authenticate with the API.
        """
        async with self.arequest("POST", "api/tokens", json={"identity": email, "secret": password}) as response:
            json_out: TokenOut = await response.json()
            if keep_token:
                self._token = json_out["token"]
            return json_out

    def refresh(self, *, keep_token: bool = True) -> TokenOut:
        """
        Refresh the current token.
        """
        with self.request("GET", "api/tokens") as response:
            json_out: TokenOut = response.json()
            if keep_token:
                self._token = json_out["token"]
            return json_out

    async def async_refresh(self, *, keep_token: bool = True) -> TokenOut:
        """
        Refresh the current token.
        """
        async with self.arequest("GET", "api/tokens") as response:
            json_out: TokenOut = await response.json()
            if keep_token:
                self._token = json_out["token"]
            return json_out

    # /audit-log

    def get_audit_log(self) -> list[AuditLogEntry]:
        """
        Get the audit log.
        """
        with self.request("GET", "api/audit-log", params={"expand": "user"}) as response:
            return [AuditLogEntry(**entry) for entry in response.json()]

    async def async_get_audit_log(self) -> list[AuditLogEntry]:
        """
        Get the audit log.
        """
        async with self.arequest("GET", "api/audit-log", params={"expand": "user"}) as response:
            return [AuditLogEntry(**entry) for entry in await response.json()]

    # /reports/hosts

    def get_hosts(self) -> HostsInfo:
        """
        Get the hosts.
        """
        with self.request("GET", "api/hosts") as response:
            return response.json()

    async def async_get_hosts(self) -> HostsInfo:
        """
        Get the hosts.
        """
        async with self.arequest("GET", "api/reports/hosts") as response:
            return await response.json()

    # /schema

    def get_schema(self) -> dict[str, Any]:
        """
        Get the schema. No pratcical use for end user.
        """
        with self.request("GET", "api/schema") as response:
            return response.json()

    async def async_get_schema(self) -> dict[str, Any]:
        """
        Get the schema. No pratcical use for end user.
        """
        async with self.arequest("GET", "api/schema") as response:
            return await response.json()

    # /settings

    def get_settings(self) -> list[Setting]:
        """
        Get the settings.
        """
        with self.request("GET", "api/settings") as response:
            return [Setting(**setting) for setting in response.json()]

    async def async_get_settings(self) -> list[Setting]:
        """
        Get the settings.
        """
        async with self.arequest("GET", "api/settings") as response:
            return [Setting(**setting) for setting in await response.json()]

    # /settings/{settingID}

    def update_settings(self, setting: str, meta: dict, value: str) -> Setting:
        """
        Update a setting.
        """
        with self.request("PUT", f"api/settings/{setting}", json={"meta": meta, "value": value}) as response:
            return Setting(**response.json())

    async def async_update_settings(self, setting: str, meta: dict, value: str) -> Setting:
        """
        Update a setting.
        """
        async with self.arequest("PUT", f"api/settings/{setting}", json={"meta": meta, "value": value}) as response:
            return Setting(**await response.json())

    # /users

    def get_users(self, permissions: bool = True) -> list[User]:
        """
        Get the users.
        """
        with self.request("GET", "api/users", params={"expand": "permissions"} if permissions else {}) as response:
            return [User(**user) for user in response.json()]

    async def async_get_users(self, permissions: bool = True) -> list[User]:
        """
        Get the users.
        """
        async with self.arequest("GET", "api/users",
                                 params={"expand": "permissions"} if permissions else {}) as response:
            return [User(**user) for user in await response.json()]

    def add_user(
            self,
            name: str,
            nickname: str,
            email: str,
            roles: list[str],
            is_disabled: bool,
            password: str
    ) -> User:
        """
        Add a user.
        """
        with self.request("POST", "api/users", json={
            "name": name,
            "nickname": nickname,
            "email": email,
            "roles": roles,
            "is_disabled": is_disabled,
            "auth": {"type": "password", "secret": password}
        }) as response:
            return User(**response.json())

    async def async_add_user(
            self,
            name: str,
            nickname: str,
            email: str,
            roles: list[str],
            is_disabled: bool,
            password: str
    ) -> User:
        """
        Add a user.
        """
        async with self.arequest("POST", "api/users", json={
            "name": name,
            "nickname": nickname,
            "email": email,
            "roles": roles,
            "is_disabled": is_disabled,
            "auth": {"type": "password", "secret": password}
        }) as response:
            return User(**await response.json())

    # /users/{userID}

    def get_user(self, user_id: UserId = "me", permissions: bool = True) -> User:
        """
        Get a user.
        """
        with self.request("GET", f"api/users/{user_id}",
                          params={"expand": "permissions"} if permissions else {}) as response:
            return User(**response.json())

    async def async_get_user(self, user_id: UserId = "me", permissions: bool = True) -> User:
        """
        Get a user.
        """
        async with self.arequest("GET", f"api/users/{user_id}",
                                 params={"expand": "permissions"} if permissions else {}) as response:
            return User(**await response.json())

    def update_user(
            self,
            user_id: UserId,
            *,
            name: str | None,
            nickname: str | None,
            email: str | None,
            roles: list[str] | None,
            is_disabled: bool | None
    ) -> User:
        """
        Update a user.
        """
        with self.request("PUT", f"api/users/{user_id}", json={
            "name": name,
            "nickname": nickname,
            "email": email,
            "roles": roles,
            "is_disabled": is_disabled,
        }) as response:
            return User(**response.json())

    async def async_update_user(
            self,
            user_id: UserId,
            *,
            name: str | None,
            nickname: str | None,
            email: str | None,
            roles: list[str] | None,
            is_disabled: bool | None
    ) -> User:
        """
        Update a user.
        """
        async with self.arequest("PUT", f"api/users/{user_id}", json={
            "name": name,
            "nickname": nickname,
            "email": email,
            "roles": roles,
            "is_disabled": is_disabled,
        }) as response:
            return User(**await response.json())

    def delete_user(self, user_id: UserId) -> bool:
        """
        Delete a user.
        """
        with self.request("DELETE", f"api/users/{user_id}") as response:
            return response.ok

    async def async_delete_user(self, user_id: UserId) -> bool:
        """
        Delete a user.
        """
        async with self.arequest("DELETE", f"api/users/{user_id}") as response:
            return response.ok

    # /users/{userID}/auth

    def update_password(self, user_id: str, current_password: str | None, new_password: str) -> bool:
        """
        Update a user's password.
        """
        with self.request("PUT", f"api/users/{user_id}/auth",
                          json={"type": "password", "current_password": current_password,
                                "new_password": new_password}) as response:
            return response.ok

    async def async_update_password(self, user_id: str, current_password: str | None, new_password: str) -> bool:
        """
        Update a user's password.
        """
        async with self.arequest("PUT", f"api/users/{user_id}/auth",
                                 json={"type": "password", "current_password": current_password,
                                       "new_password": new_password}) as response:
            return response.ok

    # /users/{userID}/permissions

    def set_user_permissions(
            self,
            user_id: UserId,
            visibility: Visibility,
            access_lists: PermissionState | None,
            dead_hosts: PermissionState | None,
            proxy_hosts: PermissionState | None,
            redirection_hosts: PermissionState | None,
            streams: PermissionState | None,
            certificates: PermissionState | None
    ) -> bool:
        """
        Set a user's permissions.
        """
        with self.request("PUT", f"api/users/{user_id}/permissions", json={
            "visibility": visibility,
            "access_lists": access_lists,
            "dead_hosts": dead_hosts,
            "proxy_hosts": proxy_hosts,
            "redirection_hosts": redirection_hosts,
            "streams": streams,
            "certificates": certificates
        }) as response:
            return response.ok

    async def async_set_user_permissions(
            self,
            user_id: UserId,
            visibility: Visibility,
            access_lists: PermissionState | None,
            dead_hosts: PermissionState | None,
            proxy_hosts: PermissionState | None,
            redirection_hosts: PermissionState | None,
            streams: PermissionState | None,
            certificates: PermissionState | None
    ) -> bool:
        """
        Set a user's permissions.
        """
        async with self.arequest("PUT", f"api/users/{user_id}/permissions", json={
            "visibility": visibility,
            "access_lists": access_lists,
            "dead_hosts": dead_hosts,
            "proxy_hosts": proxy_hosts,
            "redirection_hosts": redirection_hosts,
            "streams": streams,
            "certificates": certificates
        }) as response:
            return response.ok

    # /users/{userID}/login

    def login_as_user(self, user_id: str, *, keep_token: bool = False) -> UserLoginUpdate:
        """
        Login as a user.
        """
        with self.request("PUT", f"api/users/{user_id}/login") as response:
            json_out: UserLoginUpdate = response.json()
            if keep_token:
                self._token = json_out["token"]
            return json_out

    async def async_login_as_user(self, user_id: str, *, keep_token: bool = False) -> UserLoginUpdate:
        """
        Login as a user.
        """
        async with self.arequest("PUT", f"api/users/{user_id}/login") as response:
            json_out: UserLoginUpdate = await response.json()
            if keep_token:
                self._token = json_out["token"]
            return json_out


__all__: list[str] = ["NginxProxyManagerClient"]
