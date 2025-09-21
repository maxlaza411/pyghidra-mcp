"""Unit tests for the server CLI entry point."""

from __future__ import annotations

import asyncio
import sys
import types
from typing import Any

import pytest
from click.testing import CliRunner


def _ensure_stub_modules() -> None:
    """Create lightweight stand-ins for external dependencies."""

    if "src" not in sys.path:
        sys.path.insert(0, "src")

    if "pyghidra" not in sys.modules:
        sys.modules["pyghidra"] = types.ModuleType("pyghidra")

    if "chromadb" not in sys.modules:
        chromadb_module = types.ModuleType("chromadb")

        class Collection:  # pragma: no cover - attribute placeholder
            pass

        class PersistentClient:  # pragma: no cover - lightweight stub
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

        chromadb_module.Collection = Collection
        chromadb_module.PersistentClient = PersistentClient

        chromadb_config_module = types.ModuleType("chromadb.config")

        class Settings:  # pragma: no cover - configuration placeholder
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

        chromadb_config_module.Settings = Settings
        chromadb_module.config = chromadb_config_module

        sys.modules["chromadb"] = chromadb_module
        sys.modules["chromadb.config"] = chromadb_config_module

    # Reset MCP-related modules to provide deterministic stubs.
    for module_name in [
        "mcp.server.fastmcp.server",
        "mcp.server.fastmcp",
        "mcp.server.auth.provider",
        "mcp.server.auth",
        "mcp.server",
        "mcp.shared.exceptions",
        "mcp.shared",
        "mcp.types",
        "mcp",
    ]:
        sys.modules.pop(module_name, None)

    mcp_module = types.ModuleType("mcp")
    mcp_module.__path__ = []
    sys.modules["mcp"] = mcp_module

    server_module = types.ModuleType("mcp.server")
    server_module.__path__ = []

    class Server:  # pragma: no cover - server placeholder
        pass

    server_module.Server = Server
    sys.modules["mcp.server"] = server_module

    fastmcp_module = types.ModuleType("mcp.server.fastmcp")
    fastmcp_module.__path__ = []

    class Context:  # pragma: no cover - context stand-in
        def __init__(self, request_context: Any | None = None) -> None:
            self.request_context = request_context

    class _Settings:  # pragma: no cover - track configuration mutations
        def __init__(self) -> None:
            self.host = "127.0.0.1"
            self.port = 8000
            self.transport_security = None
            self.auth = None
            self.streamable_http_path = "/mcp"
            self.mount_path = "/"
            self.message_path = "/messages/"
            self.sse_path = "/sse"
            self.json_response = False
            self.stateless_http = False

    class TransportSecuritySettings:  # pragma: no cover - lightweight container
        def __init__(
            self,
            *,
            enable_dns_rebinding_protection: bool = False,
            allowed_hosts: list[str] | None = None,
            allowed_origins: list[str] | None = None,
        ) -> None:
            self.enable_dns_rebinding_protection = enable_dns_rebinding_protection
            self.allowed_hosts = list(allowed_hosts or [])
            self.allowed_origins = list(allowed_origins or [])

    class AuthSettings:  # pragma: no cover - minimal auth model
        def __init__(
            self,
            issuer_url: str,
            resource_server_url: str | None = None,
            required_scopes: list[str] | None = None,
            **_: Any,
        ) -> None:
            self.issuer_url = issuer_url
            self.resource_server_url = resource_server_url
            self.required_scopes = required_scopes

    class FastMCP:  # pragma: no cover - decorator provider
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.settings = _Settings()
            self._token_verifier = None
            self._session_manager = None

        def tool(self, *args: Any, **kwargs: Any):
            def decorator(func):
                return func

            return decorator

        def custom_route(self, *args: Any, **kwargs: Any):
            def decorator(func):
                return func

            return decorator

        def run(self, *, transport: str) -> None:  # pragma: no cover - patched in tests
            raise NotImplementedError

    server_submodule = types.ModuleType("mcp.server.fastmcp.server")
    server_submodule.AuthSettings = AuthSettings
    server_submodule.TransportSecuritySettings = TransportSecuritySettings
    sys.modules["mcp.server.fastmcp.server"] = server_submodule

    fastmcp_module.Context = Context
    fastmcp_module.FastMCP = FastMCP
    fastmcp_module.TransportSecuritySettings = TransportSecuritySettings
    fastmcp_module.AuthSettings = AuthSettings
    fastmcp_module.server = server_submodule
    sys.modules["mcp.server.fastmcp"] = fastmcp_module
    server_module.fastmcp = fastmcp_module

    auth_module = types.ModuleType("mcp.server.auth")
    auth_module.__path__ = []
    sys.modules["mcp.server.auth"] = auth_module

    provider_module = types.ModuleType("mcp.server.auth.provider")

    class AccessToken:  # pragma: no cover - minimal token representation
        def __init__(
            self,
            token: str,
            client_id: str,
            scopes: list[str] | None = None,
            expires_at: int | None = None,
        ) -> None:
            self.token = token
            self.client_id = client_id
            self.scopes = scopes or []
            self.expires_at = expires_at

    class TokenVerifier:  # pragma: no cover - protocol mimic
        async def verify_token(self, token: str) -> AccessToken | None:
            raise NotImplementedError

    provider_module.AccessToken = AccessToken
    provider_module.TokenVerifier = TokenVerifier
    sys.modules["mcp.server.auth.provider"] = provider_module
    auth_module.provider = provider_module

    if "mcp.shared" not in sys.modules:
        shared_package = types.ModuleType("mcp.shared")
        shared_package.__path__ = []
        sys.modules["mcp.shared"] = shared_package

    shared_exceptions = sys.modules.get("mcp.shared.exceptions")
    if shared_exceptions is None:
        shared_exceptions = types.ModuleType("mcp.shared.exceptions")

        class McpError(Exception):  # pragma: no cover - basic error type
            def __init__(self, error_data: Any) -> None:
                super().__init__(error_data.message)
                self.error_data = error_data

        shared_exceptions.McpError = McpError
        sys.modules["mcp.shared.exceptions"] = shared_exceptions
        sys.modules["mcp.shared"].exceptions = shared_exceptions

    types_module = sys.modules.get("mcp.types")
    if types_module is None:
        types_module = types.ModuleType("mcp.types")

        class ErrorData:  # pragma: no cover - error payload container
            def __init__(self, code: str, message: str, data: Any | None = None) -> None:
                self.code = code
                self.message = message
                self.data = data

        types_module.ErrorData = ErrorData
        types_module.INTERNAL_ERROR = "INTERNAL_ERROR"
        types_module.INVALID_PARAMS = "INVALID_PARAMS"
        sys.modules["mcp.types"] = types_module

    if "pydantic" not in sys.modules:
        pydantic_module = types.ModuleType("pydantic")

        class BaseModel:  # pragma: no cover - minimal model behaviour
            def __init__(self, **kwargs: Any) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

        def Field(default: Any, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - passthrough
            return default

        pydantic_module.BaseModel = BaseModel
        pydantic_module.Field = Field
        sys.modules["pydantic"] = pydantic_module


_ensure_stub_modules()

import pyghidra_mcp.server as server  # noqa: E402


@pytest.mark.parametrize(
    ("transport", "should_raise"),
    [
        ("stdio", False),
        ("streamable-http", True),
        ("sse", False),
    ],
)
def test_main_invokes_run_and_closes_context(monkeypatch: pytest.MonkeyPatch, transport: str, should_raise: bool) -> None:
    """Each supported transport should reach `mcp.run` and always close the context."""

    runner = CliRunner()

    run_calls: list[str] = []

    def fake_run(*, transport: str) -> None:
        run_calls.append(transport)
        if should_raise:
            raise RuntimeError("run failed")

    monkeypatch.setattr(server.mcp, "run", fake_run, raising=False)

    close_calls: list[str] = []
    fake_context = types.SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(server.mcp, "_pyghidra_context", fake_context, raising=False)

    def fake_close() -> None:
        close_calls.append("closed")

    monkeypatch.setattr(fake_context, "close", fake_close)

    init_calls: list[tuple[Any, tuple[str, ...], str, str]] = []

    def fake_init(
        mcp_obj: Any,
        input_paths: tuple[str, ...],
        project_name: str,
        project_directory: str,
    ) -> None:
        init_calls.append((mcp_obj, input_paths, project_name, project_directory))

    monkeypatch.setattr(server, "init_pyghidra_context", fake_init)

    result = runner.invoke(server.main, ["--transport", transport])

    assert run_calls == [transport]
    assert len(init_calls) == 1
    assert init_calls[0][0] is server.mcp
    assert close_calls == ["closed"]

    expected_exit = 1 if should_raise else 0
    assert result.exit_code == expected_exit
    if should_raise:
        assert isinstance(result.exception, RuntimeError)
        assert str(result.exception) == "run failed"
    else:
        assert result.exception is None


def test_main_rejects_invalid_transport() -> None:
    """Providing an unsupported transport should yield a helpful error message."""

    runner = CliRunner()
    result = runner.invoke(server.main, ["--transport", "invalid"])

    assert result.exit_code == 2
    assert (
        "Invalid value for '-t' / '--transport': 'invalid' is not one of 'stdio',"
        " 'streamable-http', 'sse'." in result.output
    )


def test_main_configures_http_security(monkeypatch: pytest.MonkeyPatch) -> None:
    """HTTP transports should configure binding, security allowlists, and authentication."""

    runner = CliRunner()

    monkeypatch.setattr(server.mcp, "run", lambda *, transport: None, raising=False)
    monkeypatch.setattr(server, "init_pyghidra_context", lambda *args, **kwargs: None)

    result = runner.invoke(
        server.main,
        [
            "--transport",
            "streamable-http",
            "--http-host",
            "127.0.0.1",
            "--http-port",
            "9001",
            "--auth-token",
            "secret-token",
            "--allowed-origin",
            "http://example.com",
        ],
    )

    assert result.exit_code == 0
    assert server.mcp.settings.host == "127.0.0.1"
    assert server.mcp.settings.port == 9001

    security = server.mcp.settings.transport_security
    assert security is not None
    assert security.enable_dns_rebinding_protection is True
    assert "127.0.0.1:9001" in security.allowed_hosts
    assert "http://example.com" in security.allowed_origins

    verifier = server.mcp._token_verifier
    assert verifier is not None
    assert asyncio.run(verifier.verify_token("secret-token")) is not None
    assert asyncio.run(verifier.verify_token("wrong")) is None

    # Cleanup mutated global state for subsequent tests
    server.mcp._token_verifier = None
    server.mcp.settings.auth = None
    server.mcp.settings.transport_security = None
