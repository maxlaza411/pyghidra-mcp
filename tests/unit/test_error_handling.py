"""Unit tests for improved analysis error handling."""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass
from types import SimpleNamespace

import pytest


def _ensure_stub_modules() -> None:
    """Provide lightweight stand-ins for external dependencies."""

    if "pyghidra" not in sys.modules:
        sys.modules["pyghidra"] = types.ModuleType("pyghidra")

    if "chromadb" not in sys.modules:
        chromadb_module = types.ModuleType("chromadb")
        chromadb_module.__path__ = []  # mark as package

        class _Collection:  # pragma: no cover - stub attribute holder
            pass

        class PersistentClient:  # pragma: no cover - stub
            def __init__(self, *args, **kwargs) -> None:
                pass

        chromadb_module.Collection = _Collection
        chromadb_module.PersistentClient = PersistentClient

        chromadb_config_module = types.ModuleType("chromadb.config")

        class Settings:  # pragma: no cover - stub configuration
            def __init__(self, *args, **kwargs) -> None:
                pass

        chromadb_config_module.Settings = Settings
        sys.modules["chromadb.config"] = chromadb_config_module

        chromadb_module.config = chromadb_config_module
        sys.modules["chromadb"] = chromadb_module

    if "mcp" not in sys.modules:
        try:  # pragma: no cover - use real package when installed
            import mcp as _mcp  # type: ignore
        except ModuleNotFoundError:
            mcp_module = types.ModuleType("mcp")
            mcp_module.__path__ = []
            sys.modules["mcp"] = mcp_module
        else:
            sys.modules["mcp"] = _mcp

    if "pydantic" not in sys.modules:
        pydantic_module = types.ModuleType("pydantic")

        class BaseModel:  # pragma: no cover - light-weight stand-in
            def __init__(self, **kwargs) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

        def Field(default, *args, **kwargs):  # pragma: no cover - stub behaviour
            return default

        pydantic_module.BaseModel = BaseModel
        pydantic_module.Field = Field
        sys.modules["pydantic"] = pydantic_module

    if "tomli" not in sys.modules:
        import tomllib

        tomli_module = types.ModuleType("tomli")
        tomli_module.load = tomllib.load
        sys.modules["tomli"] = tomli_module

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

    class Server:  # pragma: no cover - stub server
        pass

    server_module.Server = Server
    sys.modules["mcp.server"] = server_module

    fastmcp_module = types.ModuleType("mcp.server.fastmcp")
    fastmcp_module.__path__ = []

    class Context:  # pragma: no cover - stub context type
        def __init__(self, request_context: object | None = None) -> None:
            self.request_context = request_context

    class _Settings:  # pragma: no cover - mimic settings container
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
            **_: object,
        ) -> None:
            self.issuer_url = issuer_url
            self.resource_server_url = resource_server_url
            self.required_scopes = required_scopes

    class FastMCP:  # pragma: no cover - stub decorator provider
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.settings = _Settings()
            self._token_verifier = None
            self._session_manager = None

        def tool(self, *args: object, **kwargs: object):
            def decorator(func):
                return func

            return decorator

        def custom_route(self, *args: object, **kwargs: object):
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

    shared_package = types.ModuleType("mcp.shared")
    shared_package.__path__ = []
    sys.modules["mcp.shared"] = shared_package

    shared_exceptions = types.ModuleType("mcp.shared.exceptions")

    class McpError(Exception):
        def __init__(self, error_data):
            super().__init__(error_data.message)
            self.error_data = error_data

    shared_exceptions.McpError = McpError
    sys.modules["mcp.shared.exceptions"] = shared_exceptions
    shared_package.exceptions = shared_exceptions

    types_module = types.ModuleType("mcp.types")

    @dataclass
    class ErrorData:  # pragma: no cover - simple container
        code: str
        message: str
        data: dict | None = None

    types_module.ErrorData = ErrorData
    types_module.INTERNAL_ERROR = "INTERNAL_ERROR"
    types_module.INVALID_PARAMS = "INVALID_PARAMS"
    sys.modules["mcp.types"] = types_module

    server_module = sys.modules.get("mcp.server")
    if server_module is None:
        try:  # pragma: no cover - prefer real server module when available
            import mcp.server as server_module  # type: ignore
        except ModuleNotFoundError:
            server_module = types.ModuleType("mcp.server")
            server_module.__path__ = []

            class Server:  # pragma: no cover - stub server
                pass

            server_module.Server = Server
            sys.modules["mcp.server"] = server_module
        else:
            sys.modules["mcp.server"] = server_module

    fastmcp_module = sys.modules.get("mcp.server.fastmcp")
    if fastmcp_module is None:
        fastmcp_module = types.ModuleType("mcp.server.fastmcp")

        class Context:  # pragma: no cover - stub context type
            def __init__(self, request_context: object | None = None) -> None:
                self.request_context = request_context

        class FastMCP:  # pragma: no cover - stub decorator provider
            def __init__(self, *args, **kwargs) -> None:
                pass

            def tool(self, *args, **kwargs):
                def decorator(func):
                    return func

                return decorator

        fastmcp_module.Context = Context
        fastmcp_module.FastMCP = FastMCP
        sys.modules["mcp.server.fastmcp"] = fastmcp_module
        server_module.fastmcp = fastmcp_module

    if "mcp.shared" not in sys.modules:
        shared_package = types.ModuleType("mcp.shared")
        shared_package.__path__ = []
        sys.modules["mcp.shared"] = shared_package

    shared_exceptions = sys.modules.get("mcp.shared.exceptions")
    if shared_exceptions is None:
        shared_exceptions = types.ModuleType("mcp.shared.exceptions")

        class McpError(Exception):
            def __init__(self, error_data):
                super().__init__(error_data.message)
                self.error_data = error_data

        shared_exceptions.McpError = McpError
        sys.modules["mcp.shared.exceptions"] = shared_exceptions
        shared_package.exceptions = shared_exceptions

    types_module = sys.modules.get("mcp.types")
    if types_module is None:
        types_module = types.ModuleType("mcp.types")

        @dataclass
        class ErrorData:  # pragma: no cover - simple container
            code: str
            message: str
            data: dict | None = None

        types_module.ErrorData = ErrorData
        types_module.INTERNAL_ERROR = "INTERNAL_ERROR"
        types_module.INVALID_PARAMS = "INVALID_PARAMS"
        sys.modules["mcp.types"] = types_module


_ensure_stub_modules()

from mcp.shared.exceptions import McpError
from mcp.types import INVALID_PARAMS
from pyghidra_mcp.context import AnalysisIncompleteError, ProgramInfo, PyGhidraContext
import pyghidra_mcp.server as server

_run_tool = server._run_tool


def test_analysis_incomplete_error_details():
    """The custom exception should expose structured analysis state."""

    error = AnalysisIncompleteError(
        binary_name="sample.bin",
        ghidra_analysis_complete=False,
        code_collection_ready=False,
        strings_collection_ready=True,
        suggestion="Retry shortly.",
    )

    assert error.binary_name == "sample.bin"
    assert error.details == {
        "binary_name": "sample.bin",
        "ghidra_analysis_complete": False,
        "code_collection_ready": False,
        "strings_collection_ready": True,
        "suggestion": "Retry shortly.",
    }


def test_get_program_info_raises_analysis_incomplete_error():
    """An incomplete program should trigger the custom exception."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    program_info = ProgramInfo(
        name="sample.bin",
        program=object(),
        flat_api=None,
        decompiler=object(),
        metadata={},
        ghidra_analysis_complete=False,
    )
    context.programs = {"sample.bin": program_info}

    with pytest.raises(AnalysisIncompleteError) as excinfo:
        context.get_program_info("sample.bin")

    error = excinfo.value
    assert error.binary_name == "sample.bin"
    assert not error.ghidra_analysis_complete
    assert not error.code_collection_ready
    assert not error.strings_collection_ready


def test_run_tool_maps_analysis_incomplete_error_to_mcp_error():
    """The shared error handler should map the custom error to INVALID_PARAMS."""

    class FakeContext:
        def get_program_info(self, binary_name: str):
            raise AnalysisIncompleteError(
                binary_name=binary_name,
                ghidra_analysis_complete=False,
                code_collection_ready=False,
                strings_collection_ready=False,
            )

    request_context = SimpleNamespace(lifespan_context=FakeContext())
    ctx = SimpleNamespace(request_context=request_context)

    with pytest.raises(McpError) as excinfo:
        _run_tool(ctx, lambda *_args: None, binary_name="sample.bin", error_message="boom")

    error = excinfo.value.error_data
    assert error.code == INVALID_PARAMS
    assert "Analysis for 'sample.bin' is not complete" in error.message
    assert error.data == {
        "binary_name": "sample.bin",
        "ghidra_analysis_complete": False,
        "code_collection_ready": False,
        "strings_collection_ready": False,
        "suggestion": "Wait and try tool call again.",
    }
