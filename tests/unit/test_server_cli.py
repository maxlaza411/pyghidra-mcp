"""Unit tests for the server CLI entry point."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))


def _ensure_stub_modules() -> None:
    """Create lightweight stand-ins for external dependencies."""

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

    if "mcp" not in sys.modules:
        mcp_module = types.ModuleType("mcp")
        mcp_module.__path__ = []  # mark as package
        sys.modules["mcp"] = mcp_module

    server_module = sys.modules.get("mcp.server")
    if server_module is None:
        server_module = types.ModuleType("mcp.server")
        server_module.__path__ = []

        class Server:  # pragma: no cover - server placeholder
            pass

        server_module.Server = Server
        sys.modules["mcp.server"] = server_module

    fastmcp_module = sys.modules.get("mcp.server.fastmcp")
    if fastmcp_module is None:
        fastmcp_module = types.ModuleType("mcp.server.fastmcp")

        class Context:  # pragma: no cover - context stand-in
            def __init__(self, request_context: Any | None = None) -> None:
                self.request_context = request_context

        class FastMCP:  # pragma: no cover - decorator provider
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            def tool(self, *args: Any, **kwargs: Any):
                def decorator(func):
                    return func

                return decorator

        fastmcp_module.Context = Context
        fastmcp_module.FastMCP = FastMCP
        resources_module = types.ModuleType("mcp.server.fastmcp.resources")
        resources_types = types.ModuleType("mcp.server.fastmcp.resources.types")

        class BinaryResource:  # pragma: no cover - stub container
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

        class TextResource:  # pragma: no cover - stub container
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

        resources_types.BinaryResource = BinaryResource
        resources_types.TextResource = TextResource
        resources_module.types = resources_types
        sys.modules["mcp.server.fastmcp.resources.types"] = resources_types
        sys.modules["mcp.server.fastmcp.resources"] = resources_module
        fastmcp_module.resources = resources_module
        sys.modules["mcp.server.fastmcp"] = fastmcp_module
        server_module.fastmcp = fastmcp_module

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

        class ResourceContents:  # pragma: no cover - stub container
            def __init__(self, **kwargs: Any) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

        class CallToolResult:  # pragma: no cover - stub container
            def __init__(self, **kwargs: Any) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

            structuredContent: list | None = None

        types_module.ErrorData = ErrorData
        types_module.INTERNAL_ERROR = "INTERNAL_ERROR"
        types_module.INVALID_PARAMS = "INVALID_PARAMS"
        types_module.ResourceContents = ResourceContents
        types_module.CallToolResult = CallToolResult
        sys.modules["mcp.types"] = types_module

    if "pydantic" not in sys.modules:
        pydantic_module = types.ModuleType("pydantic")

        class BaseModel:  # pragma: no cover - minimal model behaviour
            def __init__(self, **kwargs: Any) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

        def Field(default: Any, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - passthrough
            return default

        class ConfigDict(dict):  # pragma: no cover - simple alias
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)

        pydantic_module.BaseModel = BaseModel
        pydantic_module.Field = Field
        pydantic_module.ConfigDict = ConfigDict
        sys.modules["pydantic"] = pydantic_module


_ensure_stub_modules()

from pyghidra_mcp import server  # noqa: E402


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
