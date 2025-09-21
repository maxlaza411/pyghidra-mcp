"""Unit tests for improved analysis error handling."""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))


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

    starlette_module = sys.modules.get("starlette")
    if starlette_module is None:
        starlette_module = types.ModuleType("starlette")
        starlette_module.__path__ = []
        sys.modules["starlette"] = starlette_module

    responses_module = sys.modules.get("starlette.responses")
    if responses_module is None:
        responses_module = types.ModuleType("starlette.responses")

        class JSONResponse:  # pragma: no cover - stub implementation
            def __init__(
                self,
                content,
                status_code: int = 200,
                headers=None,
                media_type: str | None = None,
                background=None,
            ) -> None:
                self.content = content
                self.status_code = status_code
                self.headers = headers
                self.media_type = media_type
                self.background = background

        responses_module.JSONResponse = JSONResponse
        sys.modules["starlette.responses"] = responses_module

    starlette_module.responses = responses_module

    if "mcp" not in sys.modules:
        mcp_module = types.ModuleType("mcp")
        mcp_module.__path__ = []
        sys.modules["mcp"] = mcp_module

    if "pydantic" not in sys.modules:
        pydantic_module = types.ModuleType("pydantic")

        class BaseModel:  # pragma: no cover - light-weight stand-in
            def __init__(self, **kwargs) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

        def Field(default, *args, **kwargs):  # pragma: no cover - stub behaviour
            return default

        class ConfigDict(dict):  # pragma: no cover - simple alias
            def __init__(self, *args, **kwargs) -> None:
                super().__init__(*args, **kwargs)

        pydantic_module.BaseModel = BaseModel
        pydantic_module.Field = Field
        pydantic_module.ConfigDict = ConfigDict
        sys.modules["pydantic"] = pydantic_module

    if "tomli" not in sys.modules:
        import tomllib

        tomli_module = types.ModuleType("tomli")
        tomli_module.load = tomllib.load
        sys.modules["tomli"] = tomli_module

    server_module = sys.modules.get("mcp.server")
    if server_module is None:
        server_module = types.ModuleType("mcp.server")
        server_module.__path__ = []

        class Server:  # pragma: no cover - stub server
            pass

        server_module.Server = Server
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
        resources_module = types.ModuleType("mcp.server.fastmcp.resources")
        resources_types = types.ModuleType("mcp.server.fastmcp.resources.types")

        class BinaryResource:  # pragma: no cover - stub container
            def __init__(self, *args, **kwargs) -> None:
                pass

        class TextResource:  # pragma: no cover - stub container
            def __init__(self, *args, **kwargs) -> None:
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

        class ResourceContents:  # pragma: no cover - stub container
            def __init__(self, **kwargs) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

        class CallToolResult:  # pragma: no cover - stub container
            def __init__(self, **kwargs) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

            structuredContent: list | None = None

        types_module.ErrorData = ErrorData
        types_module.INTERNAL_ERROR = "INTERNAL_ERROR"
        types_module.INVALID_PARAMS = "INVALID_PARAMS"
        types_module.ResourceContents = ResourceContents
        types_module.CallToolResult = CallToolResult
        sys.modules["mcp.types"] = types_module


_ensure_stub_modules()

from mcp.shared.exceptions import McpError
from mcp.types import INVALID_PARAMS
from pyghidra_mcp.context import AnalysisIncompleteError, ProgramInfo, PyGhidraContext
from pyghidra_mcp.server import _run_tool, select_program


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


def test_select_program_sets_active_binary():
    """The selection tool should validate analysis state and persist the choice."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    program_info = ProgramInfo(
        name="binary",
        program=object(),
        flat_api=None,
        decompiler=object(),
        metadata={},
        ghidra_analysis_complete=True,
        file_path=None,
        load_time=0.0,
        collection=object(),
        strings_collection=object(),
    )
    context.programs = {"binary": program_info}
    context.active_program_name = None

    request_context = SimpleNamespace(lifespan_context=context)
    ctx = SimpleNamespace(request_context=request_context)

    result = select_program("binary", ctx)

    assert result.name == "binary"
    assert result.analysis_complete is True
    assert context.active_program_name == "binary"


def test_run_tool_uses_active_program_when_binary_missing():
    """Tool helpers should fall back to the selected program when none is provided."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    program_info = ProgramInfo(
        name="binary",
        program=object(),
        flat_api=None,
        decompiler=object(),
        metadata={},
        ghidra_analysis_complete=True,
        file_path=None,
        load_time=0.0,
        collection=object(),
        strings_collection=object(),
    )
    context.programs = {"binary": program_info}
    context.active_program_name = None

    request_context = SimpleNamespace(lifespan_context=context)
    ctx = SimpleNamespace(request_context=request_context)

    select_program("binary", ctx)

    captured: dict[str, str] = {}

    def fake_tool(_pyghidra_context, tools):
        captured["name"] = tools.program_info.name
        return "ok"

    assert _run_tool(ctx, fake_tool, error_message="should use active") == "ok"
    assert captured == {"name": "binary"}


def test_run_tool_without_selection_raises_clear_error():
    """Invocations needing tools should explain when no program is selected."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {}
    context.active_program_name = None

    request_context = SimpleNamespace(lifespan_context=context)
    ctx = SimpleNamespace(request_context=request_context)

    with pytest.raises(McpError) as excinfo:
        _run_tool(ctx, lambda _ctx, _tools: None, error_message="unused")

    message = excinfo.value.error_data.message
    assert message.startswith("No active program selected")
