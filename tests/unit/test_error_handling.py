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

        pydantic_module.BaseModel = BaseModel
        pydantic_module.Field = Field
        pydantic_module.ConfigDict = dict
        sys.modules["pydantic"] = pydantic_module

    if "tomli" not in sys.modules:
        import tomllib

        tomli_module = types.ModuleType("tomli")
        tomli_module.load = tomllib.load
        sys.modules["tomli"] = tomli_module

    if "starlette" not in sys.modules:
        starlette_module = types.ModuleType("starlette")
        responses_module = types.ModuleType("starlette.responses")

        class JSONResponse:  # pragma: no cover - lightweight stub
            def __init__(self, content: dict | None = None, status_code: int = 200) -> None:
                self.content = content or {}
                self.status_code = status_code

        responses_module.JSONResponse = JSONResponse
        starlette_module.responses = responses_module
        sys.modules["starlette"] = starlette_module
        sys.modules["starlette.responses"] = responses_module

    server_module = sys.modules.get("mcp.server")
    if server_module is None:
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

    class FastMCP:  # pragma: no cover - stub decorator provider
        def __init__(self, *args, **kwargs) -> None:
            pass

        def tool(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

        def custom_route(self, *args, **kwargs):  # pragma: no cover - stub decorator
            def decorator(func):
                return func

            return decorator

    fastmcp_module.Context = Context
    fastmcp_module.FastMCP = FastMCP
    resources_module = types.ModuleType("mcp.server.fastmcp.resources")
    resources_module.__path__ = []
    resources_types_module = types.ModuleType("mcp.server.fastmcp.resources.types")

    class BinaryResource:  # pragma: no cover - lightweight stub
        def __init__(self, uri: str, data: bytes, mime_type: str) -> None:
            self.uri = uri
            self.data = data
            self.mime_type = mime_type

    class TextResource:  # pragma: no cover - lightweight stub
        def __init__(self, uri: str, text: str, mime_type: str) -> None:
            self.uri = uri
            self.text = text
            self.mime_type = mime_type

    resources_types_module.BinaryResource = BinaryResource
    resources_types_module.TextResource = TextResource
    resources_types_module.ResourceContents = SimpleNamespace
    resources_module.types = resources_types_module
    fastmcp_module.resources = resources_module
    sys.modules["mcp.server.fastmcp.resources"] = resources_module
    sys.modules["mcp.server.fastmcp.resources.types"] = resources_types_module
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

        class ResourceContents:  # pragma: no cover - lightweight stub
            def __init__(self, *args, **kwargs) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

        class CallToolResult:  # pragma: no cover - lightweight stub
            def __init__(self, structuredContent=None, **kwargs) -> None:
                self.structuredContent = structuredContent
                for key, value in kwargs.items():
                    setattr(self, key, value)

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
import pyghidra_mcp.server as server


def _make_program_info(name: str) -> ProgramInfo:
    return ProgramInfo(
        name=name,
        program=SimpleNamespace(),
        flat_api=None,
        decompiler=SimpleNamespace(),
        metadata={},
        ghidra_analysis_complete=True,
        file_path=None,
        load_time=None,
        collection=object(),
        strings_collection=object(),
    )


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
        server._run_tool(
            ctx, lambda *_args: None, binary_name="sample.bin", error_message="boom"
        )

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


def test_run_tool_without_binary_uses_active_program(monkeypatch: pytest.MonkeyPatch) -> None:
    """When a tool expects a program, the active selection should be reused."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    program_info = _make_program_info("active.bin")
    context.programs = {program_info.name: program_info}
    context.active_program_name = program_info.name

    class DummyTools:
        def __init__(self, program_info):
            self.program_info = program_info

    monkeypatch.setattr(server, "GhidraTools", DummyTools)

    request_context = SimpleNamespace(lifespan_context=context)
    ctx = SimpleNamespace(request_context=request_context)

    result = server._run_tool(
        ctx,
        lambda pyghidra_context, tools: (pyghidra_context, tools.program_info.name),
        binary_name=None,
        error_message="unused",
    )

    assert result == (context, program_info.name)


def test_run_tool_without_selection_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing binary context should surface a clear INVALID_PARAMS error."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {}
    context.active_program_name = None

    request_context = SimpleNamespace(lifespan_context=context)
    ctx = SimpleNamespace(request_context=request_context)

    with pytest.raises(McpError) as excinfo:
        server._run_tool(
            ctx,
            lambda _ctx, _tools: None,
            binary_name=None,
            error_message="unused",
        )

    error = excinfo.value.error_data
    assert error.code == INVALID_PARAMS
    assert (
        error.message
        == "No binary selected. Call select_program(...) first or pass binary_name."
    )


def test_select_program_sets_active_for_future_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Selecting a program should update the active context for later tool invocations."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    program_info = _make_program_info("binary.bin")
    context.programs = {program_info.name: program_info}
    context.active_program_name = None

    captured_calls: list[dict[str, object]] = []

    class DummyTools:
        def __init__(self, program_info):
            self.program_info = program_info

        def search_symbols_by_name(self, query, offset, limit):
            captured_calls.append(
                {
                    "program": self.program_info.name,
                    "query": query,
                    "offset": offset,
                    "limit": limit,
                }
            )
            return [
                {
                    "name": "symbol",
                    "address": "0x1000",
                    "type": "function",
                    "namespace": "global",
                    "source": "USER_DEFINED",
                    "refcount": 1,
                }
            ]

    monkeypatch.setattr(server, "GhidraTools", DummyTools)

    request_context = SimpleNamespace(lifespan_context=context)
    ctx = SimpleNamespace(request_context=request_context)

    selection = server.select_program(program_info.name, ctx)
    assert context.active_program_name == program_info.name
    assert selection.name == program_info.name
    assert selection.analysis_complete is True

    search_results = server.search_symbols_by_name(
        binary_name=None, query="needle", ctx=ctx, offset=2, limit=3
    )

    assert captured_calls == [
        {"program": program_info.name, "query": "needle", "offset": 2, "limit": 3}
    ]
    assert search_results.symbols == [
        {
            "name": "symbol",
            "address": "0x1000",
            "type": "function",
            "namespace": "global",
            "source": "USER_DEFINED",
            "refcount": 1,
        }
    ]
