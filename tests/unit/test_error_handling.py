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
from pyghidra_mcp.server import _run_tool


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
