"""Unit tests for :mod:`pyghidra_mcp.context`."""

from __future__ import annotations

import hashlib
import sys
import types
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))


def _ensure_context_dependencies() -> None:
    """Provide stub modules required to import the context module."""

    if "pyghidra" not in sys.modules:
        sys.modules["pyghidra"] = types.ModuleType("pyghidra")

    chromadb_module = sys.modules.get("chromadb")
    if chromadb_module is None:
        chromadb_module = types.ModuleType("chromadb")
        chromadb_module.__path__ = []  # mark as package for import machinery
        sys.modules["chromadb"] = chromadb_module

    if not hasattr(chromadb_module, "Collection"):
        class _Collection:  # pragma: no cover - lightweight stub
            pass

        chromadb_module.Collection = _Collection

    if not hasattr(chromadb_module, "PersistentClient"):
        class PersistentClient:  # pragma: no cover - lightweight stub
            def __init__(self, *args, **kwargs) -> None:
                pass

        chromadb_module.PersistentClient = PersistentClient

    chromadb_config_module = sys.modules.get("chromadb.config")
    if chromadb_config_module is None:
        chromadb_config_module = types.ModuleType("chromadb.config")
        sys.modules["chromadb.config"] = chromadb_config_module

    if not hasattr(chromadb_config_module, "Settings"):
        class Settings:  # pragma: no cover - lightweight stub
            def __init__(self, *args, **kwargs) -> None:
                pass

        chromadb_config_module.Settings = Settings

    chromadb_module.config = chromadb_config_module

    if "mcp" not in sys.modules:
        mcp_module = types.ModuleType("mcp")
        mcp_module.__path__ = []
        sys.modules["mcp"] = mcp_module
    else:
        mcp_module = sys.modules["mcp"]

    server_module = sys.modules.get("mcp.server")
    if server_module is None:
        server_module = types.ModuleType("mcp.server")
        server_module.__path__ = []

        class Server:  # pragma: no cover - lightweight stub
            pass

        server_module.Server = Server
        sys.modules["mcp.server"] = server_module
        mcp_module.server = server_module

    fastmcp_module = sys.modules.get("mcp.server.fastmcp")
    if fastmcp_module is None:
        fastmcp_module = types.ModuleType("mcp.server.fastmcp")

        class Context:  # pragma: no cover - lightweight stub
            def __init__(self, request_context: object | None = None) -> None:
                self.request_context = request_context

        class FastMCP:  # pragma: no cover - lightweight stub
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

        class BinaryResource:  # pragma: no cover - lightweight stub
            def __init__(self, *args, **kwargs) -> None:
                pass

        class TextResource:  # pragma: no cover - lightweight stub
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
        shared_module = types.ModuleType("mcp.shared")
        shared_module.__path__ = []
        sys.modules["mcp.shared"] = shared_module
    else:
        shared_module = sys.modules["mcp.shared"]

    shared_exceptions = sys.modules.get("mcp.shared.exceptions")
    if shared_exceptions is None:
        shared_exceptions = types.ModuleType("mcp.shared.exceptions")

        class McpError(Exception):  # pragma: no cover - lightweight stub
            def __init__(self, error_data):
                super().__init__(getattr(error_data, "message", ""))
                self.error_data = error_data

        shared_exceptions.McpError = McpError
        sys.modules["mcp.shared.exceptions"] = shared_exceptions
        shared_module.exceptions = shared_exceptions

    types_module = sys.modules.get("mcp.types")
    if types_module is None:
        types_module = types.ModuleType("mcp.types")

        class ErrorData:  # pragma: no cover - lightweight stub
            def __init__(self, code: str, message: str, data: dict | None = None) -> None:
                self.code = code
                self.message = message
                self.data = data

        class ResourceContents:  # pragma: no cover - lightweight stub
            def __init__(self, **kwargs) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

        class CallToolResult:  # pragma: no cover - lightweight stub
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

    if "pydantic" not in sys.modules:
        pydantic_module = types.ModuleType("pydantic")

        class BaseModel:  # pragma: no cover - lightweight stub
            def __init__(self, **kwargs) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

        def Field(default, *args, **kwargs):  # pragma: no cover - lightweight stub
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


_ensure_context_dependencies()

from pyghidra_mcp.context import (  # noqa: E402 - imported after dependency stubs
    AnalysisIncompleteError,
    ProgramInfo,
    PyGhidraContext,
)


def test_gen_unique_bin_name_appends_hash(tmp_path: Path) -> None:
    """The helper should suffix the filename with a content hash."""

    binary_path = tmp_path / "dummy.bin"
    payload = b"hello world"
    binary_path.write_bytes(payload)

    expected_hash = hashlib.sha1(payload).hexdigest()[:6]
    program_name = PyGhidraContext._gen_unique_bin_name(binary_path)

    assert program_name == f"{binary_path.name}-{expected_hash}"


def test_get_program_info_validation_flow(tmp_path: Path) -> None:
    """`get_program_info` should validate presence and analysis state."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {}

    metadata_path = tmp_path / "binary"
    program_info = ProgramInfo(
        name="binary",
        program=object(),
        flat_api=None,
        decompiler=object(),
        metadata={"Executable Location": str(metadata_path)},
        ghidra_analysis_complete=True,
        file_path=metadata_path,
        load_time=0.0,
        collection=None,
        strings_collection=None,
    )
    context.programs["binary"] = program_info

    with pytest.raises(ValueError) as missing_info:
        context.get_program_info("missing")
    assert "missing" in str(missing_info.value)

    program_info.collection = object()
    assert not program_info.analysis_complete

    with pytest.raises(AnalysisIncompleteError) as incomplete_info:
        context.get_program_info("binary")

    error = incomplete_info.value
    assert isinstance(error, RuntimeError)
    assert error.details == {
        "binary_name": "binary",
        "ghidra_analysis_complete": True,
        "code_collection_ready": True,
        "strings_collection_ready": False,
        "suggestion": "Wait and try tool call again.",
    }

    program_info.strings_collection = object()
    assert program_info.analysis_complete

    assert context.get_program_info("binary") is program_info


def test_set_active_program_updates_state(tmp_path: Path) -> None:
    """Selecting a program should validate and persist the active program name."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {}
    context.active_program_name = None

    metadata_path = tmp_path / "binary"
    program_info = ProgramInfo(
        name="binary",
        program=object(),
        flat_api=None,
        decompiler=object(),
        metadata={"Executable Location": str(metadata_path)},
        ghidra_analysis_complete=True,
        file_path=metadata_path,
        load_time=0.0,
        collection=object(),
        strings_collection=object(),
    )
    context.programs["binary"] = program_info

    selected = context.set_active_program("binary")

    assert selected is program_info
    assert context.active_program_name == "binary"


def test_set_active_program_requires_completed_analysis(tmp_path: Path) -> None:
    """Active program selection should fail if analysis has not finished."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {}
    context.active_program_name = "existing"

    metadata_path = tmp_path / "incomplete"
    incomplete = ProgramInfo(
        name="incomplete",
        program=object(),
        flat_api=None,
        decompiler=object(),
        metadata={"Executable Location": str(metadata_path)},
        ghidra_analysis_complete=True,
        file_path=metadata_path,
        load_time=0.0,
        collection=object(),
        strings_collection=None,
    )
    context.programs["incomplete"] = incomplete

    with pytest.raises(AnalysisIncompleteError):
        context.set_active_program("incomplete")

    assert context.active_program_name == "existing"


def test_get_active_program_info_requires_selection() -> None:
    """Requesting the active program without selection should raise a helpful error."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {}
    context.active_program_name = None

    with pytest.raises(ValueError) as excinfo:
        context.get_active_program_info()

    assert "No active program selected" in str(excinfo.value)

def test_import_binary_backgrounded_missing_file(tmp_path: Path) -> None:
    """The background importer should surface missing binaries immediately."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {}

    missing_path = tmp_path / "nonexistent.bin"

    with pytest.raises(FileNotFoundError) as excinfo:
        context.import_binary_backgrounded(missing_path)

    assert str(excinfo.value) == f"The file {missing_path} cannot be found"
