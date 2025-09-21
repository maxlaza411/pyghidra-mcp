import sys
import types

import pytest


def _ensure_stubbed_dependency(module_name: str, module: types.ModuleType) -> None:
    if module_name not in sys.modules:
        sys.modules[module_name] = module


if "chromadb" not in sys.modules:
    chromadb_module = types.ModuleType("chromadb")
    chromadb_module.__path__ = []  # mark as package for submodule imports

    class _StubCollection:  # pragma: no cover - simple placeholder
        pass

    class _StubPersistentClient:  # pragma: no cover - simple placeholder
        def __init__(self, *args, **kwargs) -> None:
            self.args = args
            self.kwargs = kwargs

        def get_collection(self, *args, **kwargs):  # pragma: no cover - placeholder
            raise RuntimeError("stub client does not provide collections")

    chromadb_module.Collection = _StubCollection
    chromadb_module.PersistentClient = _StubPersistentClient
    _ensure_stubbed_dependency("chromadb", chromadb_module)

    chromadb_config_module = types.ModuleType("chromadb.config")

    class _StubSettings:  # pragma: no cover - simple placeholder
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

    chromadb_config_module.Settings = _StubSettings
    _ensure_stubbed_dependency("chromadb.config", chromadb_config_module)


if "pyghidra" not in sys.modules:
    _ensure_stubbed_dependency("pyghidra", types.ModuleType("pyghidra"))


context_module = pytest.importorskip(
    "pyghidra_mcp.context",
    reason="pyghidra_mcp.context requires optional runtime dependencies",
)
server_module = pytest.importorskip(
    "pyghidra_mcp.server",
    reason="pyghidra_mcp.server requires optional runtime dependencies",
)

AnalysisIncompleteError = context_module.AnalysisIncompleteError
ProgramInfo = context_module.ProgramInfo
PyGhidraContext = context_module.PyGhidraContext


class _DummyCtx:
    def __init__(self, lifespan_context: object) -> None:
        self.request_context = types.SimpleNamespace(
            lifespan_context=lifespan_context
        )


def _make_incomplete_program_info(name: str = "binary") -> ProgramInfo:
    return ProgramInfo(
        name=name,
        program=object(),
        flat_api=None,
        decompiler=object(),
        metadata={},
        ghidra_analysis_complete=False,
        file_path=None,
        load_time=None,
        collection=None,
        strings_collection=None,
    )


def test_get_program_info_raises_custom_error_when_analysis_incomplete():
    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {"binary": _make_incomplete_program_info()}

    with pytest.raises(AnalysisIncompleteError) as exc_info:
        context.get_program_info("binary")

    error = exc_info.value
    assert error.binary_name == "binary"
    assert not error.ghidra_analysis_complete
    assert not error.code_collection_ready
    assert not error.strings_collection_ready
    assert "Analysis incomplete" in str(error)
    assert error.to_dict()["pending_components"]


@pytest.mark.asyncio
async def test_tool_error_handler_maps_incomplete_analysis_to_invalid_params():
    class DummyContext:
        def get_program_info(self, binary_name: str):
            raise AnalysisIncompleteError(
                binary_name=binary_name,
                ghidra_analysis_complete=False,
                code_collection_ready=False,
                strings_collection_ready=False,
            )

    ctx = _DummyCtx(DummyContext())

    with pytest.raises(server_module.McpError) as exc_info:
        await server_module.decompile_function("binary", "function", ctx)

    error_data = exc_info.value.error
    assert error_data.code == server_module.INVALID_PARAMS
    assert "analysis is incomplete" in error_data.message
    assert error_data.data["binary_name"] == "binary"
    assert error_data.data["pending_components"]
    assert (
        error_data.data["suggestion"].lower().startswith("wait")
        or "wait" in error_data.data["suggestion"].lower()
    )
