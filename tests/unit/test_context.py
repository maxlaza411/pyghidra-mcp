# ruff: noqa: N802

"""Unit tests for :mod:`pyghidra_mcp.context`."""

from __future__ import annotations

import concurrent.futures
import hashlib
import sys
import threading
import types
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))


def _ensure_context_dependencies() -> None:  # noqa: C901
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

        types_module.ErrorData = ErrorData
        types_module.INTERNAL_ERROR = "INTERNAL_ERROR"
        types_module.INVALID_PARAMS = "INVALID_PARAMS"
        types_module.ResourceContents = object
        sys.modules["mcp.types"] = types_module

    if "pydantic" not in sys.modules:
        pydantic_module = types.ModuleType("pydantic")

        class BaseModel:  # pragma: no cover - lightweight stub
            def __init__(self, **kwargs) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

        def Field(default, *args, **kwargs):  # pragma: no cover - lightweight stub
            return default

        pydantic_module.BaseModel = BaseModel
        pydantic_module.Field = Field
        pydantic_module.ConfigDict = dict
        sys.modules["pydantic"] = pydantic_module

    if "ghidra" not in sys.modules:
        ghidra_module = types.ModuleType("ghidra")
        sys.modules["ghidra"] = ghidra_module
    else:
        ghidra_module = sys.modules["ghidra"]

    program_module = sys.modules.get("ghidra.program")
    if program_module is None:
        program_module = types.ModuleType("ghidra.program")
        sys.modules["ghidra.program"] = program_module
        ghidra_module.program = program_module

    model_module = sys.modules.get("ghidra.program.model")
    if model_module is None:
        model_module = types.ModuleType("ghidra.program.model")
        sys.modules["ghidra.program.model"] = model_module
        program_module.model = model_module

    listing_module = sys.modules.get("ghidra.program.model.listing")
    if listing_module is None:
        listing_module = types.ModuleType("ghidra.program.model.listing")

        class Program:  # pragma: no cover - lightweight stub
            pass

        listing_module.Program = Program
        sys.modules["ghidra.program.model.listing"] = listing_module
        model_module.listing = listing_module

    if "tomli" not in sys.modules:
        import tomllib

        tomli_module = types.ModuleType("tomli")
        tomli_module.load = tomllib.load
        sys.modules["tomli"] = tomli_module


_ensure_context_dependencies()

from pyghidra_mcp.context import (
    AnalysisIncompleteError,
    ProgramInfo,
    PyGhidraContext,
)


def _make_program_info(program: object, location: Path) -> ProgramInfo:
    return ProgramInfo(
        name=getattr(program, "name", "program"),
        program=program,
        flat_api=None,
        decompiler=object(),
        metadata={"Executable Location": str(location)},
        ghidra_analysis_complete=False,
        file_path=location,
        load_time=0.0,
        collection=None,
        strings_collection=None,
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


def test_import_binary_backgrounded_missing_file(tmp_path: Path) -> None:
    """The background importer should surface missing binaries immediately."""

    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {}

    missing_path = tmp_path / "nonexistent.bin"

    with pytest.raises(FileNotFoundError) as excinfo:
        context.import_binary_backgrounded(missing_path)

    assert str(excinfo.value) == f"The file {missing_path} cannot be found"


def test_project_lock_releases_even_on_exception() -> None:
    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {}
    context._project_lock_guard = threading.RLock()

    class DummyProjectData:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.locked = False

        def acquireWriteLock(self):
            assert not self.locked
            self.locked = True
            self.calls.append("acquire")
            return self

        def releaseWriteLock(self, handle) -> None:
            assert handle is self
            assert self.locked
            self.locked = False
            self.calls.append("release")

    class DummyProject:
        def __init__(self) -> None:
            self.data = DummyProjectData()

        def getProjectData(self):
            return self.data

    context.project = DummyProject()

    with pytest.raises(RuntimeError):
        with context._project_lock(write=True):
            raise RuntimeError("boom")

    assert context.project.data.calls == ["acquire", "release"]


def test_import_binary_existing_program_uses_project_and_domain_locks(  # noqa: C901
    tmp_path: Path,
) -> None:
    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {}
    context._project_lock_guard = threading.RLock()

    binary_path = tmp_path / "existing.bin"
    binary_path.write_bytes(b"data")
    program_name = PyGhidraContext._gen_unique_bin_name(binary_path)

    class ProjectDataStub:
        def __init__(self) -> None:
            self.events: list[str] = []
            self.locked = False

        def acquireWriteLock(self):
            assert not self.locked
            self.locked = True
            self.events.append("acquire")
            return self

        def releaseWriteLock(self, handle) -> None:
            assert self.locked
            self.locked = False
            self.events.append("release")

    class DomainFileStub:
        def __init__(self, name: str) -> None:
            self.name = name
            self.events: list[str] = []
            self.locked = False

        def getName(self) -> str:
            return self.name

        def acquireWriteLock(self):
            assert not self.locked
            self.locked = True
            self.events.append("acquire")
            return self

        def releaseWriteLock(self, handle) -> None:
            assert handle is self
            assert self.locked
            self.locked = False
            self.events.append("release")

    class ProgramStub:
        def __init__(self, name: str, domain_file: DomainFileStub) -> None:
            self.name = name
            self._domain_file = domain_file
            self.path = binary_path

        def getDomainFile(self) -> DomainFileStub:
            return self._domain_file

    class ProjectStub:
        def __init__(self) -> None:
            self.data = ProjectDataStub()
            self.domain_file = DomainFileStub(program_name)
            self.program = ProgramStub(program_name, self.domain_file)
            self.open_calls = 0

        def getProjectData(self) -> ProjectDataStub:
            return self.data

        def getRootFolder(self):
            return types.SimpleNamespace(getFile=lambda name: self.domain_file)

        def openProgram(self, folder: str, name: str, read_only: bool) -> ProgramStub:
            assert self.data.locked
            assert self.domain_file.locked
            self.open_calls += 1
            return self.program

    project = ProjectStub()
    context.project = project
    context._init_program_info = lambda program: _make_program_info(program, binary_path)

    context.import_binary(binary_path, analyze=False)

    assert project.open_calls == 1
    assert project.data.events == ["acquire", "release"]
    assert project.domain_file.events == ["acquire", "release"]
    assert program_name in context.programs


def test_import_binary_new_program_uses_locks(tmp_path: Path) -> None:  # noqa: C901
    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {}
    context._project_lock_guard = threading.RLock()

    binary_path = tmp_path / "new.bin"
    binary_path.write_bytes(b"new-data")

    class LockTracker:
        def __init__(self) -> None:
            self.events: list[str] = []
            self.locked = False

        def acquireWriteLock(self):
            assert not self.locked
            self.locked = True
            self.events.append("acquire")
            return self

        def releaseWriteLock(self, handle) -> None:
            assert self.locked
            self.locked = False
            self.events.append("release")

    class DomainFileStub:
        def __init__(self) -> None:
            self.events: list[str] = []
            self.locked = False
            self.name = ""

        def getName(self) -> str:
            return self.name

        def acquireWriteLock(self):
            assert not self.locked
            self.locked = True
            self.events.append("acquire")
            return self

        def releaseWriteLock(self, handle) -> None:
            assert handle is self
            assert self.locked
            self.locked = False
            self.events.append("release")

    class ProgramStub:
        def __init__(self, domain_file: DomainFileStub) -> None:
            self.name = ""
            self._domain_file = domain_file
            self.path = binary_path

        def getDomainFile(self) -> DomainFileStub:
            return self._domain_file

    class ProjectStub:
        def __init__(self) -> None:
            self.data = LockTracker()
            self.import_calls = 0
            self.save_calls = 0

        def getProjectData(self) -> LockTracker:
            return self.data

        def getRootFolder(self):
            return types.SimpleNamespace(getFile=lambda name: None)

        def importProgram(self, path: Path) -> ProgramStub:
            assert self.data.locked
            self.import_calls += 1
            return ProgramStub(DomainFileStub())

        def saveAs(self, program: ProgramStub, folder: str, name: str, overwrite: bool) -> None:
            assert self.data.locked
            domain = program.getDomainFile()
            assert domain.locked
            domain.name = name
            self.save_calls += 1

    project = ProjectStub()
    context.project = project
    context._init_program_info = lambda program: _make_program_info(program, binary_path)

    context.import_binary(binary_path, analyze=False)

    assert project.import_calls == 1
    assert project.save_calls == 1
    assert project.data.events == ["acquire", "release", "acquire", "release"]
    assert len(context.programs) == 1
    program_info = next(iter(context.programs.values()))
    assert program_info.program.getDomainFile().events == ["acquire", "release"]


def test_concurrent_imports_respect_project_lock(tmp_path: Path) -> None:  # noqa: C901
    tracker_lock = threading.Lock()

    class LockTracker:
        def __init__(self) -> None:
            self.mutex = tracker_lock
            self.project_active = 0
            self.domain_active = 0
            self.project_peak = 0
            self.domain_peak = 0

    class ProjectDataStub:
        def __init__(self, tracker: LockTracker) -> None:
            self.tracker = tracker

        def acquireWriteLock(self):
            with self.tracker.mutex:
                self.tracker.project_active += 1
                self.tracker.project_peak = max(
                    self.tracker.project_peak, self.tracker.project_active
                )
                if self.tracker.project_active > 1:
                    raise RuntimeError("Project lock is not exclusive")
            return self

        def releaseWriteLock(self, handle) -> None:
            with self.tracker.mutex:
                self.tracker.project_active -= 1

    class DomainFileStub:
        def __init__(self, tracker: LockTracker, name: str) -> None:
            self.tracker = tracker
            self.name = name

        def getName(self) -> str:
            return self.name

        def acquireWriteLock(self):
            with self.tracker.mutex:
                self.tracker.domain_active += 1
                self.tracker.domain_peak = max(
                    self.tracker.domain_peak, self.tracker.domain_active
                )
                if self.tracker.domain_active > 1:
                    raise RuntimeError("Domain file lock is not exclusive")
            return self

        def releaseWriteLock(self, handle) -> None:
            with self.tracker.mutex:
                self.tracker.domain_active -= 1

    class ProgramStub:
        def __init__(self, domain_file: DomainFileStub, path: Path) -> None:
            self.name = ""
            self._domain_file = domain_file
            self.path = path

        def getDomainFile(self) -> DomainFileStub:
            return self._domain_file

    class ProjectStub:
        def __init__(self, tracker: LockTracker) -> None:
            self.tracker = tracker
            self.data = ProjectDataStub(tracker)

        def getProjectData(self) -> ProjectDataStub:
            return self.data

        def getRootFolder(self):
            return types.SimpleNamespace(getFile=lambda name: None)

        def importProgram(self, path: Path) -> ProgramStub:
            with self.tracker.mutex:
                assert self.tracker.project_active == 1
            domain = DomainFileStub(self.tracker, "")
            return ProgramStub(domain, path)

        def saveAs(self, program: ProgramStub, folder: str, name: str, overwrite: bool) -> None:
            with self.tracker.mutex:
                assert self.tracker.project_active == 1
                assert self.tracker.domain_active == 1
            program.getDomainFile().name = name

    tracker = LockTracker()
    project = ProjectStub(tracker)

    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {}
    context._project_lock_guard = threading.RLock()
    context.project = project
    context._init_program_info = lambda program: _make_program_info(program, program.path)

    def run_import(index: int) -> None:
        path = tmp_path / f"binary-{index}.bin"
        path.write_bytes(f"payload-{index}".encode())
        context.import_binary(path, analyze=False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(run_import, i) for i in range(6)]
        for future in futures:
            future.result()

    assert tracker.project_peak == 1
    assert tracker.project_active == 0
    assert tracker.domain_active == 0
    assert tracker.domain_peak <= 1
    assert len(context.programs) == 6
