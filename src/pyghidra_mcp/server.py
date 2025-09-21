# Server
# ---------------------------------------------------------------------------------
import inspect
import json
import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable, TypeVar
from urllib.parse import quote

import click
import pyghidra
from mcp.server import Server
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.resources.types import BinaryResource, TextResource
from mcp.shared.exceptions import McpError
from mcp.types import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    CallToolResult,
    ErrorData,
    ResourceContents,
)
from starlette.responses import JSONResponse

from pyghidra_mcp.__init__ import __version__
from pyghidra_mcp.context import AnalysisIncompleteError, PyGhidraContext
from pyghidra_mcp.models import (
    CodeSearchResults,
    CrossReferenceInfos,
    ExportInfos,
    FunctionSearchResults,
    FunctionResourceMetadata,
    ImportInfos,
    ProgramBasicInfo,
    ProgramBasicInfos,
    ProgramInfo,
    ProgramInfos,
    StringSearchResults,
    SymbolSearchResults,
)
from pyghidra_mcp.tools import GhidraTools

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,  # Critical for STDIO transport
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

_T = TypeVar("_T")


# Init Pyghidra
# ---------------------------------------------------------------------------------
@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[PyGhidraContext]:
    """Manage server startup and shutdown lifecycle."""
    try:
        yield server._pyghidra_context  # type: ignore
    finally:
        pyghidra_context = getattr(server, "_pyghidra_context", None)
        if pyghidra_context is not None:
            close_method = getattr(pyghidra_context, "close", None)
            if callable(close_method):
                try:
                    close_method()
                except Exception:  # pragma: no cover - defensive cleanup
                    logger.exception("Error closing PyGhidraContext during shutdown")


mcp = FastMCP("pyghidra-mcp", lifespan=server_lifespan)  # type: ignore


def _calltoolresult_resources(self: CallToolResult) -> list[ResourceContents]:
    structured = self.structuredContent or {}
    raw_resources = structured.get("resources") or []
    resources: list[ResourceContents] = []
    for item in raw_resources:
        if isinstance(item, ResourceContents):
            resources.append(item)
        else:
            try:
                resources.append(ResourceContents.model_validate(item))
            except Exception:
                continue
    return resources


if not hasattr(CallToolResult, "resources"):
    CallToolResult.resources = property(_calltoolresult_resources)  # type: ignore[attr-defined]


# Helpers
# ---------------------------------------------------------------------------------
def _function_resource_uri(binary_name: str, function_name: str, artifact: str) -> str:
    return "ghidra://program/{}/function/{}/{}".format(
        quote(binary_name, safe=""), quote(function_name, safe=""), quote(artifact, safe="")
    )


def _publish_resource(
    ctx: Context, *, uri: str, data: str | bytes, mime_type: str
) -> ResourceContents:
    resource_manager = getattr(ctx.fastmcp, "_resource_manager", None)
    if resource_manager is not None:
        try:
            resource_manager._resources.pop(uri, None)  # type: ignore[attr-defined]
        except AttributeError:
            pass

    if isinstance(data, str):
        resource = TextResource(uri=uri, text=data, mime_type=mime_type)
    else:
        resource = BinaryResource(uri=uri, data=data, mime_type=mime_type)

    ctx.fastmcp.add_resource(resource)
    return ResourceContents(uri=uri, mimeType=mime_type)


def _make_artifact_metadata(
    *,
    binary_name: str,
    function_name: str,
    artifact_type: str,
    summary: str,
    resource: ResourceContents,
    mime_type: str,
    signature: str | None = None,
    details: dict[str, Any] | None = None,
) -> FunctionResourceMetadata:
    return FunctionResourceMetadata(
        binary_name=binary_name,
        function_name=function_name,
        artifact_type=artifact_type,
        summary=summary,
        resource_uri=str(resource.uri),
        mime_type=mime_type,
        signature=signature,
        details=details,
        resources=[resource],
    )


def _run_tool(
    ctx: Context,
    func: Callable[..., _T],
    *,
    binary_name: str | None = None,
    error_message: str,
) -> _T:
    """Execute a tool callable with shared error handling."""
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        parameters = list(inspect.signature(func).parameters.values())
        positional_count = 0
        expects_tools = False
        for parameter in parameters:
            if parameter.kind == inspect.Parameter.VAR_POSITIONAL:
                expects_tools = True
                break
            if parameter.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            ):
                positional_count += 1
        if positional_count >= 2:
            expects_tools = True

        if expects_tools:
            if binary_name is not None:
                program_info = pyghidra_context.get_program_info(binary_name)
            else:
                program_info = pyghidra_context.get_active_program_info()
            tools = GhidraTools(program_info)
            return func(pyghidra_context, tools)

        return func(pyghidra_context)
    except AnalysisIncompleteError as e:
        message = (
            f"Analysis for '{e.binary_name}' is not complete. "
            f"Ghidra analysis complete: {e.ghidra_analysis_complete}. "
            f"Code indexed: {e.code_collection_ready}. "
            f"Strings indexed: {e.strings_collection_ready}. "
            f"{e.suggestion}"
        )
        raise McpError(
            ErrorData(
                code=INVALID_PARAMS,
                message=message,
                data=e.details,
            )
        ) from e
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
    except McpError:
        raise
    except Exception as e:  # pragma: no cover - defensive programming
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"{error_message}: {e!s}")) from e


# MCP Tools
# ---------------------------------------------------------------------------------
@mcp.tool(structured_output=True)
async def decompile_function(
    name: str,
    ctx: Context,
    binary_name: str | None = None,
) -> FunctionResourceMetadata:
    """Decompiles a function and returns its pseudo-C code.

    Args:
        name: The name of the function to decompile.
        binary_name: Optional name of the binary. When omitted, the active program is used.
    """
    return _run_tool(
        ctx,
        lambda _pyghidra_context, tools: _decompile_function_artifact(
            ctx, tools.program_info.name, name, tools
        ),
        binary_name=binary_name,
        error_message="Error decompiling function",
    )


def _decompile_function_artifact(
    ctx: Context, binary_name: str, name: str, tools: GhidraTools
) -> FunctionResourceMetadata:
    decomp = tools.decompile_function(name)
    func = tools._require_function(name)
    uri = _function_resource_uri(binary_name, name, "decompiled")
    mime_type = "text/x-c"
    resource = _publish_resource(ctx, uri=uri, data=decomp.code, mime_type=mime_type)
    summary = f"Pseudo-C decompilation for {name} in {binary_name}."
    details = {
        "entry_point": str(func.getEntryPoint()),
        "file_hint": decomp.name,
    }
    return _make_artifact_metadata(
        binary_name=binary_name,
        function_name=name,
        artifact_type="decompilation",
        summary=summary,
        resource=resource,
        mime_type=mime_type,
        signature=decomp.signature,
        details=details,
    )


@mcp.tool(structured_output=True)
async def get_function_disassembly(
    name: str,
    ctx: Context,
    binary_name: str | None = None,
) -> FunctionResourceMetadata:
    return _run_tool(
        ctx,
        lambda _pyghidra_context, tools: _disassembly_artifact(
            ctx, tools.program_info.name, name, tools
        ),
        binary_name=binary_name,
        error_message="Error fetching disassembly",
    )


def _disassembly_artifact(
    ctx: Context, binary_name: str, name: str, tools: GhidraTools
) -> FunctionResourceMetadata:
    listing = tools.get_function_disassembly(name)
    func = tools._require_function(name)
    uri = _function_resource_uri(binary_name, name, "disassembly")
    mime_type = "text/x-asm"
    resource = _publish_resource(ctx, uri=uri, data=listing, mime_type=mime_type)
    summary = f"Assembly listing for {name} in {binary_name}."
    details = {
        "entry_point": str(func.getEntryPoint()),
        "instruction_count": listing.count("\n") + (1 if listing else 0),
    }
    signature = str(func.getSignature()) if func.getSignature() else None
    return _make_artifact_metadata(
        binary_name=binary_name,
        function_name=name,
        artifact_type="disassembly",
        summary=summary,
        resource=resource,
        mime_type=mime_type,
        signature=signature,
        details=details,
    )


@mcp.tool(structured_output=True)
async def get_function_pcode(
    name: str,
    ctx: Context,
    binary_name: str | None = None,
) -> FunctionResourceMetadata:
    return _run_tool(
        ctx,
        lambda _pyghidra_context, tools: _pcode_artifact(
            ctx, tools.program_info.name, name, tools
        ),
        binary_name=binary_name,
        error_message="Error fetching pcode",
    )


def _pcode_artifact(
    ctx: Context, binary_name: str, name: str, tools: GhidraTools
) -> FunctionResourceMetadata:
    pcode = tools.get_function_pcode(name)
    func = tools._require_function(name)
    uri = _function_resource_uri(binary_name, name, "pcode")
    mime_type = "text/x-pcode"
    resource = _publish_resource(ctx, uri=uri, data=pcode, mime_type=mime_type)
    summary = f"Pcode listing for {name} in {binary_name}."
    signature = str(func.getSignature()) if func.getSignature() else None
    details = {"entry_point": str(func.getEntryPoint())}
    return _make_artifact_metadata(
        binary_name=binary_name,
        function_name=name,
        artifact_type="pcode",
        summary=summary,
        resource=resource,
        mime_type=mime_type,
        signature=signature,
        details=details,
    )


@mcp.tool(structured_output=True)
async def get_function_callgraph(
    name: str,
    ctx: Context,
    binary_name: str | None = None,
) -> FunctionResourceMetadata:
    return _run_tool(
        ctx,
        lambda _pyghidra_context, tools: _callgraph_artifact(
            ctx, tools.program_info.name, name, tools
        ),
        binary_name=binary_name,
        error_message="Error fetching callgraph",
    )


def _callgraph_artifact(
    ctx: Context, binary_name: str, name: str, tools: GhidraTools
) -> FunctionResourceMetadata:
    graph = tools.get_function_callgraph(name)
    graph_text = json.dumps(graph, indent=2, sort_keys=True)
    func = tools._require_function(name)
    uri = _function_resource_uri(binary_name, name, "callgraph")
    mime_type = "application/json"
    resource = _publish_resource(ctx, uri=uri, data=graph_text, mime_type=mime_type)
    summary = f"Callgraph relationships for {name} in {binary_name}."
    signature = str(func.getSignature()) if func.getSignature() else None
    return _make_artifact_metadata(
        binary_name=binary_name,
        function_name=name,
        artifact_type="callgraph",
        summary=summary,
        resource=resource,
        mime_type=mime_type,
        signature=signature,
        details={"callers": graph.get("callers", []), "callees": graph.get("callees", [])},
    )


@mcp.tool(structured_output=True)
async def get_function_analysis_report(
    name: str,
    ctx: Context,
    binary_name: str | None = None,
) -> FunctionResourceMetadata:
    return _run_tool(
        ctx,
        lambda _pyghidra_context, tools: _analysis_artifact(
            ctx, tools.program_info.name, name, tools
        ),
        binary_name=binary_name,
        error_message="Error fetching analysis report",
    )


def _analysis_artifact(
    ctx: Context, binary_name: str, name: str, tools: GhidraTools
) -> FunctionResourceMetadata:
    report, metrics = tools.get_function_analysis_report(name)
    func = tools._require_function(name)
    uri = _function_resource_uri(binary_name, name, "analysis")
    mime_type = "text/plain"
    resource = _publish_resource(ctx, uri=uri, data=report, mime_type=mime_type)
    summary = f"Analysis summary for {name} in {binary_name}."
    signature = str(func.getSignature()) if func.getSignature() else None
    return _make_artifact_metadata(
        binary_name=binary_name,
        function_name=name,
        artifact_type="analysis",
        summary=summary,
        resource=resource,
        mime_type=mime_type,
        signature=signature,
        details=metrics,
    )


@mcp.tool()
def search_functions_by_name(
    query: str,
    ctx: Context,
    offset: int = 0,
    limit: int = 25,
    binary_name: str | None = None,
) -> FunctionSearchResults:
    """Searches for functions within a binary by name.

    Args:
        binary_name: Optional name of the binary to search within. Falls back to the active program.
        query: The substring to search for in function names (case-insensitive).
        offset: The number of results to skip.
        limit: The maximum number of results to return.
    """
    return _run_tool(
        ctx,
        lambda _pyghidra_context, tools: FunctionSearchResults(
            functions=tools.search_functions_by_name(query, offset, limit)
        ),
        binary_name=binary_name,
        error_message="Error searching for functions",
    )


@mcp.tool()
def search_symbols_by_name(
    query: str,
    ctx: Context,
    offset: int = 0,
    limit: int = 25,
    binary_name: str | None = None,
) -> SymbolSearchResults:
    """
    Search for symbols by case insensitive substring within a specific binary
    Symbols include Functions, Labels, Classes, Namespaces, Externals,
    Dynamics, Libraries, Global Variables, Parameters, and Local Variables

    Return: A paginatedlist of matches.

    Args:
        binary_name: Optional name of the binary to search within. Falls back to the active program.
        query: The substring to search for in symbol names (case-insensitive).
        offset: The number of results to skip.
        limit: The maximum number of results to return.
    """
    return _run_tool(
        ctx,
        lambda _pyghidra_context, tools: SymbolSearchResults(
            symbols=tools.search_symbols_by_name(query, offset, limit)
        ),
        binary_name=binary_name,
        error_message="Error searching for symbols",
    )


@mcp.tool()
def search_code(
    query: str,
    ctx: Context,
    limit: int = 5,
    binary_name: str | None = None,
) -> CodeSearchResults:
    """
    Perform a semantic code search over a binarys decompiled pseudo C output
    powered by a vector database for similarity matching.

    This returns the most relevant functions or code blocks whose semantics
    match the provided query even if the exact text differs. Results are
    Ghidra generated pseudo C enabling natural language like exploration of
    binary code structure.

    For best results provide a short distinctive query such as a function
    signature or key logic snippet to minimize irrelevant matches.

    Args:
        binary_name: Optional name of the binary to search within. Falls back to the active program.
        query: Code snippet signature or description to match via semantic search.
        limit: Maximum number of top scoring results to return (default: 5).
    """
    return _run_tool(
        ctx,
        lambda _pyghidra_context, tools: CodeSearchResults(results=tools.search_code(query, limit)),
        binary_name=binary_name,
        error_message="Error searching for code",
    )


@mcp.tool()
def list_project_binaries(ctx: Context) -> ProgramBasicInfos:
    """Lists the names and analysis status of all binaries currently loaded in
    the Ghidra project."""
    return _run_tool(
        ctx,
        lambda pyghidra_context: ProgramBasicInfos(
            programs=[
                ProgramBasicInfo(name=name, analysis_complete=pi.analysis_complete)
                for name, pi in pyghidra_context.programs.items()
            ]
        ),
        error_message="Error listing project binaries",
    )


@mcp.tool()
def list_project_program_info(ctx: Context) -> ProgramInfos:
    """
    Retrieve metadata and analysis status for every program (binary) currently
    loaded in the active project.

    Returns a structured list of program entries, each containing:
    - name: The display name of the program
    - file_path: Absolute path to the binary file (if available)
    - load_time: Timestamp when the program was loaded into the project
    - analysis_complete: Boolean indicating if automated analysis has finished
    - metadata: Additional attributes or annotations provided by the analysis toolchain

    Use this to inspect the full set of binaries in the project, monitor analysis
    progress, or drive follow up actions such as listing imports/exports or running
    code searches on specific programs.
    """
    return _run_tool(
        ctx,
        lambda pyghidra_context: ProgramInfos(
            programs=[
                ProgramInfo(
                    name=pi.name,
                    file_path=str(pi.file_path) if pi.file_path else None,
                    load_time=pi.load_time,
                    analysis_complete=pi.analysis_complete,
                    metadata=pi.metadata,
                    collection=None,
                )
                for _name, pi in pyghidra_context.programs.items()
            ]
        ),
        error_message="Error listing project program info",
    )


@mcp.tool(structured_output=True)
def select_program(binary_name: str, ctx: Context) -> ProgramBasicInfo:
    """Select the active program used when `binary_name` is omitted from tool calls."""

    def _select(pyghidra_context: PyGhidraContext) -> ProgramBasicInfo:
        program_info = pyghidra_context.set_active_program(binary_name)
        return ProgramBasicInfo(
            name=program_info.name,
            analysis_complete=program_info.analysis_complete,
        )

    return _run_tool(
        ctx,
        _select,
        error_message="Error selecting program",
    )


@mcp.tool()
def list_exports(
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
    binary_name: str | None = None,
) -> ExportInfos:
    """
    Retrieve exported functions and symbols from a given binary,
    with optional regex filtering to focus on only the most relevant items.

    For large binaries, using the `query` parameter is strongly recommended
    to reduce noise and improve downstream reasoning. Specify a substring
    or regex to match export names. For example: `query="init"`
    to list only initialization-related exports.

    Args:
        binary_name: Optional name of the binary to inspect. Falls back to the active program.
        query: Strongly recommended. Regex pattern to match specific
               export names. Use to limit irrelevant results and narrow
               context for analysis.
        offset: Number of matching results to skip (for pagination).
        limit: Maximum number of results to return.
    """
    return _run_tool(
        ctx,
        lambda _pyghidra_context, tools: ExportInfos(
            exports=tools.list_exports(query=query, offset=offset, limit=limit)
        ),
        binary_name=binary_name,
        error_message="Error listing exports",
    )


@mcp.tool()
def list_imports(
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
    binary_name: str | None = None,
) -> ImportInfos:
    """
    Retrieve imported functions and symbols from a given binary,
    with optional filtering to return only the most relevant matches.

    This tool is most effective when you use the `query` parameter to
    focus results — especially for large binaries — by specifying a
    substring or regex that matches the desired import names.
    For example: `query="socket"` to only see socket-related imports.

    Args:
        binary_name: Optional name of the binary to inspect. Falls back to the active program.
        query: Strongly recommended. Regex pattern to match specific
               import names. Use to reduce irrelevant results and narrow
               context for downstream reasoning.
        offset: Number of matching results to skip (for pagination).
        limit: Maximum number of results to return.
    """
    return _run_tool(
        ctx,
        lambda _pyghidra_context, tools: ImportInfos(
            imports=tools.list_imports(query=query, offset=offset, limit=limit)
        ),
        binary_name=binary_name,
        error_message="Error listing imports",
    )


@mcp.tool()
def list_cross_references(
    name_or_address: str,
    ctx: Context,
    binary_name: str | None = None,
) -> CrossReferenceInfos:
    """Finds and lists all cross-references (x-refs) to a given function, symbol, or address within
    a binary. This is crucial for understanding how code and data are used and related.
    If an exact match for a function or symbol is not found,
    the error message will suggest other symbols that are close matches.

    Args:
        binary_name: Optional name of the binary to search for cross-references in. Falls back to the active program.
        name_or_address: The name of the function, symbol, or a specific address (e.g., '0x1004010')
        to find cross-references to.
    """
    return _run_tool(
        ctx,
        lambda _pyghidra_context, tools: CrossReferenceInfos(
            cross_references=tools.list_cross_references(name_or_address)
        ),
        binary_name=binary_name,
        error_message="Error listing cross-references",
    )


@mcp.tool()
def search_strings(
    query: str,
    ctx: Context,
    limit: int = 100,
    binary_name: str | None = None,
) -> StringSearchResults:
    """Searches for strings within a binary by name.
    This can be very useful to gain general understanding of behaviors.

    Args:
        binary_name: Optional name of the binary to search within. Falls back to the active program.
        query: A query to filter strings by.
        limit: The maximum number of results to return.
    """
    return _run_tool(
        ctx,
        lambda _pyghidra_context, tools: StringSearchResults(
            strings=tools.search_strings(query=query, limit=limit)
        ),
        binary_name=binary_name,
        error_message="Error searching for strings",
    )


@mcp.tool()
def import_binary(binary_path: str, ctx: Context) -> str:
    """Imports a binary from a designated path into the current Ghidra project.

    Args:
        binary_path: The path to the binary file to import.
    """
    def _import(pyghidra_context: PyGhidraContext) -> str:
        pyghidra_context.import_binary_backgrounded(binary_path)
        return (
            f"Importing {binary_path} in the background. When ready, it will appear analyzed in binary list."
        )

    return _run_tool(
        ctx,
        _import,
        error_message="Error importing binary",
    )


def init_pyghidra_context(
    mcp: FastMCP, input_paths: list[Path], project_name: str, project_directory: str
) -> FastMCP:
    bin_paths: list[str | Path] = [Path(p) for p in input_paths]

    logger.info(f"Analyzing {', '.join(map(str, bin_paths))}")
    logger.info(f"Project: {project_name}")
    logger.info(f"Project: Location {project_directory}")

    # init pyghidra
    pyghidra.start(False)  # setting Verbose output

    # init PyGhidraContext / import + analyze binaries
    logger.info("Server initializing...")
    try:
        pyghidra_context = PyGhidraContext(project_name, project_directory)
        logger.info(f"Importing binaries: {project_directory}")
        pyghidra_context.import_binaries(bin_paths)
        logger.info(f"Analyzing project: {pyghidra_context.project}")
        pyghidra_context.analyze_project()

        if len(pyghidra_context.list_binaries()) == 0 and len(input_paths) == 0:
            logger.warning("No binaries were imported and none exist in the project.")

        mcp._pyghidra_context = pyghidra_context  # type: ignore[attr-defined]
        mcp._pyghidra_context_error = None  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover - defensive programming
        logger.exception("Failed to initialize PyGhidra context: %s", exc)
        mcp._pyghidra_context = None  # type: ignore[attr-defined]
        mcp._pyghidra_context_error = {"message": str(exc)}  # type: ignore[attr-defined]
        raise
    logger.info("Server intialized")

    return mcp


# MCP Server Entry Point
# ---------------------------------------------------------------------------------


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(
    __version__,
    "-v",
    "--version",
    help="Show version and exit.",
)
@click.option(
    "-t",
    "--transport",
    type=click.Choice(["stdio", "streamable-http", "sse"]),
    default="stdio",
    envvar="MCP_TRANSPORT",
    help="Transport protocol to use: stdio, streamable-http, or sse (legacy)",
)
@click.option(
    "--project-path",
    type=click.Path(),
    default=Path("pyghidra_mcp_projects/pyghidra_mcp"),
    help="Location on disk which points to the Ghidra project to use. Can be an existing file.",
)
@click.argument("input_paths", type=click.Path(exists=True), nargs=-1)
def main(transport: str, input_paths: list[Path], project_path: Path) -> None:
    """PyGhidra Command-Line MCP server

    - input_paths: Path to one or more binaries to import, analyze, and expose with pyghidra-mcp
    - transport: Supports stdio, streamable-http, and sse transports.
    For stdio, it will read from stdin and write to stdout.
    For streamable-http and sse, it will start an HTTP server on port 8000.

    """
    project_name = project_path.stem
    project_directory = str(project_path.parent)

    init_pyghidra_context(mcp, input_paths, project_name, project_directory)

    @mcp.custom_route("/health", ["GET"])
    async def health(_request) -> JSONResponse:
        """Report readiness information for HTTP-based transports."""

        error_info = getattr(mcp, "_pyghidra_context_error", None)
        pyghidra_context = getattr(mcp, "_pyghidra_context", None)

        if error_info is not None:
            detail = (
                error_info.get("message", "PyGhidra context initialization failed.")
                if isinstance(error_info, dict)
                else str(error_info)
            )
            payload = {"status": "error", "detail": detail}
            if isinstance(error_info, dict):
                payload.update(error_info)
            return JSONResponse(payload, status_code=503)

        if pyghidra_context is None:
            return JSONResponse(
                {
                    "status": "error",
                    "detail": "PyGhidra context is not available.",
                },
                status_code=503,
            )

        program_count = len(pyghidra_context.programs)
        analyzed_programs = sum(
            1 for program in pyghidra_context.programs.values() if program.analysis_complete
        )

        payload = {
            "status": "ready",
            "project_name": pyghidra_context.project_name,
            "project_path": str(pyghidra_context.project_path),
            "program_count": program_count,
            "analyzed_programs": analyzed_programs,
        }
        return JSONResponse(payload, status_code=200)

    try:
        if transport == "stdio":
            mcp.run(transport="stdio")
        elif transport == "streamable-http":
            mcp.run(transport="streamable-http")
        elif transport == "sse":
            mcp.run(transport="sse")
        else:
            raise ValueError(f"Invalid transport: {transport}")
    finally:
        pyghidra_context = getattr(mcp, "_pyghidra_context", None)
        if pyghidra_context is not None:
            pyghidra_context.close()


if __name__ == "__main__":
    main()
