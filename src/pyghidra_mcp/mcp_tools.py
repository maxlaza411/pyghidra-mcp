"""
MCP Tool handlers for pyghidra-mcp.

This module contains all MCP tool implementations with centralized error handling.
"""

import functools
import logging
from pathlib import Path
from urllib.parse import quote

from mcp.server.fastmcp import Context
from mcp.server.fastmcp.resources.types import BinaryResource, TextResource
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData, ResourceContents

from pyghidra_mcp.context import AnalysisIncompleteError, PyGhidraContext
from pyghidra_mcp.models import (
    AnalyzeNowResult,
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CodeSearchResults,
    CrossReferenceInfos,
    DecompiledFunction,
    ExportInfos,
    FunctionResourceMetadata,
    ImportInfos,
    ProgramBasicInfo,
    ProgramInfo,
    ProgramInfos,
    SearchMode,
    StringSearchResults,
    SymbolSearchResults,
)
from pyghidra_mcp.tools import GhidraTools

logger = logging.getLogger(__name__)


def _get_action_name(func_name: str) -> str:
    """Derives a gerund action name from a function name."""
    action = func_name.replace("_", " ")
    words = action.split()
    if words and not words[0].endswith("ing"):
        first = words[0]
        if first.endswith("e"):
            words[0] = first[:-1] + "ing"
        else:
            words[0] = first + "ing"
    return " ".join(words)


def mcp_error_handler(func):
    """
    Decorator that provides centralized error handling for MCP tools.
    Converts AnalysisIncompleteError, ValueError, and generic exceptions into
    structured McpError responses.
    """
    action = _get_action_name(func.__name__)

    def handle_error(e):
        if isinstance(e, AnalysisIncompleteError):
            message = (
                f"Analysis for '{e.binary_name}' is not complete. "
                f"Ghidra analysis complete: {e.ghidra_analysis_complete}. "
                f"Code indexed: {e.code_collection_ready}. "
                f"Strings indexed: {e.strings_collection_ready}. "
                f"{e.suggestion}"
            )
            return McpError(ErrorData(code=INVALID_PARAMS, message=message, data=e.details))
        if isinstance(e, ValueError):
            return McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))
        if isinstance(e, McpError):
            return e
        return McpError(ErrorData(code=INTERNAL_ERROR, message=f"Error {action}: {e!s}"))

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            raise handle_error(e) from e

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise handle_error(e) from e

    import asyncio

    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


# Resource artifact helpers
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
    details: dict | None = None,
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


# MCP Tool Implementations
# ---------------------------------------------------------------------------------


@mcp_error_handler
async def decompile_function(
    binary_name: str, name_or_address: str, ctx: Context
) -> DecompiledFunction:
    """Decompiles a function in a specified binary and returns its pseudo-C code.

    Args:
        binary_name: The name of the binary containing the function.
        name_or_address: The name or address of the function to decompile.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.decompile_function_by_name_or_addr(name_or_address)


@mcp_error_handler
def search_symbols_by_name(
    binary_name: str, query: str, ctx: Context, offset: int = 0, limit: int = 25
) -> SymbolSearchResults:
    """Searches for symbols, including functions, within a binary by name.

    This tool searches for symbols by a case-insensitive substring. Symbols include
    Functions, Labels, Classes, Namespaces, Externals, Dynamics, Libraries,
    Global Variables, Parameters, and Local Variables.

    Args:
        binary_name: The name of the binary to search within.
        query: The substring to search for in symbol names (case-insensitive).
        offset: The number of results to skip.
        limit: The maximum number of results to return.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    symbols = tools.search_symbols_by_name(query, offset, limit)
    return SymbolSearchResults(symbols=symbols)


@mcp_error_handler
def search_code(
    binary_name: str,
    query: str,
    ctx: Context,
    limit: int = 5,
    offset: int = 0,
    search_mode: SearchMode = SearchMode.SEMANTIC,
    include_full_code: bool = True,
    preview_length: int = 500,
    similarity_threshold: float = 0.0,
) -> CodeSearchResults:
    """
    Perform a code search over a binary's decompiled pseudo C output.

    Supports two search modes:
    - **semantic**: Vector similarity search for meaning-based matching (default)
    - **literal**: Exact string matching using $contains for precise text matches

    Results always include counts to help
    decide if switching modes would yield better results

    For best results provide a short distinctive query such as a function
    signature or key logic snippet to minimize irrelevant matches.

    Args:
        binary_name: Name of the binary to search within.
        query: Code snippet, signature, or exact text to search for.
        limit: Maximum number of results to return (default: 5).
        offset: Number of results to skip for pagination (default: 0).
        search_mode: Search mode - 'semantic' or 'literal' (default: semantic).
        include_full_code: If True, return full function code. If False, return truncated preview.
        preview_length: Length of preview in characters when include_full_code=False (default: 500).
        similarity_threshold: Minimum similarity score (0.0-1.0) for semantic results
            (default: 0.0).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.search_code(
        query=query,
        limit=limit,
        offset=offset,
        search_mode=search_mode,
        include_full_code=include_full_code,
        preview_length=preview_length,
        similarity_threshold=similarity_threshold,
    )


@mcp_error_handler
def list_project_binaries(ctx: Context) -> ProgramInfos:
    """
    Retrieve binary name, path, and analysis status for every program (binary) currently
    loaded in the active project.

    Returns a structured list of program entries, each containing:
    - name: The display name of the program
    - file_path: Absolute path to the binary file on disk (if available)
    - load_time: Timestamp when the program was loaded into the project
    - analysis_complete: Boolean indicating if automated analysis has finished

    Use this to inspect the full set of binaries in the project, monitor analysis
    progress, or drive follow up actions such as listing imports/exports or running
    code searches on specific programs.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_infos = []
    for name, pi in pyghidra_context.programs.items():
        program_infos.append(
            ProgramInfo(
                name=name,
                file_path=str(pi.file_path) if pi.file_path else None,
                load_time=pi.load_time,
                analysis_complete=pi.analysis_complete,
                metadata={},
                code_collection=pi.code_collection is not None,
                strings_collection=pi.strings_collection is not None,
            )
        )
    return ProgramInfos(programs=program_infos)


@mcp_error_handler
def list_project_binary_metadata(binary_name: str, ctx: Context) -> dict:
    """
    Retrieve detailed metadata for a specified binary.

    Returns a dictionary containing properties such as architecture, compiler,
    endianness, file hashes, and analysis counts (functions, symbols, etc.).

    Args:
        binary_name: The name of the binary to retrieve metadata for.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    return program_info.metadata


@mcp_error_handler
async def delete_project_binary(binary_name: str, ctx: Context) -> str:
    """Deletes a binary (program) from the project.

    Args:
        binary_name: The name of the binary to delete.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    if pyghidra_context.delete_program(binary_name):
        return f"Successfully deleted binary: {binary_name}"
    else:
        raise McpError(
            ErrorData(
                code=INVALID_PARAMS,
                message=f"Binary '{binary_name}' not found or could not be deleted.",
            )
        )


@mcp_error_handler
def list_exports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ExportInfos:
    """
    Retrieve exported functions and symbols from a given binary,
    with optional regex filtering to focus on only the most relevant items.

    For large binaries, using the `query` parameter is strongly recommended
    to reduce noise and improve downstream reasoning. Specify a substring
    or regex to match export names. For example: `query="init"`
    to list only initialization-related exports.

    Args:
        binary_name: Name of the binary to inspect.
        query: Strongly recommended. Regex pattern to match specific
               export names. Use to limit irrelevant results and narrow
               context for analysis.
        offset: Number of matching results to skip (for pagination).
        limit: Maximum number of results to return.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    exports = tools.list_exports(query=query, offset=offset, limit=limit)
    return ExportInfos(exports=exports)


@mcp_error_handler
def list_imports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ImportInfos:
    """
    Retrieve imported functions and symbols from a given binary,
    with optional filtering to return only the most relevant matches.

    This tool is most effective when you use the `query` parameter to
    focus results — especially for large binaries — by specifying a
    substring or regex that matches the desired import names.
    For example: `query="socket"` to only see socket-related imports.

    Args:
        binary_name: Name of the binary to inspect.
        query: Strongly recommended. Regex pattern to match specific
               import names. Use to reduce irrelevant results and narrow
               context for downstream reasoning.
        offset: Number of matching results to skip (for pagination).
        limit: Maximum number of results to return.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    imports = tools.list_imports(query=query, offset=offset, limit=limit)
    return ImportInfos(imports=imports)


@mcp_error_handler
def list_cross_references(
    binary_name: str, name_or_address: str, ctx: Context
) -> CrossReferenceInfos:
    """Finds and lists all cross-references (x-refs) to a given function, symbol, or address within
    a binary. This is crucial for understanding how code and data are used and related.
    If an exact match for a function or symbol is not found,
    the error message will suggest other symbols that are close matches.

    Args:
        binary_name: The name of the binary to search for cross-references in.
        name_or_address: The name of the function, symbol, or a specific address (e.g., '0x1004010')
        to find cross-references to.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    cross_references = tools.list_cross_references(name_or_address)
    return CrossReferenceInfos(cross_references=cross_references)


@mcp_error_handler
def search_strings(
    binary_name: str,
    ctx: Context,
    query: str,
    limit: int = 100,
) -> StringSearchResults:
    """Searches for strings within a binary by name.
    This can be very useful to gain general understanding of behaviors.

    Args:
        binary_name: The name of the binary to search within.
        query: A query to filter strings by.
        limit: The maximum number of results to return.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    strings = tools.search_strings(query=query, limit=limit)
    return StringSearchResults(strings=strings)


@mcp_error_handler
def read_bytes(binary_name: str, ctx: Context, address: str, size: int = 32) -> BytesReadResult:
    """Reads raw bytes from memory at a specified address.

    Args:
        binary_name: The name of the binary to read bytes from.
        address: The memory address to read from (supports hex format with or without 0x prefix).
        size: The number of bytes to read (default: 32, max: 8192).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.read_bytes(address=address, size=size)


@mcp_error_handler
def gen_callgraph(
    binary_name: str,
    function_name: str,
    ctx: Context,
    direction: CallGraphDirection = CallGraphDirection.CALLING,
    display_type: CallGraphDisplayType = CallGraphDisplayType.FLOW,
    condense_threshold: int = 50,
    top_layers: int = 3,
    bottom_layers: int = 3,
    max_run_time: int = 120,
) -> CallGraphResult:
    """Generates a mermaidjs function call graph for a specified function.

    Typically the 'calling' callgraph is most useful.
    The resulting graph string is mermaidjs format. This output is critical for correct rendering.
    The graph details function calls originating from (calling) or terminating at (called)
    the target function.

    Args:
        binary_name: The name of the binary containing the function.
        function_name: The name of the function to generate the call graph for.
        direction: Direction of the call graph (calling or called).
        display_type: Format of the graph (flow, flow_ends).
        condense_threshold: Maximum number of edges before graph condensation is triggered.
        top_layers: Number of top layers to show in a condensed graph.
        bottom_layers: Number of bottom layers to show in a condensed graph.
        max_run_time: Maximum run time in seconds (default: 120).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.gen_callgraph(
        function_name_or_address=function_name,
        cg_direction=direction,
        cg_display_type=display_type,
        include_refs=True,
        max_depth=None,
        max_run_time=max_run_time,
        condense_threshold=condense_threshold,
        top_layers=top_layers,
        bottom_layers=bottom_layers,
    )


@mcp_error_handler
def import_binary(binary_path: str, ctx: Context) -> str:
    """Imports a binary from a designated path into the current Ghidra project.

    Args:
        binary_path: The path to the binary file to import.
    """
    # We would like to do context progress updates, but until that is more
    # widely supported by clients, we will resort to this
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    pyghidra_context.import_binary_backgrounded(binary_path)
    return (
        f"Importing {binary_path} in the background. "
        "When ready, it will appear analyzed in binary list."
    )


# Resource artifact tools
# These tools publish heavy payloads as MCP resources and return lightweight metadata.
# ---------------------------------------------------------------------------------

@mcp_error_handler
async def get_function_disassembly(
    binary_name: str, name: str, ctx: Context
) -> FunctionResourceMetadata:
    """Returns the assembly listing for a function, published as an MCP resource.

    Args:
        binary_name: The name of the binary containing the function.
        name: The name or address of the function.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    listing = tools.get_function_disassembly(name)
    func = tools._require_function(name)
    uri = _function_resource_uri(binary_name, name, "disassembly")
    mime_type = "text/x-asm"
    resource = _publish_resource(ctx, uri=uri, data=listing, mime_type=mime_type)
    signature = str(func.getSignature()) if func.getSignature() else None
    details = {
        "entry_point": str(func.getEntryPoint()),
        "instruction_count": listing.count("\n") + (1 if listing else 0),
    }
    return _make_artifact_metadata(
        binary_name=binary_name,
        function_name=name,
        artifact_type="disassembly",
        summary=f"Assembly listing for {name} in {binary_name}.",
        resource=resource,
        mime_type=mime_type,
        signature=signature,
        details=details,
    )


@mcp_error_handler
async def get_function_pcode(
    binary_name: str, name: str, ctx: Context
) -> FunctionResourceMetadata:
    """Returns the Pcode operations for a function, published as an MCP resource.

    Args:
        binary_name: The name of the binary containing the function.
        name: The name or address of the function.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    pcode = tools.get_function_pcode(name)
    func = tools._require_function(name)
    uri = _function_resource_uri(binary_name, name, "pcode")
    mime_type = "text/x-pcode"
    resource = _publish_resource(ctx, uri=uri, data=pcode, mime_type=mime_type)
    signature = str(func.getSignature()) if func.getSignature() else None
    details = {"entry_point": str(func.getEntryPoint())}
    return _make_artifact_metadata(
        binary_name=binary_name,
        function_name=name,
        artifact_type="pcode",
        summary=f"Pcode listing for {name} in {binary_name}.",
        resource=resource,
        mime_type=mime_type,
        signature=signature,
        details=details,
    )


@mcp_error_handler
async def get_function_analysis_report(
    binary_name: str, name: str, ctx: Context
) -> FunctionResourceMetadata:
    """Returns a lightweight analysis report for a function, published as an MCP resource.

    Args:
        binary_name: The name of the binary containing the function.
        name: The name or address of the function.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    report, metrics = tools.get_function_analysis_report(name)
    func = tools._require_function(name)
    uri = _function_resource_uri(binary_name, name, "analysis")
    mime_type = "text/plain"
    resource = _publish_resource(ctx, uri=uri, data=report, mime_type=mime_type)
    signature = str(func.getSignature()) if func.getSignature() else None
    return _make_artifact_metadata(
        binary_name=binary_name,
        function_name=name,
        artifact_type="analysis",
        summary=f"Analysis summary for {name} in {binary_name}.",
        resource=resource,
        mime_type=mime_type,
        signature=signature,
        details=metrics,
    )


# State management tools
# ---------------------------------------------------------------------------------

@mcp_error_handler
def select_program(binary_name: str, ctx: Context) -> ProgramBasicInfo:
    """Mark a binary as the default target for subsequent tool invocations.

    Args:
        binary_name: The name of the binary to select as active.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.set_active_program(binary_name)
    return ProgramBasicInfo(
        name=program_info.name,
        analysis_complete=program_info.analysis_complete,
    )


@mcp_error_handler
async def analyze_now(binary_name: str, ctx: Context, force: bool = False) -> AnalyzeNowResult:
    """Synchronously analyze a binary and rebuild its code and string indexes.

    Use this when a binary has been imported but analysis has not yet completed,
    or to force a fresh analysis pass.

    Args:
        binary_name: The name of the binary to analyze.
        force: If True, re-analyze even if already marked complete.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.analyze_now(binary_name, force=force)
    analysis_complete = program_info.analysis_complete
    next_steps = (
        "Analysis complete. You can now run queries against this binary."
        if analysis_complete
        else "Analysis incomplete. Wait for indexing to finish before querying."
    )
    return AnalyzeNowResult(
        binary_name=program_info.name,
        ghidra_analysis_complete=program_info.ghidra_analysis_complete,
        code_collection_ready=program_info.code_collection is not None,
        strings_collection_ready=program_info.strings_collection is not None,
        analysis_complete=analysis_complete,
        next_steps=next_steps,
    )


@mcp_error_handler
def project_open(project_path: str, project_name: str, ctx: Context) -> str:
    """Open or create a Ghidra project at the requested location.

    Args:
        project_path: The directory path where the project should be created or opened.
        project_name: The name of the Ghidra project.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    target_path = Path(project_path).expanduser().resolve()
    pyghidra_context.open_project(target_path, project_name)
    return f"Project '{project_name}' opened at '{target_path}'."
