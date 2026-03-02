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
    BasicBlocksResult,
    BinarySummaryResult,
    BytePatternResult,
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CodeSearchResults,
    CrossReferenceInfos,
    DataTypeListResult,
    DecompiledFunction,
    ExportInfos,
    FunctionContextResult,
    FunctionListResult,
    FunctionResourceMetadata,
    ImportInfos,
    MemoryMapResult,
    MutationResult,
    ProgramBasicInfo,
    ProgramInfo,
    ProgramInfos,
    ScriptResult,
    SearchMode,
    StackFrameResult,
    StringListResult,
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
    binary_name: str,
    name_or_address: str,
    ctx: Context,
    offset: int = 0,
    limit: int = 100,
) -> CrossReferenceInfos:
    """Finds and lists all cross-references (x-refs) to a given function, symbol, or address within
    a binary. This is crucial for understanding how code and data are used and related.
    If an exact match for a function or symbol is not found,
    the error message will suggest other symbols that are close matches.

    For heavily-referenced symbols use offset/limit to paginate results and avoid
    flooding the context window.

    Args:
        binary_name: The name of the binary to search for cross-references in.
        name_or_address: The name of the function, symbol, or a specific address
            (e.g., '0x1004010') to find cross-references to.
        offset: Number of results to skip (pagination).
        limit: Maximum number of results to return (default: 100).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    cross_references = tools.list_cross_references(name_or_address, offset=offset, limit=limit)
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
    include_url: bool = False,
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
        include_url: If True, include a MermaidJS live-editor URL in the response (default: False).
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
        include_url=include_url,
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
def get_function_analysis_report(
    binary_name: str, name: str, ctx: Context
) -> dict:
    """Returns a structured JSON analysis report for a function.

    Returns metrics inline as structured JSON so agents can use them programmatically
    without parsing text. Fields include: function_name, entry_point, signature,
    body_size, parameter_count, local_variable_count, parameters, locals.

    Args:
        binary_name: The name of the binary containing the function.
        name: The name or address of the function.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.get_function_analysis_report(name)


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


# ── Annotation / mutation tools ───────────────────────────────────────────────


@mcp_error_handler
def rename_function(binary_name: str, name_or_address: str, new_name: str, ctx: Context) -> MutationResult:
    """Rename a function and persist the change in the Ghidra project.

    Use this after identifying a function's purpose to annotate your findings for subsequent
    agent turns. Agents should call this frequently to build up a readable symbol table.

    Workflow tip: decompile → understand → rename_function → set_comment

    Args:
        binary_name: The binary containing the function.
        name_or_address: Current name or entry-point address (e.g. '0x401000').
        new_name: The new function name to apply.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.rename_function(name_or_address, new_name)


@mcp_error_handler
def rename_variable(
    binary_name: str, function_name_or_address: str, old_name: str, new_name: str, ctx: Context
) -> MutationResult:
    """Rename a local variable or parameter inside a function via the decompiler model.

    Use this to clarify auto-generated variable names (param_1, local_8) after understanding
    their purpose from decompiled code.

    Args:
        binary_name: The binary containing the function.
        function_name_or_address: Function name or entry-point address.
        old_name: Current variable name (e.g. 'param_1', 'local_8').
        new_name: New descriptive name to apply.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.rename_variable(function_name_or_address, old_name, new_name)


@mcp_error_handler
def set_comment(
    binary_name: str,
    address: str,
    comment: str,
    ctx: Context,
    comment_type: str = "EOL",
) -> MutationResult:
    """Add or update a comment at a specific address.

    Comment types:
    - EOL: end-of-line comment (most common)
    - PRE: comment before the instruction
    - POST: comment after the instruction
    - PLATE: large block comment above a function
    - REPEATABLE: comment shown wherever this address is referenced

    Args:
        binary_name: The binary to annotate.
        address: Target address (hex, with or without 0x prefix).
        comment: Comment text. Pass empty string to clear.
        comment_type: One of EOL, PRE, POST, PLATE, REPEATABLE (default: EOL).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.set_comment(address, comment, comment_type)


@mcp_error_handler
def set_function_signature(
    binary_name: str, name_or_address: str, signature: str, ctx: Context
) -> MutationResult:
    """Apply a C-style function signature to update return type and parameter types/names.

    Example signatures:
      'int authenticate(char *username, char *password)'
      'void *allocate_buffer(size_t size)'

    Args:
        binary_name: The binary containing the function.
        name_or_address: Function name or entry-point address.
        signature: Full C function signature string to parse and apply.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.set_function_signature(name_or_address, signature)


@mcp_error_handler
def create_label(
    binary_name: str, address: str, name: str, ctx: Context
) -> MutationResult:
    """Create a named label at an address (useful for data, jump targets, strings).

    Args:
        binary_name: The binary to annotate.
        address: Target address (hex, with or without 0x prefix).
        name: Label name to create.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.create_label(address, name)


# ── Navigation tools ──────────────────────────────────────────────────────────


@mcp_error_handler
def list_functions(
    binary_name: str,
    ctx: Context,
    query: str = "",
    namespace: str = "",
    offset: int = 0,
    limit: int = 50,
) -> FunctionListResult:
    """List functions with optional name/namespace filtering and pagination.

    This is the primary discovery tool — use it to enumerate what functions exist
    before diving into decompilation. Filter by namespace to focus on a class or module.

    Workflow tip: Start with get_binary_summary, then list_functions to enumerate,
    then get_function_context on interesting functions.

    Args:
        binary_name: The binary to list functions from.
        query: Case-insensitive substring filter on function name.
        namespace: Filter to functions within this namespace/class.
        offset: Pagination offset.
        limit: Maximum results to return (default: 50).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.list_functions(query=query, namespace=namespace, offset=offset, limit=limit)


@mcp_error_handler
def list_namespaces(
    binary_name: str, ctx: Context, query: str = ""
) -> list:
    """List all namespaces and classes defined in the binary.

    Useful for understanding C++ class hierarchies and module structure.
    Use the returned namespace names with list_functions(namespace=...) to enumerate members.

    Args:
        binary_name: The binary to inspect.
        query: Optional substring filter on namespace path.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return [ns.model_dump() for ns in tools.list_namespaces(query=query)]


@mcp_error_handler
def get_function_containing(
    binary_name: str, address: str, ctx: Context
) -> dict | None:
    """Return the function that owns a given address.

    Use this when you have an interesting address (e.g. from a xref, byte pattern match,
    or string reference) and need to know which function to decompile.

    Args:
        binary_name: The binary to search in.
        address: Address to look up (hex, with or without 0x prefix).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    result = tools.get_function_containing(address)
    return result.model_dump() if result else None


@mcp_error_handler
def list_basic_blocks(
    binary_name: str, name_or_address: str, ctx: Context
) -> BasicBlocksResult:
    """Return the CFG basic blocks for a function with successor edges.

    Useful for understanding control flow complexity and identifying loops/branches
    without reading full decompiled code.

    Args:
        binary_name: The binary containing the function.
        name_or_address: Function name or entry-point address.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.list_basic_blocks(name_or_address)


@mcp_error_handler
def get_entry_points(binary_name: str, ctx: Context) -> list:
    """List all entry-point addresses/symbols defined in the binary.

    Returns the program's declared entry points (main, DllMain, WinMain, _start, etc.).

    Args:
        binary_name: The binary to inspect.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.get_entry_points()


# ── Memory tools ──────────────────────────────────────────────────────────────


@mcp_error_handler
def list_memory_segments(binary_name: str, ctx: Context) -> MemoryMapResult:
    """Return the full memory map: all segments with name, address range, permissions, and type.

    Use this for initial triage to understand the binary layout (.text, .data, .rdata, etc.)
    and spot packed/unusual sections.

    Args:
        binary_name: The binary to inspect.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return MemoryMapResult(segments=tools.list_memory_segments())


@mcp_error_handler
def find_byte_pattern(
    binary_name: str,
    pattern: str,
    ctx: Context,
    start: str = "",
    end: str = "",
    limit: int = 50,
) -> BytePatternResult:
    """Search for a byte pattern with wildcard support across the binary's memory.

    Pattern format: space-separated hex bytes, use '?' for wildcard bytes.
    Examples:
      '90 90 90'          — three NOPs
      'FF 25 ? ? ? ?'     — indirect JMP with any 4-byte target
      'E8 ? ? ? ? 48 83'  — CALL followed by stack adjustment

    Args:
        binary_name: The binary to search.
        pattern: Space-separated hex bytes with optional '?' wildcards.
        start: Optional start address (hex) to limit search range.
        end: Optional end address (hex) to limit search range.
        limit: Maximum matches to return (default: 50).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.find_byte_pattern(pattern, start=start, end=end, limit=limit)


@mcp_error_handler
def list_all_strings(
    binary_name: str,
    ctx: Context,
    min_length: int = 4,
    query: str = "",
    offset: int = 0,
    limit: int = 100,
) -> StringListResult:
    """Paginated listing of all defined strings in the binary with optional filtering.

    Unlike search_strings (which uses semantic/ChromaDB search), this returns the raw
    Ghidra-defined string table with exact filtering. Use for exhaustive enumeration.

    Args:
        binary_name: The binary to list strings from.
        min_length: Minimum string length to include (default: 4).
        query: Optional substring filter (case-insensitive).
        offset: Pagination offset.
        limit: Maximum results to return (default: 100).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.list_all_strings(min_length=min_length, query=query, offset=offset, limit=limit)


# ── Data type tools ───────────────────────────────────────────────────────────


@mcp_error_handler
def list_data_types(
    binary_name: str, ctx: Context, category_filter: str = "", limit: int = 100
) -> DataTypeListResult:
    """List data types (structs, enums, typedefs) defined in the binary.

    Use category_filter to narrow to a specific category path or type name substring.
    Useful for understanding protocol formats, file structures, and C++ class layouts.

    Args:
        binary_name: The binary to inspect.
        category_filter: Optional substring filter on category path or type name.
        limit: Maximum results to return (default: 100).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.list_data_types(category_filter=category_filter, limit=limit)


@mcp_error_handler
def get_data_type(binary_name: str, type_name: str, ctx: Context) -> dict:
    """Get the full definition of a data type — struct fields, enum values, or type details.

    Returns field names, types, offsets, and sizes for structures.
    Returns value mappings for enumerations.

    Args:
        binary_name: The binary containing the data type.
        type_name: Exact name of the data type to look up.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.get_data_type(type_name)


@mcp_error_handler
def create_struct(
    binary_name: str, name: str, fields: list, ctx: Context
) -> dict:
    """Define a new struct data type and register it in the program's data type manager.

    Each field dict must have: 'name' (str), 'type' (str — must resolve to a known type).
    Optional: 'comment' (str).

    Example fields:
      [{"name": "magic", "type": "uint"}, {"name": "size", "type": "int"},
       {"name": "data_ptr", "type": "pointer"}]

    Args:
        binary_name: The binary to define the struct in.
        name: Name for the new struct.
        fields: List of field dicts with 'name', 'type', and optional 'comment'.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.create_struct(name, fields)


@mcp_error_handler
def apply_data_type(
    binary_name: str, address: str, type_name: str, ctx: Context
) -> dict:
    """Apply a data type to a memory address to create structured data.

    Clears any existing code/data at the target range and creates new structured data.
    Use after define_struct to overlay a struct on a memory region.

    Args:
        binary_name: The binary to modify.
        address: Target address (hex, with or without 0x prefix).
        type_name: Name of the data type to apply (must exist in the program).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.apply_data_type(address, type_name)


@mcp_error_handler
def get_data_at(binary_name: str, address: str, ctx: Context) -> dict:
    """Read structured data defined at an address.

    Returns type, size, value, and for structs the individual field values.
    Combine with apply_data_type to read protocol headers, file format structures, etc.

    Args:
        binary_name: The binary to read from.
        address: Address to read structured data at (hex, with or without 0x prefix).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.get_data_at(address)


@mcp_error_handler
def get_stack_frame(
    binary_name: str, name_or_address: str, ctx: Context
) -> StackFrameResult:
    """Return the full stack frame layout for a function: parameters and local variables.

    Returns each variable's name, type, stack offset, and size. Negative offsets are
    below the saved frame pointer (locals), positive are parameters.

    Critical for buffer-overflow analysis — check local buffer sizes against usage.

    Args:
        binary_name: The binary containing the function.
        name_or_address: Function name or entry-point address.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.get_stack_frame(name_or_address)


# ── Composite / context tools ─────────────────────────────────────────────────


@mcp_error_handler
async def get_function_context(
    binary_name: str, name_or_address: str, ctx: Context, callee_depth: int = 1
) -> FunctionContextResult:
    """Return a rich, all-in-one context package for a function in a single call.

    Replaces the need to call decompile_function + list_cross_references +
    get_function_callgraph separately. Returns:
    - Full decompiled pseudo-C
    - Caller and callee function names
    - All cross-references to this function
    - Decompiled code for each callee (up to 10, depth=1)

    This is the most context-efficient way to deeply understand a function.
    Use it as the primary analysis tool after identifying interesting functions.

    Workflow: get_binary_summary → list_functions → get_function_context

    Args:
        binary_name: The binary containing the function.
        name_or_address: Function name or entry-point address.
        callee_depth: Depth of callee decompilation (0=none, 1=direct callees, default: 1).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.get_function_context(name_or_address, callee_depth=callee_depth)


@mcp_error_handler
def get_binary_summary(binary_name: str, ctx: Context) -> BinarySummaryResult:
    """Return an AI-optimised triage summary of a binary for rapid initial orientation.

    Returns in a single call:
    - Architecture and language
    - Entry points
    - Total function count
    - Imports grouped by category (network, crypto, file I/O, memory, process, etc.)
    - Heuristically interesting strings (URLs, IPs, paths, credentials, format strings)
    - Memory segment map
    - Top exports

    Always call this first when starting analysis of a new binary.

    Workflow: get_binary_summary → list_functions → get_function_context

    Args:
        binary_name: The binary to summarise.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.get_binary_summary()


@mcp_error_handler
async def decompile_functions_batch(
    binary_name: str, names_or_addresses: list, ctx: Context
) -> list:
    """Decompile multiple functions in a single call to trace call chains efficiently.

    Returns a list of decompiled function results in the same order as the input.
    Functions that fail to decompile return an error comment in the code field.

    Use this instead of multiple sequential decompile_function calls when you need
    to analyse a call chain or compare several functions.

    Args:
        binary_name: The binary containing the functions.
        names_or_addresses: List of function names or addresses to decompile.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    results = tools.decompile_functions_batch(names_or_addresses)
    return [r.model_dump() for r in results]


# ── Script execution ──────────────────────────────────────────────────────────


@mcp_error_handler
def run_python_script(
    binary_name: str, code: str, ctx: Context
) -> ScriptResult:
    """Execute arbitrary Python against the binary with full pyghidra/Ghidra API access.

    The following objects are available in the script's global scope:
    - program: ghidra.program.model.listing.Program
    - flat_api: ghidra.program.flatapi.FlatProgramAPI
    - decompiler: ghidra.app.decompiler.DecompInterface
    - program_info: pyghidra_mcp.context.ProgramInfo

    Print output is captured and returned in the 'output' field.
    Set __result__ = <value> to populate the 'result' field.

    Use this as an escape hatch for any analysis not covered by other tools.

    Example:
      code = "funcs = list(program.getFunctionManager().getFunctions(True))\\n"
             "__result__ = len(funcs)"

    Args:
        binary_name: The binary to run the script against.
        code: Python source code to execute.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.run_python_script(code)
