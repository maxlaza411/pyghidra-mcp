from enum import Enum
from typing import Any

from mcp.types import ResourceContents
from pydantic import BaseModel, ConfigDict, Field


class DecompiledFunction(BaseModel):
    """Represents a single function decompiled by Ghidra."""

    name: str = Field(..., description="The name of the function.")
    code: str = Field(..., description="The decompiled pseudo-C code of the function.")
    signature: str | None = Field(None, description="The signature of the function.")


class FunctionResourceMetadata(BaseModel):
    """Metadata describing a heavy-weight function artifact that is exposed as an MCP resource."""

    binary_name: str = Field(..., description="The binary/program that owns the function.")
    function_name: str = Field(..., description="The name of the function the artifact belongs to.")
    artifact_type: str = Field(
        ..., description="The kind of artifact (e.g. decompilation, disassembly, pcode)."
    )
    summary: str = Field(..., description="A short human readable summary of the artifact.")
    resource_uri: str = Field(
        ...,
        description=(
            "URI that can be used with the MCP resources API to fetch the artifact payload."
        ),
    )
    mime_type: str = Field(..., description="MIME type describing the artifact payload.")
    signature: str | None = Field(
        None,
        description="Optional function signature information if available.",
    )
    details: dict[str, Any] | None = Field(
        None, description="Additional structured metadata about the artifact."
    )
    resources: list[ResourceContents] = Field(
        ..., description="Resource descriptors associated with the artifact payload."
    )

    model_config = ConfigDict(populate_by_name=True)


class FunctionInfo(BaseModel):
    """Provides basic information about a function within a binary."""

    name: str = Field(..., description="The name of the function.")
    entry_point: str = Field(..., description="The entry point address of the function.")


class FunctionSearchResults(BaseModel):
    """A container for a list of functions found during a search."""

    functions: list[FunctionInfo] = Field(
        ..., description="A list of functions that match the search criteria."
    )



class ProgramBasicInfo(BaseModel):
    """Basic information about a program: name and analysis status"""

    name: str = Field(..., description="The name of the program.")
    analysis_complete: bool = Field(..., description="Indicates if program is ready to be used.")


class ProgramBasicInfos(BaseModel):
    """A container for a list of basic program information objects."""

    programs: list[ProgramBasicInfo] = Field(
        ..., description="A list of basic program information."
    )


class ProgramInfo(BaseModel):
    """Detailed information about a program (binary) loaded in Ghidra."""

    name: str = Field(..., description="The name of the program in Ghidra.")
    file_path: str | None = Field(None, description="The file path of the program on disk.")
    load_time: float | None = Field(
        None, description="The time it took to load the program in seconds."
    )
    analysis_complete: bool = Field(
        ..., description="Indicates if Ghidra's analysis of the program has completed."
    )
    metadata: dict = Field(..., description="A dictionary of metadata associated with the program.")
    code_collection: bool = Field(..., description="True if the chromadb code collection is ready")
    strings_collection: bool = Field(
        ..., description="True if the chromadb strings collection is ready"
    )


class ProgramInfos(BaseModel):
    """A container for a list of program information objects."""

    programs: list[ProgramInfo] = Field(..., description="A list of program information objects.")


class AnalyzeNowResult(BaseModel):
    """Status information returned by the analyze_now MCP tool."""

    binary_name: str = Field(..., description="The name of the program that was analyzed.")
    ghidra_analysis_complete: bool = Field(
        ..., description="Indicates whether Ghidra has finished its analysis stage."
    )
    code_collection_ready: bool = Field(
        ..., description="True if the code search collection has been rebuilt."
    )
    strings_collection_ready: bool = Field(
        ..., description="True if the strings search collection has been rebuilt."
    )
    analysis_complete: bool = Field(
        ..., description="Convenience flag signalling both Ghidra and Chroma are ready."
    )
    next_steps: str = Field(
        ..., description="Guidance for the caller on what to do after invoking the tool."
    )


class ExportInfo(BaseModel):
    """Represents a single exported function or symbol from a binary."""

    name: str = Field(..., description="The name of the export.")
    address: str = Field(..., description="The address of the export.")


class ExportInfos(BaseModel):
    """A container for a list of exports from a binary."""

    exports: list[ExportInfo] = Field(..., description="A list of exports.")


class ImportInfo(BaseModel):
    """Represents a single imported function or symbol."""

    name: str = Field(..., description="The name of the import.")
    library: str = Field(
        ..., description="The name of the library from which the symbol is imported."
    )


class ImportInfos(BaseModel):
    """A container for a list of imports."""

    imports: list[ImportInfo] = Field(..., description="A list of imports.")


class CrossReferenceInfo(BaseModel):
    """Represents a cross-reference to a specific address in the binary."""

    function_name: str | None = Field(
        None, description="The name of the function containing the cross-reference."
    )
    from_address: str = Field(..., description="The address where the cross-reference originates.")
    to_address: str = Field(..., description="The address that is being referenced.")
    type: str = Field(..., description="The type of the cross-reference.")


class CrossReferenceInfos(BaseModel):
    """A container for a list of cross-references."""

    cross_references: list[CrossReferenceInfo] = Field(
        ..., description="A list of cross-references."
    )


class SymbolInfo(BaseModel):
    """Represents a symbol within the binary."""

    name: str = Field(..., description="The name of the symbol.")
    address: str = Field(..., description="The address of the symbol.")
    type: str = Field(..., description="The type of the symbol.")
    namespace: str = Field(..., description="The namespace of the symbol.")
    source: str = Field(..., description="The source of the symbol.")
    refcount: int = Field(..., description="The reference count of the symbol.")
    external: bool = Field(..., description="Is symbol external.")


class SymbolSearchResults(BaseModel):
    """A container for a list of symbols found during a search."""

    symbols: list[SymbolInfo] = Field(
        ..., description="A list of symbols that match the search criteria."
    )


class SearchMode(str, Enum):
    """Search mode for code search."""

    SEMANTIC = "semantic"  # Vector similarity search
    LITERAL = "literal"  # Exact string match ($contains)


class CodeSearchResult(BaseModel):
    """Represents a single search result from the codebase."""

    function_name: str = Field(
        ..., description="The name of the function where the code was found."
    )
    code: str = Field(..., description="The psuedo-c code snippet")
    similarity: float = Field(..., description="The similarity score of the search result.")
    search_mode: SearchMode = Field(..., description="The search mode used for this result.")
    preview: str | None = Field(None, description="Truncated preview when include_full_code=False.")


class CodeSearchResults(BaseModel):
    """A container for a list of code search results"""

    results: list[CodeSearchResult] = Field(..., description="A list of code search results.")
    query: str = Field(..., description="The query used for the search.")
    search_mode: SearchMode = Field(..., description="The search mode used.")
    # Pagination
    returned_count: int = Field(..., description="Number of results returned in this response.")
    offset: int = Field(..., description="Offset used for pagination.")
    limit: int = Field(..., description="Limit used for pagination.")
    # Dual-mode counts - ALWAYS populated to help LLM decide on mode switching
    literal_total: int = Field(
        ..., description="Total functions containing literal match. 0 if none found."
    )
    semantic_total: int = Field(..., description="Estimated total for semantic search.")
    total_functions: int = Field(..., description="Total number of functions in the binary.")


class StringInfo(BaseModel):
    """Represents a string found within the binary."""

    value: str = Field(..., description="The value of the string.")
    address: str = Field(..., description="The address of the string.")


class StringSearchResult(StringInfo):
    """Represents a string search result found within the binary."""

    similarity: float = Field(..., description="The similarity score of the search result.")


class StringSearchResults(BaseModel):
    """A container for a list of string search results."""

    strings: list[StringSearchResult] = Field(..., description="A list of string search results.")


class BytesReadResult(BaseModel):
    """Represents the result of reading raw bytes from memory."""

    address: str = Field(..., description="The normalized address where bytes were read from.")
    size: int = Field(..., description="The actual number of bytes read.")
    data: str = Field(..., description="The raw bytes as a hexadecimal string.")


class CallGraphDirection(str, Enum):
    """Represents the direction of the call graph."""

    CALLING = "calling"
    CALLED = "called"


class CallGraphDisplayType(str, Enum):
    """Represents the display type of the call graph."""

    FLOW = "flow"
    FLOW_ENDS = "flow_ends"
    MIND = "mind"


class CallGraphResult(BaseModel):
    """Represents the result of a mermaidjs call graph generation."""

    model_config = ConfigDict(exclude_none=True)

    function_name: str = Field(
        ..., description="The name of the function for which the call graph was generated."
    )
    direction: CallGraphDirection = Field(
        ..., description="The direction of the call graph (calling or called)."
    )
    display_type: CallGraphDisplayType = Field(
        ..., description="The type of the call graph visualization."
    )
    graph: str = Field(..., description="The MermaidJS markdown string for the call graph.")
    mermaid_url: str | None = Field(None, description="The MermaidJS image url (opt-in).")


# ── New models added for expanded RE capabilities ─────────────────────────────


class MutationResult(BaseModel):
    """Result of a write/mutation operation (rename, comment, label, signature)."""

    model_config = ConfigDict(exclude_none=True)

    success: bool = Field(..., description="Whether the operation succeeded.")
    message: str = Field(..., description="Human-readable status message.")
    details: dict | None = Field(None, description="Optional extra details about the change.")


class FunctionListItem(BaseModel):
    """Compact representation of a single function for listing."""

    model_config = ConfigDict(exclude_none=True)

    name: str = Field(..., description="Fully-qualified function name.")
    address: str = Field(..., description="Entry point address.")
    namespace: str = Field(..., description="Parent namespace.")
    signature: str | None = Field(None, description="Function signature if available.")


class FunctionListResult(BaseModel):
    """Paginated list of functions."""

    functions: list[FunctionListItem] = Field(..., description="Functions in this page.")
    total: int = Field(..., description="Total matching functions before pagination.")
    offset: int = Field(..., description="Offset used.")
    limit: int = Field(..., description="Limit used.")


class NamespaceInfo(BaseModel):
    """A namespace or class defined in the binary."""

    model_config = ConfigDict(exclude_none=True)

    name: str = Field(..., description="Short name of the namespace/class.")
    full_path: str = Field(..., description="Fully-qualified path.")
    type: str = Field(..., description="NAMESPACE or CLASS.")
    parent: str | None = Field(None, description="Parent namespace (None if global).")


class BasicBlockInfo(BaseModel):
    """A single basic block in a function's control-flow graph."""

    start: str = Field(..., description="Start address of the block.")
    end: str = Field(..., description="End (max) address of the block.")
    num_instructions: int = Field(..., description="Number of instructions in the block.")
    successors: list[str] = Field(..., description="Start addresses of successor blocks.")


class BasicBlocksResult(BaseModel):
    """CFG basic blocks for a function."""

    function_name: str = Field(..., description="Fully-qualified function name.")
    entry_point: str = Field(..., description="Function entry point address.")
    blocks: list[BasicBlockInfo] = Field(..., description="All basic blocks.")


class MemorySegmentInfo(BaseModel):
    """One memory segment/block from the binary's memory map."""

    name: str = Field(..., description="Block name (e.g. '.text', '.data').")
    start: str = Field(..., description="Start address.")
    end: str = Field(..., description="End address.")
    size: int = Field(..., description="Size in bytes.")
    readable: bool = Field(..., description="Read permission.")
    writable: bool = Field(..., description="Write permission.")
    executable: bool = Field(..., description="Execute permission.")
    initialized: bool = Field(..., description="Whether the block has initialized data.")
    type: str = Field(..., description="Block type string from Ghidra.")


class MemoryMapResult(BaseModel):
    """Full memory map for a binary."""

    segments: list[MemorySegmentInfo] = Field(..., description="All memory segments.")


class DataTypeInfo(BaseModel):
    """Summary of a data type defined in the binary."""

    model_config = ConfigDict(exclude_none=True)

    name: str = Field(..., description="Type name.")
    category: str = Field(..., description="Category path (e.g. '/RTTI').")
    display_name: str = Field(..., description="Display name including size hint.")
    type_class: str = Field(..., description="Class: Structure, Enum, Typedef, Pointer, etc.")
    size: int | None = Field(None, description="Size in bytes if known.")


class DataTypeListResult(BaseModel):
    """Paginated list of data types."""

    data_types: list[DataTypeInfo] = Field(..., description="Data types in this page.")
    total: int = Field(..., description="Total data types in the binary.")


class StackVariableInfo(BaseModel):
    """One variable in a function's stack frame."""

    model_config = ConfigDict(exclude_none=True)

    name: str = Field(..., description="Variable name.")
    type_name: str = Field(..., description="Data type name.")
    offset: int = Field(..., description="Stack offset (negative = below saved SP).")
    size: int | None = Field(None, description="Size in bytes.")
    kind: str = Field(..., description="'param' or 'local'.")


class StackFrameResult(BaseModel):
    """Full stack frame layout for a function."""

    model_config = ConfigDict(exclude_none=True)

    function_name: str = Field(..., description="Fully-qualified function name.")
    entry_point: str = Field(..., description="Entry point address.")
    signature: str | None = Field(None, description="Function signature.")
    stack_frame_size: int = Field(..., description="Total stack frame size in bytes.")
    parameters: list[StackVariableInfo] = Field(..., description="Parameters.")
    locals: list[StackVariableInfo] = Field(..., description="Local variables.")


class BytePatternMatch(BaseModel):
    """A single match from a byte-pattern search."""

    model_config = ConfigDict(exclude_none=True)

    address: str = Field(..., description="Address of the match.")
    matched_bytes: str = Field(..., description="Matched bytes as hex string.")
    containing_function: str | None = Field(None, description="Function that contains this address.")


class BytePatternResult(BaseModel):
    """Result of a byte-pattern search."""

    pattern: str = Field(..., description="The original pattern searched for.")
    matches: list[BytePatternMatch] = Field(..., description="All matches found.")
    total: int = Field(..., description="Total number of matches found.")


class StringListResult(BaseModel):
    """Paginated list of strings from a binary."""

    strings: list[StringInfo] = Field(..., description="Strings in this page.")
    total: int = Field(..., description="Total matching strings before pagination.")
    offset: int = Field(..., description="Offset used.")
    limit: int = Field(..., description="Limit used.")


class DecompiledFunctionSummary(BaseModel):
    """Compact decompiled function used inside composite context tools."""

    model_config = ConfigDict(exclude_none=True)

    name: str = Field(..., description="Fully-qualified function name.")
    signature: str | None = Field(None, description="Function signature.")
    code: str = Field(..., description="Decompiled pseudo-C code.")


class FunctionContextResult(BaseModel):
    """Rich context for a single function: decompilation + call graph + xrefs + callee code."""

    model_config = ConfigDict(exclude_none=True)

    function: DecompiledFunction = Field(..., description="Full decompilation of the target.")
    entry_point: str = Field(..., description="Entry point address.")
    callers: list[str] = Field(..., description="Names of functions that call this one.")
    callees: list[str] = Field(..., description="Names of functions called by this one.")
    xrefs: list[CrossReferenceInfo] = Field(..., description="Cross-references to this function.")
    callee_summaries: list[DecompiledFunctionSummary] = Field(
        ..., description="Decompiled code for each callee (depth=1, max 10)."
    )


class ImportCategory(BaseModel):
    """Imports grouped by functional category."""

    category: str = Field(..., description="Category name (network, file_io, crypto, etc.).")
    functions: list[str] = Field(..., description="Import names in this category.")


class BinarySummaryResult(BaseModel):
    """AI-optimised triage summary of a binary for fast orientation."""

    model_config = ConfigDict(exclude_none=True)

    binary_name: str = Field(..., description="Name of the binary.")
    architecture: str | None = Field(None, description="Architecture/language description.")
    entry_points: list[str] = Field(..., description="Entry point addresses/names.")
    function_count: int = Field(..., description="Total number of functions.")
    import_categories: list[ImportCategory] = Field(
        ..., description="Imports grouped by category."
    )
    interesting_strings: list[str] = Field(
        ..., description="Heuristically selected interesting strings."
    )
    memory_segments: list[MemorySegmentInfo] = Field(..., description="Memory map overview.")
    top_exports: list[str] = Field(..., description="Up to 20 exported symbol names.")


class ScriptResult(BaseModel):
    """Result of executing a Python script against the binary."""

    model_config = ConfigDict(exclude_none=True)

    output: str = Field(..., description="Captured stdout from the script.")
    error: str | None = Field(None, description="Exception message if the script raised.")
    result: str | None = Field(
        None, description="str(__result__) if the script set __result__ = ..."
    )
