"""
Comprehensive tool implementations for pyghidra-mcp.
"""

import functools
import logging
import re
import typing
from typing import Any

from ghidrecomp.callgraph import gen_callgraph
from jpype import JByte

from pyghidra_mcp.models import (
    BasicBlockInfo,
    BasicBlocksResult,
    BinarySummaryResult,
    BytePatternMatch,
    BytePatternResult,
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CodeSearchResult,
    CodeSearchResults,
    CrossReferenceInfo,
    DataTypeInfo,
    DataTypeListResult,
    DecompiledFunction,
    DecompiledFunctionSummary,
    ExportInfo,
    FunctionContextResult,
    FunctionListItem,
    FunctionListResult,
    ImportCategory,
    ImportInfo,
    MemorySegmentInfo,
    MutationResult,
    NamespaceInfo,
    ScriptResult,
    SearchMode,
    StackFrameResult,
    StackVariableInfo,
    StringInfo,
    StringListResult,
    StringSearchResult,
    SymbolInfo,
)

if typing.TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import Symbol

    from .context import ProgramInfo

logger = logging.getLogger(__name__)


def handle_exceptions(func):
    """Decorator to handle exceptions in tool methods"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e!s}")
            raise

    return wrapper


class GhidraTools:
    """Comprehensive tool handler for Ghidra MCP tools"""

    def __init__(self, program_info: "ProgramInfo"):
        """Initialize with a Ghidra ProgramInfo object"""
        self.program_info = program_info
        self.program = program_info.program
        self.decompiler = program_info.decompiler

    def _parse_address(self, candidate: str):
        """Attempt to resolve a string candidate into a Ghidra address."""

        candidate = candidate.strip()
        if not candidate:
            return None

        address_factory = self.program.getAddressFactory()

        # First, let Ghidra try to interpret the address directly. This handles
        # base-prefixed formats (e.g., 0x) or default space qualified strings.
        try:
            address = address_factory.getAddress(candidate)
            if address is not None:
                return address
        except Exception:
            pass

        # Normalise potential hexadecimal strings so both 0x-prefixed and bare
        # hex forms are accepted.
        normalized = candidate.lower()
        if normalized.startswith("0x"):
            normalized = normalized[2:]

        if re.fullmatch(r"[0-9a-f]+", normalized):
            try:
                value = int(normalized, 16)
                default_space = address_factory.getDefaultAddressSpace()
                return default_space.getAddress(value)
            except Exception:
                return None

        return None

    def _require_function(self, name_or_address: str) -> "Function":
        fm = self.program.getFunctionManager()
        functions = list(fm.getFunctions(True))

        address = self._parse_address(name_or_address)
        if address is not None:
            func = fm.getFunctionAt(address)
            if func is not None:
                return func

        qualified_matches = [
            func for func in functions if name_or_address == func.getName(True)
        ]
        if len(qualified_matches) == 1:
            return qualified_matches[0]
        if len(qualified_matches) > 1:
            entry_points = ", ".join(str(func.getEntryPoint()) for func in qualified_matches)
            raise ValueError(
                "Multiple functions named "
                f"'{name_or_address}' found at entry points: {entry_points}. "
                "Use an entry point address to disambiguate."
            )

        simple_matches = [func for func in functions if name_or_address == func.getName()]
        if len(simple_matches) == 1:
            return simple_matches[0]
        if len(simple_matches) > 1:
            entry_points = ", ".join(str(func.getEntryPoint()) for func in simple_matches)
            raise ValueError(
                "Multiple functions named "
                f"'{name_or_address}' found at entry points: {entry_points}. "
                "Use a fully qualified name or entry point address to disambiguate."
            )

        raise ValueError(f"Function {name_or_address} not found")

    def _get_filename(self, func: "Function"):
        qualified_name = func.getName(True) or func.getName()
        sanitized = qualified_name.replace("::", "__")
        sanitized = re.sub(r"[^0-9A-Za-z_.-]+", "_", sanitized).strip("_")
        if not sanitized:
            sanitized = "function"
        return f"{sanitized}@{func.getEntryPoint()}"

    @handle_exceptions
    def find_function(
        self,
        name_or_address: str,
        include_externals: bool = True,
    ) -> "Function":
        """
        Resolve a function by name or address.
        - If name_or_address is an address, return the function at that entry point.
        - If it's a name, return exact match if unique.
        - If multiple exact matches, raise with suggestions (signature + entry point).
        - If none, raise with 'Did you mean...' suggestions from partial matches.
        """
        af = self.program.getAddressFactory()
        fm = self.program.getFunctionManager()

        # Try interpreting as an address
        try:
            addr = af.getAddress(name_or_address)
            if addr:
                func = fm.getFunctionAt(addr)
                if func:
                    return func
        except Exception:
            pass  # Not an address, continue with name search

        # Name-based search
        functions = self.get_all_functions(include_externals=include_externals)
        exact_matches = [
            f for f in functions if name_or_address.lower() == f.getSymbol().getName(True).lower()
        ]

        if len(exact_matches) == 1:
            return exact_matches[0]
        elif len(exact_matches) > 1:
            suggestions = [
                f"{f.getSymbol().getName(True)}({f.getSignature()}) @ {f.getEntryPoint()}"
                for f in exact_matches
            ]
            raise ValueError(
                f"Ambiguous match for '{name_or_address}'. Did you mean one of these: "
                + ", ".join(suggestions)
            )

        # No exact matches → suggest partials
        partial_matches = [
            f for f in functions if name_or_address.lower() in f.getSymbol().getName(True).lower()
        ]
        if partial_matches:
            suggestions = [
                f"{f.getSymbol().getName(True)} @ {f.getEntryPoint()}" for f in partial_matches
            ]
            raise ValueError(
                f"Function '{name_or_address}' not found. Did you mean one of these: "
                + ", ".join(suggestions)
            )

        raise ValueError(f"Function or symbol '{name_or_address}' not found.")

    def _lookup_symbols(
        self,
        name_or_address: str,
        *,
        exact: bool = True,
        partial: bool = False,
        dynamic: bool = False,
    ) -> list["Symbol"]:
        """
        Resolve symbols by name or address.
        Returns a single flat list of unique Symbol objects.
        Search modes (exact, partial, dynamic) are optional and only applied if enabled.
        """
        st = self.program.getSymbolTable()
        af = self.program.getAddressFactory()

        # Try interpreting as an address first
        try:
            addr = af.getAddress(name_or_address)
            if addr:
                addr_symbols = st.getSymbols(addr)
                if addr_symbols:
                    return list(addr_symbols)
        except Exception:
            pass  # Not an address, fall back to name search

        name_lc = name_or_address.lower()
        matches: set[Symbol] = set()

        # Base symbol set (externals only once)
        base_symbols = self.get_all_symbols(include_externals=True)

        # Exact match
        if exact:
            matches.update(s for s in base_symbols if name_lc == s.getName(True).lower())

        # Partial match
        if partial:
            matches.update(s for s in base_symbols if name_lc in s.getName(True).lower())

        # Dynamic match (requires second scan)
        if dynamic:
            dyn_symbols = self.get_all_symbols(include_externals=True, include_dynamic=True)
            matches.update(s for s in dyn_symbols if name_lc in s.getName(True).lower())

        return list(matches)

    @handle_exceptions
    def find_symbols(self, name_or_address: str) -> list["Symbol"]:
        """
        Return all symbols that match name_or_address (exact or partial).
        Never raises; returns empty list if none.
        """
        return self._lookup_symbols(name_or_address, exact=True, partial=True)

    @handle_exceptions
    def find_symbol(self, name_or_address: str) -> "Symbol":
        """
        Resolve a single symbol by name or address.
        Raises if ambiguous or not found.
        """
        matches = self._lookup_symbols(name_or_address, exact=True, partial=True)

        if len(matches) == 1:
            return matches[0]
        elif len(matches) > 1:
            suggestions = [f"{s.getName(True)} @ {s.getAddress()}" for s in matches]
            raise ValueError(
                f"Ambiguous match for '{name_or_address}'. Did you mean one of these: "
                + ", ".join(suggestions)
            )
        else:
            raise ValueError(f"Symbol '{name_or_address}' not found.")

    @handle_exceptions
    def decompile_function_by_name_or_addr(
        self, name_or_address: str, timeout: int = 0
    ) -> DecompiledFunction:
        """Finds and decompiles a function in a specified binary and returns its pseudo-C code."""

        func = self.find_function(name_or_address)
        return self.decompile_function(func)

    def decompile_function(self, func: "Function", timeout: int = 0) -> DecompiledFunction:
        """Decompiles a function in a specified binary and returns its pseudo-C code."""
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        result: DecompileResults = self.decompiler.decompileFunction(func, timeout, monitor)
        if "" == result.getErrorMessage():
            code = result.decompiledFunction.getC()
            sig = result.decompiledFunction.getSignature()
        else:
            code = result.getErrorMessage()
            sig = None
        return DecompiledFunction(name=self._get_filename(func), code=code, signature=sig)

    @handle_exceptions
    def get_function_disassembly(self, name: str) -> str:
        """Collect a textual disassembly listing for a function."""

        func = self._require_function(name)
        listing = self.program.getListing()
        instructions = listing.getInstructions(func.getBody(), True)
        lines: list[str] = []
        for instr in instructions:
            lines.append(f"{instr.getAddress()}:\t{instr}")
        return "\n".join(lines)

    @handle_exceptions
    def get_function_callgraph(self, name: str) -> dict[str, list[str]]:
        """Return caller and callee relationships for a function."""

        from ghidra.util.task import ConsoleTaskMonitor

        func = self._require_function(name)
        monitor = ConsoleTaskMonitor()

        callers = sorted({caller.getName() for caller in func.getCallingFunctions(monitor)})
        callees = sorted({callee.getName() for callee in func.getCalledFunctions(monitor)})

        return {"callers": callers, "callees": callees}

    @handle_exceptions
    def get_function_pcode(self, name: str, timeout: int = 0) -> str:
        """Return the Pcode operations for a function."""

        from ghidra.util.task import ConsoleTaskMonitor

        func = self._require_function(name)
        monitor = ConsoleTaskMonitor()
        result: DecompileResults = self.decompiler.decompileFunction(func, timeout, monitor)
        if result.getHighFunction() is None:
            error = result.getErrorMessage()
            if error:
                return error
            return ""

        pcode_ops = result.getHighFunction().getPcodeOps()
        lines: list[str] = []
        while pcode_ops.hasNext():
            op = pcode_ops.next()
            lines.append(str(op))
        return "\n".join(lines)

    @handle_exceptions
    def get_function_analysis_report(self, name: str) -> dict[str, Any]:
        """Generate a structured analysis report for a function (pure JSON, no text blob)."""

        func = self._require_function(name)
        body = func.getBody()
        entry_point = func.getEntryPoint()
        signature = func.getSignature()
        language = self.program.getLanguage()
        parameters = list(func.getParameters())
        locals_ = list(func.getLocalVariables())

        params_list = [
            {"name": p.getName(), "type": str(p.getDataType())} for p in parameters
        ]
        locals_list = [
            {
                "name": v.getName(),
                "type": str(v.getDataType()),
                "address": str(v.getMinAddress()),
            }
            for v in locals_
        ]

        return {
            "function_name": func.getName(True),
            "entry_point": str(entry_point),
            "language": str(language.getLanguageDescription()) if language else None,
            "signature": str(signature),
            "body_size": body.getNumAddresses() if body else 0,
            "parameter_count": len(parameters),
            "local_variable_count": len(locals_),
            "parameters": params_list,
            "locals": locals_list,
        }

    @handle_exceptions
    def get_all_functions(self, include_externals=False) -> list["Function"]:
        """
        Gets all functions within a binary.
        Returns a python list that doesn't need to be re-intialized
        """

        funcs = set()
        fm = self.program.getFunctionManager()
        functions = fm.getFunctions(True)
        for func in functions:
            func: Function
            if not include_externals and func.isExternal():
                continue
            if not include_externals and func.thunk:
                continue
            funcs.add(func)
        return list(funcs)

    @handle_exceptions
    def get_all_symbols(
        self, include_externals: bool = False, include_dynamic=False
    ) -> list["Symbol"]:
        """
        Gets all symbols within a binary.
        Returns a python list that doesn't need to be re-initialized.
        """

        symbols = set()
        from ghidra.program.model.symbol import SymbolTable

        st: SymbolTable = self.program.getSymbolTable()
        all_symbols = st.getAllSymbols(include_dynamic)

        for sym in all_symbols:
            sym: Symbol
            if not include_externals and sym.isExternal():
                continue
            symbols.add(sym)

        return list(symbols)

    @handle_exceptions
    def get_all_strings(self) -> list[StringInfo]:
        """Gets all defined strings for a binary"""
        try:
            from ghidra.program.util import DefinedStringIterator  # type: ignore

            data_iterator = DefinedStringIterator.forProgram(self.program)
        except ImportError:
            # Support Ghidra 11.3.2
            from ghidra.program.util import DefinedDataIterator

            data_iterator = DefinedDataIterator.definedStrings(self.program)

        strings = []
        for data in data_iterator:
            try:
                string_value = data.getValue()
                strings.append(StringInfo(value=str(string_value), address=str(data.getAddress())))
            except Exception as e:
                logger.debug(f"Could not get string value from data at {data.getAddress()}: {e}")

        return strings

    @handle_exceptions
    def search_symbols_by_name(
        self, query: str, offset: int = 0, limit: int = 100
    ) -> list[SymbolInfo]:
        """Searches for symbols within a binary by name."""

        if not query:
            raise ValueError("Query string is required")

        symbols_info = []
        symbols = self.find_symbols(query)
        rm = self.program.getReferenceManager()

        # Search for symbols containing the query string
        for symbol in symbols:
            if query.lower() in symbol.getName(True).lower():
                ref_count = len(list(rm.getReferencesTo(symbol.getAddress())))
                symbols_info.append(
                    SymbolInfo(
                        name=symbol.name,
                        address=str(symbol.getAddress()),
                        type=str(symbol.getSymbolType()),
                        namespace=str(symbol.getParentNamespace()),
                        source=str(symbol.getSource()),
                        refcount=ref_count,
                        external=symbol.isExternal(),
                    )
                )
        return symbols_info[offset : limit + offset]

    @handle_exceptions
    def list_exports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ExportInfo]:
        """Lists all exported functions and symbols from a specified binary."""
        exports = []
        symbols = self.program.getSymbolTable().getAllSymbols(True)
        for symbol in symbols:
            if symbol.isExternalEntryPoint():
                if query and not re.search(query, symbol.getName(), re.IGNORECASE):
                    continue
                exports.append(ExportInfo(name=symbol.getName(), address=str(symbol.getAddress())))
        return exports[offset : limit + offset]

    @handle_exceptions
    def list_imports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ImportInfo]:
        """Lists all imported functions and symbols for a specified binary."""
        imports = []
        symbols = self.program.getSymbolTable().getExternalSymbols()
        for symbol in symbols:
            if query and not re.search(query, symbol.getName(), re.IGNORECASE):
                continue
            imports.append(
                ImportInfo(name=symbol.getName(), library=str(symbol.getParentNamespace()))
            )
        return imports[offset : limit + offset]

    @handle_exceptions
    def list_cross_references(
        self, name_or_address: str, offset: int = 0, limit: int = 100
    ) -> list[CrossReferenceInfo]:
        """Finds and lists all cross-references (x-refs) to a given function, symbol,
        or address within a binary.
        """
        # Use the unified resolver
        sym: Symbol = self.find_symbol(name_or_address)
        addr = sym.getAddress()

        cross_references: list[CrossReferenceInfo] = []
        rm = self.program.getReferenceManager()
        references = rm.getReferencesTo(addr)

        for ref in references:
            from_func = self.program.getFunctionManager().getFunctionContaining(
                ref.getFromAddress()
            )
            cross_references.append(
                CrossReferenceInfo(
                    function_name=from_func.getName() if from_func else None,
                    from_address=str(ref.getFromAddress()),
                    to_address=str(ref.getToAddress()),
                    type=str(ref.getReferenceType()),
                )
            )
        return cross_references[offset : offset + limit]

    def _search_code_literal(
        self,
        literal_results: typing.Any,
        limit: int,
        offset: int,
        include_full_code: bool,
        preview_length: int,
    ) -> list[CodeSearchResult]:
        search_results: list[CodeSearchResult] = []
        if literal_results and literal_results.get("documents"):
            # Apply offset and limit
            docs = literal_results["documents"] or []
            metadatas = literal_results["metadatas"] or []

            # Paginate
            start_idx = offset
            end_idx = offset + limit
            paginated_docs = docs[start_idx:end_idx]
            paginated_meta = metadatas[start_idx:end_idx] if metadatas else []

            for i, doc in enumerate(paginated_docs):
                metadata = paginated_meta[i] if i < len(paginated_meta) else {}
                code = doc
                preview = None

                if not include_full_code:
                    preview = code[:preview_length] + "..." if len(code) > preview_length else code
                    code = preview

                search_results.append(
                    CodeSearchResult(
                        function_name=str(
                            metadata.get("function_name", "unknown")
                            if isinstance(metadata, dict)
                            else "unknown"
                        ),
                        code=code,
                        similarity=1.0,  # Exact match
                        search_mode=SearchMode.LITERAL,
                        preview=preview,
                    )
                )
        return search_results

    def _search_code_semantic(
        self,
        query: str,
        limit: int,
        offset: int,
        similarity_threshold: float,
        include_full_code: bool,
        preview_length: int,
        total_functions: int,  # Added total_functions to correctly calculate semantic_total
    ) -> tuple[list[CodeSearchResult], int]:  # Changed return type to int for semantic_total
        assert self.program_info.code_collection is not None
        search_results: list[CodeSearchResult] = []
        # Semantic search
        results = self.program_info.code_collection.query(
            query_texts=[query],
            n_results=limit + offset,
        )

        docs_list = results.get("documents") if results else None
        semantic_total = total_functions  # Initialize semantic_total here

        if results and docs_list and len(docs_list) > 0 and docs_list[0]:
            # Apply offset
            docs = docs_list[0][offset:]
            metadatas_list = results.get("metadatas")
            distances_list = results.get("distances")
            metadatas = (
                metadatas_list[0][offset:] if metadatas_list and len(metadatas_list) > 0 else []
            )
            distances = (
                distances_list[0][offset:] if distances_list and len(distances_list) > 0 else []
            )

            for i, doc in enumerate(docs):
                metadata = metadatas[i] if i < len(metadatas) else {}
                distance = distances[i] if i < len(distances) else 0
                # ChromaDB uses L2 distance by default (0 = identical, can be > 1)
                # Normalize to 0-1 range where 1 = identical
                similarity = 1 / (1 + distance)

                # Skip results below similarity threshold
                if similarity < similarity_threshold:
                    continue

                code = doc
                preview = None

                if not include_full_code:
                    preview = code[:preview_length] + "..." if len(code) > preview_length else code
                    code = preview

                search_results.append(
                    CodeSearchResult(
                        function_name=str(
                            metadata.get("function_name", "unknown")
                            if isinstance(metadata, dict)
                            else "unknown"
                        ),
                        code=code,
                        similarity=similarity,
                        search_mode=SearchMode.SEMANTIC,
                        preview=preview,
                    )
                )

            # Refine semantic_total
            # If we got fewer results than requested limit (after filtering),
            # providing we fetched enough (n_results was limit+offset)
            # and we processed strictly what we asked for.
            # Actually, if the RAW result count was less than n_results, we know we exhausted
            # the DB.
            # If valid_results_count < limit, we *might* have exhausted matches above threshold
            # in this batch.
            # A better heuristic: if result count < limit, we found everything.
            if len(search_results) < limit:
                # This is only accurate if we assume we found "the end".
                # However, since we queried limit + offset, if we got less than limit (and we
                # started at offset),
                # it implies we are at the tail.
                semantic_total = offset + len(search_results)

        return search_results, semantic_total

    @handle_exceptions
    def search_code(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        search_mode: SearchMode = SearchMode.SEMANTIC,
        include_full_code: bool = True,
        preview_length: int = 500,
        similarity_threshold: float = 0.0,
    ) -> CodeSearchResults:
        """
        Searches the code in the binary for a given query.

        Supports semantic (vector similarity) and literal (exact match) modes.
        Always returns dual-mode counts to help LLM decide on mode switching.

        Args:
            similarity_threshold: Minimum similarity score (0.0-1.0) for semantic results.
                                  Results below this threshold are filtered out.
        """
        if not self.program_info.code_collection:
            raise ValueError(
                "Code indexing is not complete for this binary. Please try again later."
            )

        # ALWAYS get literal count (reuse for literal mode search)
        literal_results = self.program_info.code_collection.get(where_document={"$contains": query})
        literal_total = (
            len(literal_results["ids"]) if literal_results and literal_results.get("ids") else 0
        )

        # Total functions in collection (absolute total)
        total_functions = self.program_info.code_collection.count()

        # Default semantic total to "available" (filtered by limit)
        # If we filter and get FEWER than requested, we effectively found "all" above threshold
        # in this range.
        # But we don't know beyond the limit.
        # So we default to total_functions as "estimated matches" if we hit the limit.
        semantic_total = total_functions

        search_results: list[CodeSearchResult] = []

        if search_mode == SearchMode.LITERAL:
            search_results = self._search_code_literal(
                literal_results, limit, offset, include_full_code, preview_length
            )
        else:
            search_results, estimated_total = self._search_code_semantic(
                query,
                limit,
                offset,
                similarity_threshold,
                include_full_code,
                preview_length,
                total_functions,
            )
            if estimated_total is not None:
                semantic_total = estimated_total

        return CodeSearchResults(
            results=search_results,
            query=query,
            search_mode=search_mode,
            returned_count=len(search_results),
            offset=offset,
            limit=limit,
            literal_total=literal_total,
            semantic_total=semantic_total,
            total_functions=total_functions,
        )

    @handle_exceptions
    def search_strings(self, query: str, limit: int = 100) -> list[StringSearchResult]:
        """Searches for strings within a binary."""

        if not self.program_info.strings_collection:
            raise ValueError(
                "String indexing is not complete for this binary. Please try again later."
            )

        search_results = []
        results = self.program_info.strings_collection.get(
            where_document={"$contains": query}, limit=limit
        )
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"]):
                metadata = results["metadatas"][i]  # type: ignore
                search_results.append(
                    StringSearchResult(
                        value=doc,
                        address=str(metadata["address"]),
                        similarity=1,
                    )
                )
            limit -= len(results["documents"])

        results = self.program_info.strings_collection.query(query_texts=[query], n_results=limit)
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                metadata = results["metadatas"][0][i]  # type: ignore
                distance = results["distances"][0][i]  # type: ignore
                search_results.append(
                    StringSearchResult(
                        value=doc,
                        address=str(metadata["address"]),
                        similarity=1 - distance,
                    )
                )

        return search_results

    @handle_exceptions
    def read_bytes(self, address: str, size: int = 32) -> BytesReadResult:
        """Reads raw bytes from memory at a specified address."""
        # Maximum size limit to prevent excessive memory reads
        max_read_size = 8192

        if size <= 0:
            raise ValueError("size must be > 0")

        if size > max_read_size:
            raise ValueError(f"Size {size} exceeds maximum {max_read_size}")

        # Get address factory and parse address
        af = self.program.getAddressFactory()

        try:
            # Handle common hex address formats
            addr_str = address
            if address.lower().startswith("0x"):
                addr_str = address[2:]

            addr = af.getAddress(addr_str)
            if addr is None:
                raise ValueError(f"Invalid address: {address}")
        except Exception as e:
            raise ValueError(f"Invalid address format '{address}': {e}") from e

        # Check if address is in valid memory
        mem = self.program.getMemory()
        if not mem.contains(addr):
            raise ValueError(f"Address {address} is not in mapped memory")

        # Use JPype to handle byte arrays properly for PyGhidra
        # Create Java byte array - JPype's runtime magic confuses static type checkers
        buf = JByte[size]  # type: ignore[reportInvalidTypeArguments]
        n = mem.getBytes(addr, buf)

        # Convert Java signed bytes (-128 to 127) to Python unsigned (0 to 255)
        if n > 0:
            data = bytes([b & 0xFF for b in buf[:n]])  # type: ignore[reportGeneralTypeIssues]
        else:
            data = b""

        return BytesReadResult(
            address=str(addr),
            size=len(data),
            data=data.hex(),
        )

    @handle_exceptions
    def gen_callgraph(
        self,
        function_name_or_address: str,
        cg_direction: CallGraphDirection = CallGraphDirection.CALLING,
        cg_display_type: CallGraphDisplayType = CallGraphDisplayType.FLOW,
        include_refs: bool = True,
        max_depth: int | None = None,
        max_run_time: int = 60,
        condense_threshold: int = 50,
        top_layers: int = 5,
        bottom_layers: int = 5,
        include_url: bool = False,
    ) -> CallGraphResult:
        """Generates a call graph for a specified function."""

        cg_func = self.find_function(function_name_or_address)
        mermaid_url: str = ""

        # Call the ghidrecomp function
        name, direction, _, graphs_data = gen_callgraph(
            func=cg_func,
            max_display_depth=max_depth,
            direction=cg_direction.value,
            max_run_time=max_run_time,
            name=cg_func.getSymbol().getName(True),
            include_refs=include_refs,
            condense_threshold=condense_threshold,
            top_layers=top_layers,
            bottom_layers=bottom_layers,
            wrap_mermaid=False,
        )

        selected_graph_content = ""
        for graph_type, graph_content in graphs_data:
            if CallGraphDisplayType(graph_type) == cg_display_type:
                selected_graph_content = graph_content
                break

        if not selected_graph_content:
            raise ValueError(
                f"Cg display type {cg_display_type.value} not found for function {cg_func}."
            )

        for graph_type, graph_content in graphs_data:
            if graph_type == "mermaid_url":
                mermaid_url = graph_content.split("\n")[0]
                break

        return CallGraphResult(
            function_name=name,
            direction=CallGraphDirection(direction),
            display_type=cg_display_type,
            graph=selected_graph_content,
            mermaid_url=mermaid_url if include_url else None,
        )

    # ── Annotation / mutation tools ────────────────────────────────────────────

    @handle_exceptions
    def rename_function(self, name_or_address: str, new_name: str) -> MutationResult:
        """Rename a function, persisting the change into the Ghidra project."""
        from ghidra.program.model.symbol import SourceType

        func = self.find_function(name_or_address)
        old_name = func.getName(True)
        tx = self.program.startTransaction("rename function")
        try:
            func.setName(new_name, SourceType.USER_DEFINED)
            self.program.endTransaction(tx, True)
        except Exception:
            self.program.endTransaction(tx, False)
            raise
        return MutationResult(
            success=True,
            message=f"Renamed '{old_name}' → '{new_name}'",
            details={"old_name": old_name, "new_name": new_name, "address": str(func.getEntryPoint())},
        )

    @handle_exceptions
    def rename_variable(
        self, function_name_or_address: str, old_name: str, new_name: str
    ) -> MutationResult:
        """Rename a local variable or parameter inside a function via the decompiler model."""
        from ghidra.program.model.pcode import HighFunctionDBUtil
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor

        func = self.find_function(function_name_or_address)
        monitor = ConsoleTaskMonitor()
        result = self.decompiler.decompileFunction(func, 60, monitor)
        if result.getHighFunction() is None:
            raise ValueError(
                f"Could not decompile '{function_name_or_address}': {result.getErrorMessage()}"
            )

        high_func = result.getHighFunction()
        local_map = high_func.getLocalSymbolMap()

        target_sym = None
        for sym in local_map.getSymbols():
            if sym.getName() == old_name:
                target_sym = sym
                break

        if target_sym is None:
            available = sorted({sym.getName() for sym in local_map.getSymbols()})
            raise ValueError(
                f"Variable '{old_name}' not found in '{function_name_or_address}'. "
                f"Available: {available}"
            )

        tx = self.program.startTransaction("rename variable")
        try:
            HighFunctionDBUtil.updateDBVariable(
                target_sym, new_name, None, SourceType.USER_DEFINED
            )
            self.program.endTransaction(tx, True)
        except Exception:
            self.program.endTransaction(tx, False)
            raise

        return MutationResult(
            success=True,
            message=f"Renamed variable '{old_name}' → '{new_name}' in '{func.getName(True)}'",
            details={"function": func.getName(True), "old_name": old_name, "new_name": new_name},
        )

    @handle_exceptions
    def set_comment(
        self, address: str, comment: str, comment_type: str = "EOL"
    ) -> MutationResult:
        """Set a comment at an address. type: EOL, PRE, POST, PLATE, REPEATABLE."""
        from ghidra.program.model.listing import CodeUnit

        type_map = {
            "EOL": CodeUnit.EOL_COMMENT,
            "PRE": CodeUnit.PRE_COMMENT,
            "POST": CodeUnit.POST_COMMENT,
            "PLATE": CodeUnit.PLATE_COMMENT,
            "REPEATABLE": CodeUnit.REPEATABLE_COMMENT,
        }
        c_type = type_map.get(comment_type.upper())
        if c_type is None:
            raise ValueError(
                f"Invalid comment_type '{comment_type}'. Choose from: {list(type_map)}"
            )

        addr = self._parse_address(address)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")

        listing = self.program.getListing()
        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            raise ValueError(f"No code unit at address {address}")

        tx = self.program.startTransaction("set comment")
        try:
            cu.setComment(c_type, comment if comment else None)
            self.program.endTransaction(tx, True)
        except Exception:
            self.program.endTransaction(tx, False)
            raise

        return MutationResult(
            success=True,
            message=f"Set {comment_type} comment at {addr}",
            details={"address": str(addr), "comment_type": comment_type, "comment": comment},
        )

    @handle_exceptions
    def set_function_signature(
        self, name_or_address: str, signature: str
    ) -> MutationResult:
        """Apply a new C-style function signature (e.g. 'int foo(int a, char *b)')."""
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.app.util.cparser.c import CParserUtils
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor

        func = self.find_function(name_or_address)
        monitor = ConsoleTaskMonitor()

        func_def = CParserUtils.parseSignature(None, self.program, signature, False)
        if func_def is None:
            raise ValueError(f"Could not parse function signature: '{signature}'")

        tx = self.program.startTransaction("set function signature")
        try:
            cmd = ApplyFunctionSignatureCmd(
                func.getEntryPoint(), func_def, SourceType.USER_DEFINED
            )
            if not cmd.applyTo(self.program, monitor):
                raise ValueError(f"Failed to apply signature: {cmd.getStatusMsg()}")
            self.program.endTransaction(tx, True)
        except Exception:
            self.program.endTransaction(tx, False)
            raise

        return MutationResult(
            success=True,
            message=f"Applied signature to '{func.getName(True)}'",
            details={"function": func.getName(True), "new_signature": str(func.getSignature())},
        )

    @handle_exceptions
    def create_label(self, address: str, name: str) -> MutationResult:
        """Create a named label at an address."""
        from ghidra.program.model.symbol import SourceType

        addr = self._parse_address(address)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")

        tx = self.program.startTransaction("create label")
        try:
            st = self.program.getSymbolTable()
            sym = st.createLabel(addr, name, SourceType.USER_DEFINED)
            self.program.endTransaction(tx, True)
        except Exception:
            self.program.endTransaction(tx, False)
            raise

        return MutationResult(
            success=True,
            message=f"Created label '{name}' at {addr}",
            details={"address": str(addr), "name": name},
        )

    # ── Navigation tools ───────────────────────────────────────────────────────

    @handle_exceptions
    def list_functions(
        self,
        query: str = "",
        namespace: str = "",
        offset: int = 0,
        limit: int = 50,
    ) -> FunctionListResult:
        """List functions with optional name/namespace filtering and pagination."""
        all_funcs = self.get_all_functions(include_externals=False)

        if query:
            all_funcs = [f for f in all_funcs if query.lower() in f.getName(True).lower()]
        if namespace:
            all_funcs = [
                f
                for f in all_funcs
                if namespace.lower() in f.getParentNamespace().getName(True).lower()
            ]

        total = len(all_funcs)
        all_funcs.sort(key=lambda f: str(f.getEntryPoint()))
        paginated = all_funcs[offset : offset + limit]

        items = [
            FunctionListItem(
                name=func.getName(True),
                address=str(func.getEntryPoint()),
                namespace=str(func.getParentNamespace()),
                signature=str(func.getSignature()) if func.getSignature() else None,
            )
            for func in paginated
        ]
        return FunctionListResult(functions=items, total=total, offset=offset, limit=limit)

    @handle_exceptions
    def list_namespaces(self, query: str = "") -> list[NamespaceInfo]:
        """List all namespaces and classes defined in the binary."""
        st = self.program.getSymbolTable()
        results: list[NamespaceInfo] = []
        seen: set[str] = set()

        for sym in st.getAllSymbols(False):
            type_str = str(sym.getSymbolType())
            if type_str not in ("NAMESPACE", "CLASS"):
                continue
            full_path = sym.getName(True)
            if full_path in seen:
                continue
            if query and query.lower() not in full_path.lower():
                continue
            seen.add(full_path)
            parent = sym.getParentNamespace()
            parent_name = str(parent) if parent and not parent.isGlobal() else None
            results.append(
                NamespaceInfo(
                    name=sym.getName(),
                    full_path=full_path,
                    type=type_str,
                    parent=parent_name,
                )
            )
        return results

    @handle_exceptions
    def get_function_containing(self, address: str) -> FunctionListItem | None:
        """Return the function that contains a given address, or None."""
        addr = self._parse_address(address)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")

        fm = self.program.getFunctionManager()
        func = fm.getFunctionContaining(addr)
        if func is None:
            return None

        return FunctionListItem(
            name=func.getName(True),
            address=str(func.getEntryPoint()),
            namespace=str(func.getParentNamespace()),
            signature=str(func.getSignature()) if func.getSignature() else None,
        )

    @handle_exceptions
    def list_basic_blocks(self, name_or_address: str) -> BasicBlocksResult:
        """Return all CFG basic blocks for a function."""
        from ghidra.program.model.block import BasicBlockModel
        from ghidra.util.task import ConsoleTaskMonitor

        func = self.find_function(name_or_address)
        monitor = ConsoleTaskMonitor()
        bbm = BasicBlockModel(self.program)
        listing = self.program.getListing()
        blocks: list[BasicBlockInfo] = []

        code_blocks = bbm.getCodeBlocksContaining(func.getBody(), monitor)
        while code_blocks.hasNext():
            block = code_blocks.next()
            start = str(block.getFirstStartAddress())
            end = str(block.getMaxAddress())

            num_instrs = sum(1 for _ in listing.getInstructions(block, True))

            successors: list[str] = []
            dest_iter = block.getDestinations(monitor)
            while dest_iter.hasNext():
                ref = dest_iter.next()
                dest_addr = ref.getDestinationAddress()
                if func.getBody().contains(dest_addr):
                    successors.append(str(dest_addr))

            blocks.append(
                BasicBlockInfo(
                    start=start,
                    end=end,
                    num_instructions=num_instrs,
                    successors=successors,
                )
            )

        return BasicBlocksResult(
            function_name=func.getName(True),
            entry_point=str(func.getEntryPoint()),
            blocks=blocks,
        )

    @handle_exceptions
    def get_entry_points(self) -> list[str]:
        """Return all entry-point symbols/addresses defined in the binary."""
        st = self.program.getSymbolTable()
        fm = self.program.getFunctionManager()
        results: list[str] = []
        for addr in st.getExternalEntryPointIterator():
            func = fm.getFunctionAt(addr)
            results.append(f"{func.getName(True)}@{addr}" if func else str(addr))
        return results

    # ── Memory tools ───────────────────────────────────────────────────────────

    @handle_exceptions
    def list_memory_segments(self) -> list[MemorySegmentInfo]:
        """Return all memory blocks (segments) from the binary's memory map."""
        mem = self.program.getMemory()
        return [
            MemorySegmentInfo(
                name=block.getName(),
                start=str(block.getStart()),
                end=str(block.getEnd()),
                size=block.getSize(),
                readable=block.isRead(),
                writable=block.isWrite(),
                executable=block.isExecute(),
                initialized=block.isInitialized(),
                type=str(block.getType()),
            )
            for block in mem.getBlocks()
        ]

    @handle_exceptions
    def find_byte_pattern(
        self,
        pattern: str,
        start: str = "",
        end: str = "",
        limit: int = 50,
    ) -> BytePatternResult:
        """Search for a byte pattern with wildcard support, e.g. '90 ? ? FF D0'."""
        from jpype import JByte
        from ghidra.util.task import ConsoleTaskMonitor

        parts = pattern.strip().split()
        if not parts:
            raise ValueError("Empty pattern")

        n = len(parts)
        byte_vals: list[int] = []
        mask_vals: list[int] = []
        for p in parts:
            if p in ("?", "??"):
                byte_vals.append(0)
                mask_vals.append(0x00)
            else:
                byte_vals.append(int(p, 16))
                mask_vals.append(0xFF)

        # Build Java signed byte arrays
        bytes_arr = JByte[n]  # type: ignore[reportInvalidTypeArguments]
        mask_arr = JByte[n]  # type: ignore[reportInvalidTypeArguments]
        for i in range(n):
            v = byte_vals[i]
            bytes_arr[i] = v if v < 128 else v - 256
            m = mask_vals[i]
            mask_arr[i] = m if m < 128 else m - 256

        mem = self.program.getMemory()
        fm = self.program.getFunctionManager()
        monitor = ConsoleTaskMonitor()

        if start:
            current = self._parse_address(start)
            if current is None:
                raise ValueError(f"Invalid start address: {start}")
        else:
            current = mem.getMinAddress()

        end_addr = None
        if end:
            end_addr = self._parse_address(end)
            if end_addr is None:
                raise ValueError(f"Invalid end address: {end}")

        matches: list[BytePatternMatch] = []
        while len(matches) < limit:
            found = mem.findBytes(current, bytes_arr, mask_arr, True, monitor)
            if found is None:
                break
            if end_addr is not None and found.compareTo(end_addr) > 0:
                break

            func = fm.getFunctionContaining(found)
            buf = JByte[n]  # type: ignore[reportInvalidTypeArguments]
            mem.getBytes(found, buf)
            matched_hex = "".join(f"{b & 0xFF:02x}" for b in buf[:n])  # type: ignore

            matches.append(
                BytePatternMatch(
                    address=str(found),
                    matched_bytes=matched_hex,
                    containing_function=func.getName(True) if func else None,
                )
            )
            try:
                current = found.add(1)
            except Exception:
                break

        return BytePatternResult(pattern=pattern, matches=matches, total=len(matches))

    @handle_exceptions
    def list_all_strings(
        self,
        min_length: int = 4,
        query: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> StringListResult:
        """Paginated listing of all defined strings with optional substring filter."""
        all_strings = self.get_all_strings()

        if min_length > 0:
            all_strings = [s for s in all_strings if len(s.value) >= min_length]
        if query:
            all_strings = [s for s in all_strings if query.lower() in s.value.lower()]

        total = len(all_strings)
        return StringListResult(
            strings=all_strings[offset : offset + limit],
            total=total,
            offset=offset,
            limit=limit,
        )

    # ── Data type tools ────────────────────────────────────────────────────────

    def _resolve_data_type(self, type_name: str):
        """Resolve a type name string to a Ghidra DataType, checking program DTM then builtins."""
        dtm = self.program.getDataTypeManager()
        name_lc = type_name.lower()
        for dt in dtm.getAllDataTypes():
            if dt.getName().lower() == name_lc:
                return dt
        try:
            from ghidra.program.model.data import BuiltInDataTypeManager

            builtin_dtm = BuiltInDataTypeManager.getDataTypeManager()
            for dt in builtin_dtm.getAllDataTypes():
                if dt.getName().lower() == name_lc:
                    return dt
        except Exception:
            pass
        return None

    @handle_exceptions
    def list_data_types(
        self, category_filter: str = "", limit: int = 100
    ) -> DataTypeListResult:
        """List data types defined in the binary, optionally filtered by category or name."""
        dtm = self.program.getDataTypeManager()
        total = dtm.getDataTypeCount(False)
        results: list[DataTypeInfo] = []

        for dt in dtm.getAllDataTypes():
            if len(results) >= limit:
                break
            category = str(dt.getCategoryPath())
            if category_filter and (
                category_filter.lower() not in category.lower()
                and category_filter.lower() not in dt.getName().lower()
            ):
                continue
            class_name = str(dt.getClass().getSimpleName())
            class_name = class_name.replace("DataType", "").replace("DB", "")
            try:
                size: int | None = dt.getLength()
                if size <= 0:
                    size = None
            except Exception:
                size = None
            results.append(
                DataTypeInfo(
                    name=dt.getName(),
                    category=category,
                    display_name=dt.getDisplayName(),
                    type_class=class_name,
                    size=size,
                )
            )

        return DataTypeListResult(data_types=results, total=total)

    @handle_exceptions
    def get_data_type(self, type_name: str) -> dict[str, Any]:
        """Get the full definition of a data type (struct fields, enum values, etc.)."""
        dtm = self.program.getDataTypeManager()
        name_lc = type_name.lower()
        matches = [dt for dt in dtm.getAllDataTypes() if dt.getName().lower() == name_lc]

        if not matches:
            raise ValueError(f"Data type '{type_name}' not found")
        if len(matches) > 1:
            return {
                "ambiguous": True,
                "matches": [
                    {
                        "name": dt.getName(),
                        "category": str(dt.getCategoryPath()),
                        "display_name": dt.getDisplayName(),
                    }
                    for dt in matches
                ],
            }

        dt = matches[0]
        class_name = str(dt.getClass().getSimpleName())
        result: dict[str, Any] = {
            "name": dt.getName(),
            "category": str(dt.getCategoryPath()),
            "display_name": dt.getDisplayName(),
            "description": str(dt.getDescription()) if dt.getDescription() else None,
        }

        if "Structure" in class_name or "Struct" in class_name:
            components = []
            for comp in dt.getComponents():
                components.append(
                    {
                        "name": comp.getFieldName() or f"field_{comp.getOffset():x}",
                        "type": comp.getDataType().getDisplayName(),
                        "offset": comp.getOffset(),
                        "size": comp.getLength(),
                        "comment": comp.getComment() if comp.getComment() else None,
                    }
                )
            result["fields"] = components
            result["size"] = dt.getLength()
        elif "Enum" in class_name:
            result["values"] = {name: dt.getValue(name) for name in dt.getNames()}
            result["size"] = dt.getLength()
        else:
            try:
                result["size"] = dt.getLength()
            except Exception:
                pass

        return result

    @handle_exceptions
    def create_struct(self, name: str, fields: list[dict[str, Any]]) -> dict[str, Any]:
        """Define a new struct data type and register it in the program's data type manager."""
        from ghidra.program.model.data import (
            CategoryPath,
            DataTypeConflictHandler,
            StructureDataType,
        )

        dtm = self.program.getDataTypeManager()
        struct = StructureDataType(CategoryPath("/"), name, 0)

        for field in fields:
            field_name = field.get("name", "")
            type_name = field.get("type", "undefined")
            comment = field.get("comment", "")
            ft = self._resolve_data_type(type_name)
            if ft is None:
                raise ValueError(f"Unknown data type: '{type_name}'")
            struct.add(ft, ft.getLength(), field_name, comment)

        tx = self.program.startTransaction("create struct")
        try:
            final_dt = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)
            self.program.endTransaction(tx, True)
        except Exception:
            self.program.endTransaction(tx, False)
            raise

        return {
            "success": True,
            "name": final_dt.getName(),
            "category": str(final_dt.getCategoryPath()),
            "size": final_dt.getLength(),
            "num_fields": len(fields),
        }

    @handle_exceptions
    def apply_data_type(self, address: str, type_name: str) -> dict[str, Any]:
        """Apply a data type to a memory address, creating structured data."""
        addr = self._parse_address(address)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")

        dt = self._resolve_data_type(type_name)
        if dt is None:
            raise ValueError(f"Data type '{type_name}' not found")

        listing = self.program.getListing()
        tx = self.program.startTransaction("apply data type")
        try:
            listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
            listing.createData(addr, dt)
            self.program.endTransaction(tx, True)
        except Exception:
            self.program.endTransaction(tx, False)
            raise

        return {
            "success": True,
            "address": str(addr),
            "type": dt.getDisplayName(),
            "size": dt.getLength(),
        }

    @handle_exceptions
    def get_data_at(self, address: str) -> dict[str, Any]:
        """Read structured data defined at an address."""
        addr = self._parse_address(address)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")

        listing = self.program.getListing()
        data = listing.getDataAt(addr) or listing.getDataContaining(addr)
        if data is None:
            raise ValueError(f"No data defined at {address}")

        result: dict[str, Any] = {
            "address": str(data.getAddress()),
            "type": data.getDataType().getDisplayName(),
            "size": data.getLength(),
        }
        try:
            val = data.getValue()
            if val is not None:
                result["value"] = str(val)
        except Exception:
            pass

        class_name = str(data.getDataType().getClass().getSimpleName())
        if "Structure" in class_name or "Struct" in class_name:
            components = []
            for i in range(data.getNumComponents()):
                comp = data.getComponent(i)
                if comp:
                    comp_val = None
                    try:
                        comp_val = str(comp.getValue())
                    except Exception:
                        pass
                    components.append(
                        {
                            "name": comp.getFieldName() or f"field_{i}",
                            "type": comp.getDataType().getDisplayName(),
                            "offset": comp.getParentOffset(),
                            "value": comp_val,
                        }
                    )
            result["components"] = components

        return result

    @handle_exceptions
    def get_stack_frame(self, name_or_address: str) -> StackFrameResult:
        """Return the full stack frame layout (parameters + locals) for a function."""
        func = self.find_function(name_or_address)
        frame = func.getStackFrame()
        frame_size = frame.getFrameSize() if frame else 0

        def _var_info(v, kind: str) -> StackVariableInfo:
            storage = v.getVariableStorage()
            offset = storage.getStackOffset() if storage and storage.isStackStorage() else 0
            size: int | None = v.getLength() if v.getLength() > 0 else None
            return StackVariableInfo(
                name=v.getName(),
                type_name=v.getDataType().getDisplayName() if v.getDataType() else "unknown",
                offset=offset,
                size=size,
                kind=kind,
            )

        params = [_var_info(p, "param") for p in func.getParameters()]
        locals_ = [_var_info(v, "local") for v in func.getLocalVariables()]

        return StackFrameResult(
            function_name=func.getName(True),
            entry_point=str(func.getEntryPoint()),
            signature=str(func.getSignature()),
            stack_frame_size=frame_size,
            parameters=params,
            locals=locals_,
        )

    # ── Composite / context tools ──────────────────────────────────────────────

    @handle_exceptions
    def get_function_context(
        self, name_or_address: str, callee_depth: int = 1
    ) -> FunctionContextResult:
        """Return full decompilation + callers/callees + xrefs + callee code in one call."""
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        func = self.find_function(name_or_address)

        decompiled = self.decompile_function(func)
        callers = sorted({f.getName(True) for f in func.getCallingFunctions(monitor)})
        callees = sorted({f.getName(True) for f in func.getCalledFunctions(monitor)})

        rm = self.program.getReferenceManager()
        xrefs: list[CrossReferenceInfo] = []
        for ref in rm.getReferencesTo(func.getEntryPoint()):
            from_func = self.program.getFunctionManager().getFunctionContaining(
                ref.getFromAddress()
            )
            xrefs.append(
                CrossReferenceInfo(
                    function_name=from_func.getName(True) if from_func else None,
                    from_address=str(ref.getFromAddress()),
                    to_address=str(ref.getToAddress()),
                    type=str(ref.getReferenceType()),
                )
            )

        callee_summaries: list[DecompiledFunctionSummary] = []
        if callee_depth > 0:
            called_funcs = list(func.getCalledFunctions(monitor))[:10]
            for callee_func in called_funcs:
                if callee_func.isExternal() or callee_func.isThunk():
                    callee_summaries.append(
                        DecompiledFunctionSummary(
                            name=callee_func.getName(True),
                            signature=str(callee_func.getSignature()),
                            code=f"// external: {callee_func.getName(True)}",
                        )
                    )
                else:
                    try:
                        cd = self.decompile_function(callee_func)
                        callee_summaries.append(
                            DecompiledFunctionSummary(
                                name=cd.name,
                                signature=cd.signature,
                                code=cd.code,
                            )
                        )
                    except Exception:
                        pass

        return FunctionContextResult(
            function=decompiled,
            entry_point=str(func.getEntryPoint()),
            callers=callers,
            callees=callees,
            xrefs=xrefs,
            callee_summaries=callee_summaries,
        )

    @handle_exceptions
    def get_binary_summary(self) -> BinarySummaryResult:
        """Return an AI-optimised triage summary of the binary for rapid orientation."""
        lang = self.program.getLanguage()
        arch = str(lang.getLanguageDescription()) if lang else None

        st = self.program.getSymbolTable()
        fm = self.program.getFunctionManager()
        entry_pts: list[str] = []
        for addr in st.getExternalEntryPointIterator():
            func = fm.getFunctionAt(addr)
            entry_pts.append(f"{func.getName(True)}@{addr}" if func else str(addr))

        func_count = fm.getFunctionCount()

        # Imports grouped by category
        _CATEGORIES: dict[str, list[str]] = {
            "network": ["socket", "send", "recv", "connect", "bind", "listen", "accept", "wsa",
                        "inet", "getaddrinfo", "gethostby", "curl", "http"],
            "file_io": ["fopen", "fread", "fwrite", "fclose", "open", "read", "write",
                        "createfile", "readfile", "writefile", "deletefile"],
            "crypto": ["crypt", "aes", "rsa", "sha", "md5", "bcrypt", "openssl", "evp_",
                       "ssl_", "crc", "hmac"],
            "memory": ["malloc", "free", "realloc", "calloc", "virtualalloc", "heapalloc",
                       "mmap", "memcpy", "memset"],
            "process": ["createprocess", "shellexecute", "system", "exec", "fork", "spawn",
                        "winexec"],
            "registry": ["regopen", "regset", "regquery", "regcreate", "regdelete"],
            "thread": ["createthread", "pthread_create", "waitforsingle", "setevent", "mutex",
                       "semaphore"],
            "string": ["strlen", "strcpy", "strcat", "sprintf", "printf", "wcscpy", "wcslen"],
        }

        categorized: dict[str, list[str]] = {}
        import_syms = list(self.program.getSymbolTable().getExternalSymbols())
        for sym in import_syms:
            import_name = sym.getName()
            name_lc = import_name.lower()
            matched = False
            for cat, keywords in _CATEGORIES.items():
                if any(kw in name_lc for kw in keywords):
                    categorized.setdefault(cat, []).append(import_name)
                    matched = True
                    break
            if not matched:
                categorized.setdefault("other", []).append(import_name)

        import_cats = [
            ImportCategory(category=cat, functions=fns)
            for cat, fns in sorted(categorized.items())
        ]

        # Heuristically interesting strings
        _INTERESTING = [
            r"https?://",
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"[A-Z]:\\",
            r"/etc/|/tmp/|/var/|/proc/",
            r"password|passwd|secret|token|apikey|auth",
            r"error|exception|fail|denied|invalid",
        ]
        interesting: list[str] = []
        try:
            for s in self.get_all_strings():
                if any(re.search(p, s.value, re.IGNORECASE) for p in _INTERESTING):
                    interesting.append(s.value)
                    if len(interesting) >= 50:
                        break
        except Exception:
            pass

        segments = self.list_memory_segments()
        exports = self.list_exports(limit=20)
        top_exports = [e.name for e in exports]

        return BinarySummaryResult(
            binary_name=self.program.getName(),
            architecture=arch,
            entry_points=entry_pts,
            function_count=func_count,
            import_categories=import_cats,
            interesting_strings=interesting,
            memory_segments=segments,
            top_exports=top_exports,
        )

    @handle_exceptions
    def decompile_functions_batch(
        self, names_or_addrs: list[str]
    ) -> list[DecompiledFunction]:
        """Decompile multiple functions in a single call."""
        results: list[DecompiledFunction] = []
        for name_or_addr in names_or_addrs:
            try:
                results.append(self.decompile_function_by_name_or_addr(name_or_addr))
            except Exception as exc:
                results.append(
                    DecompiledFunction(
                        name=name_or_addr,
                        code=f"// Error: {exc}",
                        signature=None,
                    )
                )
        return results

    # ── Script execution ───────────────────────────────────────────────────────

    @handle_exceptions
    def run_python_script(self, code: str) -> ScriptResult:
        """Execute arbitrary Python with program/flat_api/decompiler in scope.

        Set ``__result__ = <value>`` in the script to populate the result field.
        """
        import contextlib
        import io

        stdout_capture = io.StringIO()
        exec_globals: dict[str, Any] = {
            "program": self.program,
            "flat_api": self.program_info.flat_api,
            "decompiler": self.decompiler,
            "program_info": self.program_info,
        }

        error_msg: str | None = None
        try:
            with contextlib.redirect_stdout(stdout_capture):
                exec(compile(code, "<mcp_script>", "exec"), exec_globals)  # noqa: S102
        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {exc}"

        result_val = exec_globals.get("__result__")
        return ScriptResult(
            output=stdout_capture.getvalue(),
            error=error_msg,
            result=str(result_val) if result_val is not None else None,
        )
