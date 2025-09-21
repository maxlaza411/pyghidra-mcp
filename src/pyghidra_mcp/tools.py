"""
Comprehensive tool implementations for pyghidra-mcp.
"""

from __future__ import annotations

import functools
import logging
import re
import typing
from collections.abc import Iterable

from pyghidra_mcp.models import (
    CodeSearchResult,
    CrossReferenceInfo,
    DecompiledFunction,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    StringInfo,
    StringSearchResult,
    SymbolInfo,
)

if typing.TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults
    from ghidra.program.model.listing import Function

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

    def __init__(self, program_info: ProgramInfo):
        """Initialize with a Ghidra ProgramInfo object"""
        self.program_info = program_info
        self.program = program_info.program
        self.decompiler = program_info.decompiler

    def _get_filename(self, func: Function):
        qualified_name = func.getName(True)
        entry_point = func.getEntryPoint()
        safe_name = re.sub(r"[\\/:*?\"<>|]", "_", qualified_name)
        return f"{safe_name}@{entry_point}"

    @staticmethod
    def _split_identifier(identifier: str) -> tuple[str, str | None]:
        if "@" not in identifier:
            return identifier, None
        name_part, _, address_part = identifier.partition("@")
        cleaned_name = name_part.strip() or identifier
        cleaned_address = address_part.strip() or None
        return cleaned_name, cleaned_address

    @staticmethod
    def _normalize_address_text(address_text: str) -> str:
        value = address_text.strip().lower()
        if not value:
            return ""
        if value.startswith("0x"):
            value = value[2:]
        if ":" in value:
            value = value.split(":")[-1]
        return value

    def _build_address_indexes(
        self, functions: list[Function]
    ) -> tuple[dict[str, Function], dict[str, list[Function]], dict[int, list[Function]]]:
        entry_lookup: dict[str, Function] = {}
        normalized_lookup: dict[str, list[Function]] = {}
        offset_lookup: dict[int, list[Function]] = {}
        for func in functions:
            entry_point = func.getEntryPoint()
            entry_str = str(entry_point)
            entry_lookup[entry_str] = func
            normalized = self._normalize_address_text(entry_str)
            if not normalized:
                continue
            normalized_lookup.setdefault(normalized, []).append(func)
            try:
                offset_lookup.setdefault(int(normalized, 16), []).append(func)
            except ValueError:
                continue
        return entry_lookup, normalized_lookup, offset_lookup

    def _get_address_from_factory(self, address_text: str):
        try:
            return self.program.getAddressFactory().getAddress(address_text)
        except Exception:
            return None

    @staticmethod
    def _parse_offset(normalized: str) -> int | None:
        try:
            return int(normalized, 16)
        except ValueError:
            return None

    def _find_function_by_address(
        self,
        address_text: str | None,
        fm,
        functions: list[Function],
        entry_lookup: dict[str, Function],
        normalized_lookup: dict[str, list[Function]],
        offset_lookup: dict[int, list[Function]],
        candidates: Iterable[Function] | None = None,
    ) -> Function | None:
        if not address_text:
            return None
        cleaned_address = address_text.strip()
        if not cleaned_address:
            return None

        pool = list(candidates) if candidates is not None else functions
        pool_set = set(pool)
        potential_matches: list[Function] = []

        direct_match = entry_lookup.get(cleaned_address)
        if direct_match:
            potential_matches.append(direct_match)

        address = self._get_address_from_factory(cleaned_address)
        if address:
            func_at = fm.getFunctionAt(address)
            if func_at:
                potential_matches.append(func_at)

        normalized = self._normalize_address_text(cleaned_address)
        if normalized:
            potential_matches.extend(normalized_lookup.get(normalized, []))
            offset = self._parse_offset(normalized)
            if offset is not None:
                potential_matches.extend(offset_lookup.get(offset, []))

        for candidate in potential_matches:
            if candidate in pool_set:
                return candidate

        return None

    @staticmethod
    def _match_functions_by_name(name_hint: str, functions: list[Function]) -> list[Function]:
        if not name_hint:
            return []
        return [
            func
            for func in functions
            if name_hint == func.getName() or name_hint == func.getName(True)
        ]

    def _resolve_function_by_name(
        self,
        name_hint: str,
        identifier: str,
        address_hint: str | None,
        fm,
        functions: list[Function],
        entry_lookup: dict[str, Function],
        normalized_lookup: dict[str, list[Function]],
        offset_lookup: dict[int, list[Function]],
    ) -> Function | None:
        matches = self._match_functions_by_name(name_hint, functions)
        if not matches:
            return None
        if len(matches) == 1:
            return matches[0]

        target = self._find_function_by_address(
            identifier,
            fm,
            functions,
            entry_lookup,
            normalized_lookup,
            offset_lookup,
            matches,
        )
        if target is None and address_hint:
            target = self._find_function_by_address(
                address_hint,
                fm,
                functions,
                entry_lookup,
                normalized_lookup,
                offset_lookup,
                matches,
            )
        if target is not None:
            return target

        suggestions = ", ".join(
            sorted(f"{func.getName(True)}@{func.getEntryPoint()}" for func in matches)
        )
        raise ValueError(
            f"Multiple functions matched '{name_hint}'. "
            f"Disambiguate using one of: {suggestions}"
        )

    @handle_exceptions
    def decompile_function(self, name: str, timeout: int = 0) -> DecompiledFunction:
        """Decompiles a function in a specified binary and returns its pseudo-C code."""
        from ghidra.util.task import ConsoleTaskMonitor

        identifier = name.strip()
        if not identifier:
            raise ValueError("Function identifier is required")

        fm = self.program.getFunctionManager()
        functions = list(fm.getFunctions(True))
        name_hint, address_hint = self._split_identifier(identifier)
        entry_lookup, normalized_lookup, offset_lookup = self._build_address_indexes(functions)

        target_func = self._find_function_by_address(
            identifier, fm, functions, entry_lookup, normalized_lookup, offset_lookup
        )
        if target_func is None and address_hint:
            target_func = self._find_function_by_address(
                address_hint, fm, functions, entry_lookup, normalized_lookup, offset_lookup
            )

        if target_func is None:
            target_func = self._resolve_function_by_name(
                name_hint,
                identifier,
                address_hint,
                fm,
                functions,
                entry_lookup,
                normalized_lookup,
                offset_lookup,
            )

        if target_func is None:
            target_func = entry_lookup.get(identifier)
        if target_func is None and address_hint:
            target_func = entry_lookup.get(address_hint)

        if target_func is None:
            raise ValueError(f"Function {name} not found")

        monitor = ConsoleTaskMonitor()
        result: DecompileResults = self.decompiler.decompileFunction(
            target_func, timeout, monitor
        )
        if "" == result.getErrorMessage():
            code = result.decompiledFunction.getC()
            sig = result.decompiledFunction.getSignature()
        else:
            code = result.getErrorMessage()
            sig = None
        return DecompiledFunction(
            name=self._get_filename(target_func), code=code, signature=sig
        )

    @handle_exceptions
    def get_all_functions(self, include_externals=False) -> list[Function]:
        """Gets all functions within a binary."""

        funcs = []
        fm = self.program.getFunctionManager()
        functions = fm.getFunctions(True)
        for func in functions:
            func: Function
            if not include_externals and func.isExternal():
                continue
            if not include_externals and func.thunk:
                continue
            funcs.append(func)
        return funcs

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
    def search_functions_by_name(
        self, query: str, offset: int = 0, limit: int = 100
    ) -> list[FunctionInfo]:
        """Searches for functions within a binary by name."""
        if not query:
            raise ValueError("Query string is required")

        funcs = []
        fm = self.program.getFunctionManager()
        functions = fm.getFunctions(True)
        # Search for functions containing the query string
        for func in functions:
            func: Function
            if query.lower() in func.name.lower():
                funcs.append(FunctionInfo(name=func.name, entry_point=str(func.getEntryPoint())))
        return funcs[offset : limit + offset]

    @handle_exceptions
    def search_symbols_by_name(
        self, query: str, offset: int = 0, limit: int = 100
    ) -> list[SymbolInfo]:
        """Searches for symbols within a binary by name."""
        from ghidra.program.model.symbol import SymbolTable

        if not query:
            raise ValueError("Query string is required")

        symbols_info = []
        st: SymbolTable = self.program.getSymbolTable()
        symbols = st.getAllSymbols(True)
        rm = self.program.getReferenceManager()

        # Search for symbols containing the query string
        for symbol in symbols:
            if query.lower() in symbol.name.lower():
                ref_count = len(list(rm.getReferencesTo(symbol.getAddress())))
                symbols_info.append(
                    SymbolInfo(
                        name=symbol.name,
                        address=str(symbol.getAddress()),
                        type=str(symbol.getSymbolType()),
                        namespace=str(symbol.getParentNamespace()),
                        source=str(symbol.getSource()),
                        refcount=ref_count,
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
    def list_cross_references(self, name_or_address: str) -> list[CrossReferenceInfo]:
        """Finds and lists all cross-references (x-refs) to a given function, symbol,
        or address within a binary.
        """
        addr = None
        try:
            addr = self.program.getAddressFactory().getAddress(name_or_address)
        except Exception:
            pass

        if addr is None:
            # Search for exact match in symbols. Functions are symbols, so this covers them.
            st = self.program.getSymbolTable()
            symbols = st.getAllSymbols(True)
            for symbol in symbols:
                if name_or_address.lower() == symbol.name.lower():
                    addr = symbol.getAddress()
                    break

        # If no exact match is found, find close matches and raise an error
        if addr is None:
            close_matches = []
            st = self.program.getSymbolTable()
            symbols = st.getAllSymbols(True)
            for symbol in symbols:
                if name_or_address.lower() in symbol.name.lower():
                    close_matches.append(symbol.name)

            if close_matches:
                unique_matches = sorted(list(set(close_matches)))
                total_matches = len(unique_matches)

                # Sort by length to get potentially more relevant matches first, and take top 10
                display_matches = sorted(unique_matches, key=len)[:10]

                suggestions = ", ".join(display_matches)
                message = (
                    f"Could not find '{name_or_address}'. Did you mean one of these: {suggestions}"
                )
                message += f" (total similar symbols {total_matches})?"
                raise ValueError(message)
            else:
                raise ValueError(f"Could not find function, symbol, or address: {name_or_address}")

        cross_references = []

        # Get references
        rm = self.program.getReferenceManager()
        references = rm.getReferencesTo(addr)

        for ref in references:
            func = self.program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
            cross_references.append(
                CrossReferenceInfo(
                    function_name=func.getName() if func else None,
                    from_address=str(ref.getFromAddress()),
                    to_address=str(ref.getToAddress()),
                    type=str(ref.getReferenceType()),
                )
            )
        return cross_references

    @handle_exceptions
    def search_code(self, query: str, limit: int = 10) -> list[CodeSearchResult]:
        """Searches the code in the binary for a given query."""
        if not self.program_info.collection:
            raise ValueError("Chromadb collection not initialized")

        results = self.program_info.collection.query(query_texts=[query], n_results=limit)
        search_results = []
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                metadata = results["metadatas"][0][i]  # type: ignore
                distance = results["distances"][0][i]  # type: ignore
                entry_point = metadata.get("entry_point") if metadata else None
                qualified_name = None
                if metadata:
                    qualified_name = metadata.get("qualified_name")
                if not qualified_name and metadata:
                    qualified_name = metadata.get("function_name")
                display_name = str(qualified_name) if qualified_name else ""
                if entry_point:
                    display_name = f"{display_name}@{entry_point}"
                search_results.append(
                    CodeSearchResult(
                        function_name=display_name,
                        code=doc,
                        similarity=1 - distance,
                    )
                )
        return search_results

    @handle_exceptions
    def search_strings(self, query: str, limit: int = 100) -> list[StringSearchResult]:
        """Searches for strings within a binary."""

        if not self.program_info.strings_collection:
            raise ValueError("Chromadb string collection not initialized")

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
