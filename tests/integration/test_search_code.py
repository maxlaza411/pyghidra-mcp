import os
import subprocess
import tempfile
import textwrap
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import CodeSearchResults, DecompiledFunction


CPP_OVERLOAD_TARGETS = [
    "demo::Overloaded::greet(int)",
    "demo::Overloaded::greet(double)",
]


@pytest.fixture(scope="module")
def test_binary():
    """Create a simple test binary for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

void function_to_find() {
    printf("This is a function to be found by search_code.");
}

int main() {
    printf("Hello, World!");
    function_to_find();
    return 0;
}
"""
        )
        c_file = f.name

    bin_file = c_file.replace(".c", "")

    os.system(f"gcc -o {bin_file} {c_file}")

    yield bin_file

    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def cpp_test_binary():
    """Create a C++ test binary with overloaded methods."""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".cpp", delete=False) as f:
        f.write(
            textwrap.dedent(
                """
                #include <cstdio>

                namespace demo {

                class Overloaded {
                public:
                    static void greet(int value) {
                        std::printf("demo::Overloaded::greet(int) invoked %d\\n", value);
                    }

                    static void greet(double value) {
                        std::printf("demo::Overloaded::greet(double) invoked %f\\n", value);
                    }
                };

                }  // namespace demo

                int main() {
                    demo::Overloaded::greet(42);
                    demo::Overloaded::greet(3.14);
                    return 0;
                }
                """
            )
        )
        cpp_file = f.name

    bin_file = cpp_file.replace(".cpp", "")

    try:
        subprocess.run(
            [
                "g++",
                "-std=c++17",
                "-g",
                "-O0",
                "-fno-inline",
                "-o",
                bin_file,
                cpp_file,
            ],
            check=True,
        )
    except FileNotFoundError:
        os.unlink(cpp_file)
        pytest.skip("g++ compiler not available")

    try:
        yield bin_file
    finally:
        for path in (cpp_file, bin_file):
            if os.path.exists(path):
                os.unlink(path)


@pytest.fixture(scope="module")
def cpp_overload_addresses(cpp_test_binary):
    """Extract entry point addresses for overloaded functions from nm output."""

    try:
        output = subprocess.check_output(["nm", "-C", cpp_test_binary], text=True)
    except FileNotFoundError:
        pytest.skip("nm tool not available")
    addresses: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        addr, _symbol_type, *name_parts = parts
        name = " ".join(name_parts)
        if name in CPP_OVERLOAD_TARGETS:
            try:
                addresses[name] = f"0x{int(addr, 16):x}"
            except ValueError:
                continue

    if len(addresses) != len(CPP_OVERLOAD_TARGETS):
        missing = sorted(set(CPP_OVERLOAD_TARGETS) - set(addresses))
        pytest.fail(f"Failed to resolve overload addresses: {missing}")

    return addresses


@pytest.fixture(scope="module")
def server_params(test_binary):
    """Get server parameters with a test binary."""

    ghidra_dir = Path("/ghidra")
    if not ghidra_dir.exists():
        pytest.skip("Ghidra installation not available")
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--no-threaded", test_binary],  # no-thread for search_code
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def cpp_server_params(cpp_test_binary):
    """Get server parameters for the C++ test binary."""

    ghidra_dir = Path("/ghidra")
    if not ghidra_dir.exists():
        pytest.skip("Ghidra installation not available")
    return StdioServerParameters(
        command="python",
        args=["-m", "pyghidra_mcp", cpp_test_binary],
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.mark.asyncio
async def test_search_code(server_params):
    """
    Tests searching for code using similarity search.
    """
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # 1. Decompile a function to get its code to use as a query
            decompile_response = await session.call_tool(
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": "function_to_find"},
            )

            decompiled_function = DecompiledFunction.model_validate_json(
                decompile_response.content[0].text
            )
            query_code = decompiled_function.code

            # 2. Use the decompiled code to search for the function
            search_response = await session.call_tool(
                "search_code", {"binary_name": binary_name, "query": query_code, "limit": 1}
            )

            search_results = CodeSearchResults.model_validate_json(search_response.content[0].text)

            # 3. Assert the results
            assert len(search_results.results) > 0
            # The top result should be the function we searched for
            assert "function_to_find" in search_results.results[0].function_name
            # Verify new fields are populated
            assert search_results.query == query_code
            assert search_results.search_mode.value == "semantic"  # Default mode
            assert search_results.returned_count > 0
            assert search_results.literal_total >= 0  # Dual-mode count
            assert search_results.semantic_total > 0
            assert search_results.total_functions > 0
            # semantic_total should be <= total_functions
            assert search_results.semantic_total <= search_results.total_functions


@pytest.mark.asyncio
async def test_search_code_literal(server_params):
    """
    Tests searching for code using literal (exact string) search mode.
    """
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Search for a literal string that should be in the decompiled code
            # "printf" should appear in the decompiled output
            literal_query = "printf"

            # Use literal search mode
            search_response = await session.call_tool(
                "search_code",
                {
                    "binary_name": binary_name,
                    "query": literal_query,
                    "limit": 5,
                    "search_mode": "literal",
                },
            )

            search_results = CodeSearchResults.model_validate_json(search_response.content[0].text)

            # Assert the results
            assert search_results.search_mode.value == "literal"
            assert search_results.literal_total > 0  # Should find functions containing "printf"

            # Each result should contain the literal query string
            for result in search_results.results:
                assert literal_query in result.code
                assert result.search_mode.value == "literal"
                assert result.similarity == 1.0  # Literal matches have similarity 1.0


@pytest.mark.asyncio
async def test_search_code_handles_overloads(
    cpp_server_params, cpp_overload_addresses
):
    """Ensure overloaded C++ methods can be decompiled and searched."""

    async with stdio_client(cpp_server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(cpp_server_params.args[-1])

            for overload_name, address in cpp_overload_addresses.items():
                response_fqn = await session.call_tool(
                    "decompile_function",
                    {"binary_name": binary_name, "name_or_address": overload_name},
                )
                decompiled_from_name = DecompiledFunction.model_validate_json(
                    response_fqn.content[0].text
                )

                response_addr = await session.call_tool(
                    "decompile_function",
                    {"binary_name": binary_name, "name_or_address": address},
                )
                decompiled_from_address = DecompiledFunction.model_validate_json(
                    response_addr.content[0].text
                )

                assert decompiled_from_name.code == decompiled_from_address.code
                if "(int)" in overload_name:
                    assert "demo::Overloaded::greet(int) invoked" in decompiled_from_name.code
                else:
                    assert "demo::Overloaded::greet(double) invoked" in decompiled_from_name.code

            search_response = await session.call_tool(
                "search_code",
                {
                    "binary_name": binary_name,
                    "query": "demo::Overloaded::greet(",
                    "limit": 5,
                },
            )

            search_results = CodeSearchResults.model_validate_json(
                search_response.content[0].text
            )

            assert len(search_results.results) >= len(CPP_OVERLOAD_TARGETS)
            result_names = {result.function_name for result in search_results.results}
            for target in CPP_OVERLOAD_TARGETS:
                assert any(target in name for name in result_names)
