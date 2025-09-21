import os
import subprocess
import tempfile
import textwrap

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import (
    CodeSearchResults,
    DecompiledFunction,
    FunctionSearchResults,
)


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
def server_params(test_binary):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", test_binary],
        # Optional environment variables
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
                "decompile_function", {"binary_name": binary_name, "name": "function_to_find"}
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
            top_result_name = search_results.results[0].function_name
            assert top_result_name.startswith("function_to_find")
            assert "@" in top_result_name


@pytest.fixture(scope="module")
def overloaded_cpp_binary():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cc", delete=False) as f:
        f.write(
            textwrap.dedent(
                """
                #include <cstdio>

                class OverloadExample {
                public:
                    __attribute__((noinline)) int compute(int value);
                    __attribute__((noinline)) double compute(double value);
                };

                __attribute__((noinline)) int helper_int(int input) {
                    return input * 2;
                }

                int OverloadExample::compute(int value) {
                    return helper_int(value) + 1;
                }

                double OverloadExample::compute(double value) {
                    return value * 2.0 + 0.5;
                }

                int call_compute_int() {
                    OverloadExample example;
                    return example.compute(10);
                }

                double call_compute_double() {
                    OverloadExample example;
                    return example.compute(10.0);
                }

                int main() {
                    OverloadExample example;
                    return example.compute(1) + static_cast<int>(example.compute(2.0));
                }
                """
            )
        )
        cpp_file = f.name

    bin_file = cpp_file.replace(".cc", "")

    try:
        subprocess.check_call(["g++", "-std=c++17", "-O0", "-g", "-o", bin_file, cpp_file])
    except subprocess.CalledProcessError as exc:  # pragma: no cover - compilation failure surface
        raise RuntimeError(f"Failed to compile C++ test binary: {exc}") from exc

    yield bin_file

    os.unlink(cpp_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def overloaded_server_params(overloaded_cpp_binary):
    return StdioServerParameters(
        command="python",
        args=["-m", "pyghidra_mcp", overloaded_cpp_binary],
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


def _normalize_entry_point(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith("0x"):
        lowered = lowered[2:]
    if ":" in lowered:
        lowered = lowered.split(":")[-1]
    return lowered


@pytest.mark.asyncio
async def test_search_code_with_overloads(overloaded_server_params):
    async with stdio_client(overloaded_server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(overloaded_server_params.args[-1])

            function_response = await session.call_tool(
                "search_functions_by_name",
                {"binary_name": binary_name, "query": "compute"},
            )

            function_infos = FunctionSearchResults.model_validate_json(
                function_response.content[0].text
            )

            overload_functions = [
                func for func in function_infos.functions if "OverloadExample" in func.name
            ]
            assert len(overload_functions) >= 2

            expected_entry_points = {
                _normalize_entry_point(func.entry_point) for func in overload_functions[:2]
            }

            decompiled_results: list[DecompiledFunction] = []
            qualified_names: set[str] = set()

            for func in overload_functions[:2]:
                entry_point_identifier = func.entry_point
                decompile_response = await session.call_tool(
                    "decompile_function",
                    {"binary_name": binary_name, "name": entry_point_identifier},
                )
                decompiled = DecompiledFunction.model_validate_json(
                    decompile_response.content[0].text
                )
                decompiled_results.append(decompiled)

                qualified_name, _, address_part = decompiled.name.partition("@")
                assert qualified_name
                assert address_part
                qualified_names.add(qualified_name)

                qualified_response = await session.call_tool(
                    "decompile_function",
                    {"binary_name": binary_name, "name": qualified_name},
                )
                qualified_decompiled = DecompiledFunction.model_validate_json(
                    qualified_response.content[0].text
                )
                assert qualified_decompiled.code == decompiled.code

            assert len(qualified_names) >= 2

            query_code = decompiled_results[0].code

            search_response = await session.call_tool(
                "search_code",
                {"binary_name": binary_name, "query": query_code, "limit": 4},
            )

            search_results = CodeSearchResults.model_validate_json(search_response.content[0].text)

            overload_matches = [
                result
                for result in search_results.results
                if result.function_name.startswith("OverloadExample::compute")
            ]
            assert len(overload_matches) >= 2

            result_entry_points = {
                _normalize_entry_point(result.function_name.split("@")[-1])
                for result in overload_matches
                if "@" in result.function_name
            }

            assert expected_entry_points.issubset(result_entry_points)
