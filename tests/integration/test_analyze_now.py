import asyncio
import json
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext

pytestmark = pytest.mark.skipif(
    not Path("/ghidra").exists(), reason="Requires Ghidra installation"
)


async def _wait_for_program(session: ClientSession, binary_name: str, attempts: int = 120):
    for _ in range(attempts):
        response = await session.call_tool("list_project_binaries", {})
        programs = json.loads(response.content[0].text)["programs"]
        for program in programs:
            if program["name"] == binary_name:
                return program
        await asyncio.sleep(1)
    raise AssertionError(f"Binary {binary_name} did not appear in project list")


@pytest.mark.asyncio
async def test_analyze_now_unlocks_queries(test_binary, server_params_no_input):
    async with stdio_client(server_params_no_input) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(test_binary)

            import_response = await session.call_tool(
                "import_binary", {"binary_path": test_binary}
            )
            assert "Importing" in import_response.content[0].text

            await _wait_for_program(session, binary_name)

            analyze_response = await session.call_tool(
                "analyze_now", {"binary_name": binary_name}
            )
            status = analyze_response.structuredContent
            assert status["binary_name"] == binary_name
            assert status["analysis_complete"] is True
            assert status["ghidra_analysis_complete"] is True
            assert status["code_collection_ready"] is True
            assert status["strings_collection_ready"] is True
            assert "ready" in status["next_steps"].lower()

            search_response = await session.call_tool(
                "search_functions_by_name", {"binary_name": binary_name, "query": "main"}
            )
            functions = json.loads(search_response.content[0].text)["functions"]
            assert functions
