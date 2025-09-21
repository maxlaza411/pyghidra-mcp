import json
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext


pytestmark = pytest.mark.skipif(
    not Path("/ghidra").exists(), reason="Requires Ghidra installation"
)


async def _call_artifact_tool(session: ClientSession, tool_name: str, binary_name: str, function_name: str):
    return await session.call_tool(tool_name, {"binary_name": binary_name, "name": function_name})


@pytest.mark.asyncio
async def test_get_function_disassembly(server_params, test_binary):
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])
            results = await _call_artifact_tool(session, "get_function_disassembly", binary_name, "main")

            metadata = results.structuredContent
            assert metadata["artifact_type"] == "disassembly"
            assert metadata["function_name"] == "main"
            assert metadata["binary_name"] == binary_name
            assert metadata["mime_type"] == "text/x-asm"
            assert metadata["resource_uri"].startswith("ghidra://")

            resource = results.resources[0]
            resource_result = await session.read_resource(resource.uri)
            text_payload = resource_result.contents[0].text
            assert text_payload
            assert metadata["details"]["instruction_count"] > 0


@pytest.mark.asyncio
async def test_get_function_pcode(server_params, test_binary):
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])
            results = await _call_artifact_tool(session, "get_function_pcode", binary_name, "main")

            metadata = results.structuredContent
            assert metadata["artifact_type"] == "pcode"
            assert metadata["mime_type"] == "text/x-pcode"

            resource = results.resources[0]
            resource_result = await session.read_resource(resource.uri)
            text_payload = resource_result.contents[0].text
            assert text_payload is not None
            assert "CALL" in text_payload or len(text_payload.splitlines()) > 0


@pytest.mark.asyncio
async def test_get_function_callgraph(server_params, test_binary):
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])
            results = await _call_artifact_tool(session, "get_function_callgraph", binary_name, "main")

            metadata = results.structuredContent
            assert metadata["artifact_type"] == "callgraph"

            resource = results.resources[0]
            resource_result = await session.read_resource(resource.uri)
            graph = json.loads(resource_result.contents[0].text)
            assert "function_one" in graph.get("callees", [])
            assert "function_two" in graph.get("callees", [])


@pytest.mark.asyncio
async def test_get_function_analysis_report(server_params, test_binary):
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])
            results = await _call_artifact_tool(session, "get_function_analysis_report", binary_name, "main")

            metadata = results.structuredContent
            assert metadata["artifact_type"] == "analysis"
            assert metadata["details"]["parameter_count"] >= 0

            resource = results.resources[0]
            resource_result = await session.read_resource(resource.uri)
            text_payload = resource_result.contents[0].text
            assert "Function: main" in text_payload
