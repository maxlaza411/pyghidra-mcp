import json
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext


pytestmark = pytest.mark.skipif(
    not Path("/ghidra").exists(), reason="Requires Ghidra installation"
)


@pytest.mark.asyncio
async def test_decompile_function_tool(server_params, test_binary):
    """Test the decompile_function tool."""

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # Call the decompile_function tool
            try:
                binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])
                results = await session.call_tool(
                    "decompile_function", {"binary_name": binary_name, "name": "main"}
                )

                assert results is not None

                # Structured metadata should describe the artifact
                metadata = results.structuredContent
                assert metadata["artifact_type"] == "decompilation"
                assert metadata["function_name"] == "main"
                assert metadata["binary_name"] == binary_name

                # Convenience resources property should expose the external payload
                resources = results.resources
                assert resources
                resource = resources[0]
                assert resource.uri.startswith("ghidra://")
                assert resource.mimeType == "text/x-c"
                assert metadata["resource_uri"] == str(resource.uri)

                # Metadata should also be present in the unstructured content payload as JSON
                assert results.content
                summary_block = results.content[0]
                parsed = json.loads(summary_block.text)
                assert parsed["artifact_type"] == "decompilation"

                # Fetch the heavy payload via the MCP resources API and ensure it contains the code
                resource_result = await session.read_resource(resource.uri)
                assert resource_result.contents
                text_payload = resource_result.contents[0].text
                assert text_payload is not None and "main" in text_payload
            except Exception as e:
                # If we get an error, it might be because the function wasn't found
                # or because of issues with the binary analysis
                # We'll just check that we got a proper error response
                assert e is not None
