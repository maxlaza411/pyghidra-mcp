import json
import os
import tempfile
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client


@pytest.mark.asyncio
async def test_project_open_success(server_params):
    """Opening a new project should return a success message and clear programs."""

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            initial_response = await session.call_tool("list_project_binaries", {})
            initial_text = initial_response.content[0].text
            assert initial_text is not None
            initial_programs = json.loads(initial_text)["programs"]
            assert initial_programs, "Expected initial project to contain binaries"

            with tempfile.TemporaryDirectory() as new_root:
                new_root_path = Path(new_root)
                new_project_name = "project_open_success"

                response = await session.call_tool(
                    "project_open",
                    {
                        "project_path": str(new_root_path),
                        "project_name": new_project_name,
                    },
                )

                assert not response.isError
                assert response.content
                message = response.content[0].text
                assert message is not None
                assert new_project_name in message
                assert str(new_root_path.resolve()) in message

                updated_response = await session.call_tool("list_project_binaries", {})
                updated_text = updated_response.content[0].text
                assert updated_text is not None
                updated_programs = json.loads(updated_text)["programs"]
                assert updated_programs == []


@pytest.mark.asyncio
async def test_project_open_error(server_params_no_input):
    """Invalid project locations should surface errors via MCP."""

    async with stdio_client(server_params_no_input) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                bad_path = tmp.name

            try:
                response = await session.call_tool(
                    "project_open",
                    {
                        "project_path": bad_path,
                        "project_name": "bad_project",
                    },
                )

                assert response.isError

                structured = response.structuredContent or {}
                error_info = structured.get("error") if isinstance(structured, dict) else None
                if isinstance(error_info, dict):
                    message = error_info.get("message")
                    assert message is not None
                    assert "Error opening project" in message
                elif response.content:
                    text = response.content[0].text
                    if text is not None:
                        assert "Error opening project" in text
            finally:
                os.unlink(bad_path)
