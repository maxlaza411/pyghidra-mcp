import asyncio
import json
import os
import subprocess
import time
from urllib.parse import urlparse

import aiohttp
import pytest
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import DecompiledFunction

base_url = os.getenv("MCP_BASE_URL", "http://127.0.0.1:8000")
parsed_base = urlparse(base_url)
HOST = parsed_base.hostname or "127.0.0.1"
PORT = parsed_base.port or (443 if parsed_base.scheme == "https" else 80)
ORIGIN = f"{parsed_base.scheme}://{HOST}:{PORT}"
AUTH_TOKEN = "pyghidra-test-token"
AUTH_HEADERS = {"Authorization": f"Bearer {AUTH_TOKEN}", "Origin": ORIGIN}

print(f"MCP_BASE_URL: {base_url}")


@pytest.fixture(scope="module")
def sse_server():
    binary_name = "/bin/ls"
    # Start the SSE server
    proc = subprocess.Popen(
        [
            "python",
            "-m",
            "pyghidra_mcp",
            "--transport",
            "sse",
            "--http-host",
            HOST,
            "--http-port",
            str(PORT),
            "--auth-token",
            AUTH_TOKEN,
            "--allowed-origin",
            ORIGIN,
            binary_name,
        ],
        env={**os.environ, "GHIDRA_INSTALL_DIR": "/ghidra"},
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    async def wait_for_server(timeout=240):
        async with aiohttp.ClientSession() as session:
            for _ in range(timeout):  # Poll for 60 seconds
                try:
                    async with session.get(f"{base_url}/sse", headers=AUTH_HEADERS) as response:
                        if response.status == 200:
                            return
                except aiohttp.ClientConnectorError:
                    pass
                await asyncio.sleep(1)
            raise RuntimeError("Server did not start in time")

    asyncio.run(wait_for_server())

    time.sleep(2)

    yield binary_name
    proc.terminate()
    proc.wait()


@pytest.mark.asyncio
async def test_sse_client_smoke(sse_server):
    async with sse_client(f"{base_url}/sse", headers=AUTH_HEADERS) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # Initializing session...
            await session.initialize()
            # Session initialized

            binary_name = PyGhidraContext._gen_unique_bin_name(sse_server)

            # Decompile a function
            results = await session.call_tool(
                "decompile_function",
                {"binary_name": binary_name, "name": "entry"},
            )
            # We have results!
            assert results is not None
            content = json.loads(results.content[0].text)
            assert isinstance(content, dict)
            assert len(content.keys()) == len(DecompiledFunction.model_fields.keys())
            assert "entry" in content["code"]
            print(json.dumps(content, indent=2))


@pytest.mark.asyncio
async def test_sse_health_endpoint(sse_server):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{base_url}/health") as response:
            assert response.status == 200
            payload = await response.json()

    assert payload["status"] == "ready"
    assert payload["program_count"] >= 1
    assert 0 <= payload["analyzed_programs"] <= payload["program_count"]
    assert payload["project_name"]
    assert payload["project_path"]


@pytest.mark.asyncio
async def test_sse_rejects_missing_auth(sse_server):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{base_url}/sse", headers={"Origin": ORIGIN}) as response:
            assert response.status == 401
