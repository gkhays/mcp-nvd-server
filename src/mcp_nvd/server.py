import logging
import os
from dotenv import load_dotenv
# from typing import Any
from collections.abc import Sequence
from mcp.server import Server
import mcp.types as types
from mcp.types import TextContent, ImageContent, EmbeddedResource

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
LOGGER = logging.getLogger("mcp-nvd")

load_dotenv()

mcp = Server("mcp-nvd")

tool_handlers = {}
def add_tool_handler(name: str):
    def decorator(func):
        tool_handlers[name] = func
        return func
    return decorator

@mcp.list_tools()
async def list_tools() -> list[types.Tool]:
    LOGGER.debug("Listing tools...")
    tools = [
        types.Tool(
            name="nvd_tool", description="Fetch CVE data from NVD",
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "The CVE ID to fetch data for."
                    }
                },
                "required": ["cve_id"]
            },
        )
    ]
    return tools

@mcp.call_tool()
async def nvd_tool(name: str, arguments: dict) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """
    Fetch CVE data from NVD using the provided arguments.

    Args:
        cve_id (str): The CVE ID to fetch data for.
    """
    from mcp_nvd.nvd import NVD
    LOGGER.info(f"Fetching CVE data for {name} with arguments: {arguments}")
    cve_id = arguments.get("cve_id")

    nvd = NVD(cve_id=cve_id)
    cve_data = nvd.get_cve()

    if cve_data:
        # return cve_data
        return [TextContent(type="text", text=str(cve_data))]
    else:
        LOGGER.info(f"CVE {cve_id} not found in NVD database.")
        return None

async def main():
    LOGGER.info("Starting NVD MCP server...")
    from mcp.server.stdio import stdio_server

    try:
        async with stdio_server() as (read_stream, write_stream):
            await mcp.run(
                read_stream, 
                write_stream,
                mcp.create_initialization_options()
            )
    except Exception as e:
        LOGGER.error(f"An error occurred: {e}")
        raise e
    finally:
        LOGGER.info("Server stopped.")