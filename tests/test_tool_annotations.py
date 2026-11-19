"""Tests for MCP tool annotations."""

import asyncio

from netbox_mcp_server.server import mcp

# Fork addition: whitelisted write tools. Every other tool stays read-only.
WRITE_TOOLS = {
    "netbox_create_inventory_item",
    "netbox_create_journal_entry",
    "netbox_create_object",
    "netbox_update_object",
    "netbox_upload_image_attachment",
}


def test_all_tools_declare_read_only_hint():
    """Each tool must declare readOnlyHint; only the whitelisted write tools may be False."""
    tools = asyncio.run(mcp.list_tools())

    assert tools
    for tool in tools:
        assert tool.annotations is not None, tool.name
        expected = tool.name not in WRITE_TOOLS
        assert tool.annotations.readOnlyHint is expected, tool.name


def test_write_tools_are_registered_and_flag_destructive_updates():
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}

    assert tools.keys() >= WRITE_TOOLS
    for name in WRITE_TOOLS:
        assert tools[name].annotations.destructiveHint is (name == "netbox_update_object"), name
