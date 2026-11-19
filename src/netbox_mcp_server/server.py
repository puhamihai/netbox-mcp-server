import argparse
import asyncio
import hashlib
import hmac
import logging
import os
import sys
from typing import Annotated, Any
from urllib.parse import urlsplit

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from pydantic import Field, SecretStr
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from netbox_mcp_server.config import Settings, configure_logging
from netbox_mcp_server.netbox_client import NetBoxRestClient
from netbox_mcp_server.netbox_types import NETBOX_OBJECT_TYPES


def parse_cli_args() -> dict[str, Any]:
    """
    Parse command-line arguments for configuration overrides.

    Returns:
        dict of configuration overrides (only includes explicitly set values)
    """
    parser = argparse.ArgumentParser(
        description="NetBox MCP Server - Model Context Protocol server for NetBox",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Core NetBox settings
    parser.add_argument(
        "--netbox-url",
        type=str,
        help="Base URL of the NetBox instance (e.g., https://netbox.example.com/)",
    )
    parser.add_argument(
        "--netbox-token",
        type=str,
        help="API token for NetBox authentication",
    )

    # Transport settings
    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "http"],
        help="MCP transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        type=str,
        help="Host address for HTTP server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Port for HTTP server (default: 8000)",
    )
    parser.add_argument(
        "--cors-origins",
        action="append",
        help="CORS origins (repeat flag). Use * to allow any origin (default: none)",
    )
    parser.add_argument(
        "--mcp-auth-token",
        type=str,
        help=(
            "Bearer token required on the HTTP transport endpoint "
            "(prefer the MCP_AUTH_TOKEN env var; default: none)"
        ),
    )

    # Security settings
    ssl_group = parser.add_mutually_exclusive_group()
    ssl_group.add_argument(
        "--verify-ssl",
        action="store_true",
        dest="verify_ssl",
        default=None,
        help="Verify SSL certificates (default)",
    )
    ssl_group.add_argument(
        "--no-verify-ssl",
        action="store_false",
        dest="verify_ssl",
        help="Disable SSL certificate verification (not recommended)",
    )

    # Plugin discovery settings
    parser.add_argument(
        "--enable-plugin-discovery",
        action="store_true",
        default=None,
        dest="enable_plugin_discovery",
        help="Auto-discover plugin object types from NetBox at startup",
    )

    # Observability settings
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity level (default: INFO)",
    )

    args: argparse.Namespace = parser.parse_args()

    overlay: dict[str, Any] = {}
    if args.netbox_url is not None:
        overlay["netbox_url"] = args.netbox_url
    if args.netbox_token is not None:
        overlay["netbox_token"] = args.netbox_token
    if args.transport is not None:
        overlay["transport"] = args.transport
    if args.host is not None:
        overlay["host"] = args.host
    if args.port is not None:
        overlay["port"] = args.port
    if args.cors_origins is not None:
        overlay["cors_origins"] = args.cors_origins
    if args.mcp_auth_token is not None:
        overlay["mcp_auth_token"] = args.mcp_auth_token
    if args.verify_ssl is not None:
        overlay["verify_ssl"] = args.verify_ssl
    if args.enable_plugin_discovery is not None:
        overlay["enable_plugin_discovery"] = args.enable_plugin_discovery
    if args.log_level is not None:
        overlay["log_level"] = args.log_level

    return overlay


class BearerTokenVerifier(TokenVerifier):
    """Constant-time single-secret bearer check for the HTTP transport.

    This is a FastMCP Resource Server verifier: it only validates an incoming
    'Authorization: Bearer <token>' against one configured secret and issues no
    tokens itself. FastMCP mounts its own auth middleware around this, returning
    401 (+ WWW-Authenticate) for unauthenticated requests to the MCP endpoint.
    """

    def __init__(self, secret: str) -> None:
        super().__init__()
        # Digest, not raw secret: lets verify_token compare in constant time.
        self._secret_digest = hashlib.sha256(secret.encode("utf-8")).digest()

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an AccessToken for a matching bearer, or None to reject."""
        if not token:
            return None
        # Hash both sides: compare_digest raises TypeError on a non-ASCII str, and
        # the bearer is attacker-controlled (header bytes decode as latin-1).
        token_digest = hashlib.sha256(token.encode("utf-8", "surrogatepass")).digest()
        if not hmac.compare_digest(token_digest, self._secret_digest):
            return None
        return AccessToken(token=token, client_id="netbox-mcp-server", scopes=[])


def build_http_auth(token: SecretStr | None) -> TokenVerifier | None:
    """
    Build the HTTP transport auth provider from an optional bearer token.

    Returns a verifier that makes FastMCP reject unauthenticated requests to the
    MCP endpoint with 401, or None when no token is configured. Empty or
    whitespace-only values are normalized to None upstream in Settings, so a
    non-None token here is always a real secret.

    Args:
        token: Optional bearer token to require on the HTTP transport endpoint

    Returns:
        A TokenVerifier requiring the token, or None when no token is set
    """
    if token is None:
        return None
    return BearerTokenVerifier(token.get_secret_value())


# Default object types for global search
DEFAULT_SEARCH_TYPES = [
    "dcim.device",  # Most common search target
    "dcim.site",  # Site names frequently searched
    "ipam.ipaddress",  # IP searches very common
    "dcim.interface",  # Interface names/descriptions
    "dcim.rack",  # Rack identifiers
    "ipam.vlan",  # VLAN names/IDs
    "circuits.circuit",  # Circuit identifiers
    "virtualization.virtualmachine",  # VM names
]

mcp = FastMCP("NetBox")
netbox = None


def validate_filters(filters: dict) -> None:
    """
    Validate that filters don't use unsupported lookup suffixes or multi-hop
    relationship traversal.

    NetBox API does not support:
    - __in suffix (pass a list as the field value instead: {'id': [1, 2, 3]})
    - nested relationship queries like device__site_id or interface__device__site

    Valid patterns:
    - Direct field filters: site_id, name, status
    - List values for multi-value filters: {'site_id': [1, 2]}
    - Lookup expressions supported by the target NetBox field: name__ic, id__gt

    Args:
        filters: Dictionary of filter parameters

    Raises:
        ValueError: If filter uses an unsupported lookup suffix or multi-hop
                    relationship traversal
    """
    valid_suffixes = {
        "n",
        "ic",
        "nic",
        "isw",
        "nisw",
        "iew",
        "niew",
        "ie",
        "nie",
        "empty",
        "regex",
        "iregex",
        "lt",
        "lte",
        "gt",
        "gte",
    }

    for filter_name in filters:
        # Skip special parameters
        if filter_name in ("limit", "offset", "fields", "q"):
            continue

        if "__" not in filter_name:
            continue

        parts = filter_name.split("__")

        if len(parts) == 2 and parts[-1] == "in":
            base = parts[0]
            raise ValueError(
                f"Invalid filter '{filter_name}': '__in' lookup suffix is not "
                "supported and may be silently ignored by NetBox. "
                f"Pass a list to the field directly instead: {{'{base}': [1, 2, 3]}}"
            )

        # Allow field__suffix pattern (e.g., name__ic, id__gt)
        if len(parts) == 2 and parts[-1] in valid_suffixes:
            continue
        # Block multi-hop patterns and invalid suffixes
        if len(parts) >= 2:
            raise ValueError(
                f"Invalid filter '{filter_name}': Multi-hop relationship "
                f"traversal or invalid lookup suffix not supported. Use direct field filters like "
                f"'site_id' or two-step queries."
            )


@mcp.tool(
    annotations={"readOnlyHint": True},
    description="""
    Get objects from NetBox based on their type and filters

    Args:
        object_type: String representing the NetBox object type (e.g. "dcim.device", "ipam.ipaddress")
        filters: dict of filters to apply to the API call based on the NetBox API filtering options

                FILTER RULES:
                Valid: Direct fields like {'site_id': 1, 'name': 'router', 'status': 'active'}
                Valid: Field-supported lookups like {'name__ic': 'switch', 'vid__gte': 100}
                Invalid: Multi-hop like {'device__site_id': 1} - NOT supported

                Lookup suffixes: n, ic, nic, isw, nisw, iew, niew, ie, nie,
                                 empty, regex, iregex, lt, lte, gt, gte
                Lookup support is field-specific. NetBox may silently ignore unsupported
                lookups and return overly broad results. The '__in' suffix is not supported
                and is rejected by this tool. For multiple values, pass a list as the field
                value directly: {'vminterface_id': [621493, 631527]} or {'id': [1, 2, 3]}.

                Two-step pattern for cross-relationship queries:
                  sites = netbox_get_objects('dcim.site', {'name': 'NYC'})
                  netbox_get_objects('dcim.device', {'site_id': sites['results'][0]['id']})

        fields: Optional list of specific fields to return
                **IMPORTANT: ALWAYS USE THIS PARAMETER TO MINIMIZE TOKEN USAGE**
                Field filtering significantly reduces response payload and is critical for performance.

                - None or [] = returns all fields (NOT RECOMMENDED - use only when you need complete objects)
                - ['id', 'name'] = returns only specified fields (RECOMMENDED)

                Examples:
                - For counting: ['id'] (minimal payload)
                - For listings: ['id', 'name', 'status']
                - For IP addresses: ['address', 'dns_name', 'description']

                Uses NetBox's native field filtering via ?fields= parameter.
                **Always specify only the fields you actually need.**

        brief: returns only a minimal representation of each object in the response.
               This is useful when you need only a list of available objects without any related data.

        limit: Maximum results to return (default 5, max 100)
               Start with default, increase only if needed

        offset: Skip this many results for pagination (default 0)
                Example: offset=0 (page 1), offset=5 (page 2), offset=10 (page 3)

        ordering: Fields used to determine sort order of results.
                  Field names may be prefixed with '-' to invert the sort order.
                  Multiple fields may be specified with a list of strings.

                  Examples:
                  - 'name' (alphabetical by name)
                  - '-id' (ordered by ID descending)
                  - ['facility', '-name'] (by facility, then by name descending)
                  - None, '' or [] (default NetBox ordering)


    Returns:
        Paginated response dict with the following structure:
            - count: Total number of objects matching the query
                     ALWAYS REFER TO THIS FIELD FOR THE TOTAL NUMBER OF OBJECTS MATCHING THE QUERY
            - next: URL to next page (or null if no more pages)
                    ALWAYS REFER TO THIS FIELD FOR THE NEXT PAGE OF RESULTS
            - previous: URL to previous page (or null if on first page)
                        ALWAYS REFER TO THIS FIELD FOR THE PREVIOUS PAGE OF RESULTS
            - results: Array of objects for this page
                       ALWAYS REFER TO THIS FIELD FOR THE OBJECTS ON THIS PAGE

    ENSURE YOU ARE AWARE THE RESULTS ARE PAGINATED BEFORE PROVIDING RESPONSE TO THE USER.

    Valid object_type values:

    """
    + "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
    + """

    See NetBox API documentation for filtering options for each object type.
    """,
)
def netbox_get_objects(
    object_type: str,
    filters: dict,
    fields: list[str] | None = None,
    brief: bool = False,
    limit: Annotated[int, Field(default=5, ge=1, le=100)] = 5,
    offset: Annotated[int, Field(default=0, ge=0)] = 0,
    ordering: str | list[str] | None = None,
):
    """
    Get objects from NetBox based on their type and filters
    """
    # Validate object_type exists in mapping
    if object_type not in NETBOX_OBJECT_TYPES:
        valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
        raise ValueError(f"Invalid object_type. Must be one of:\n{valid_types}")

    # Validate filter patterns
    validate_filters(filters)

    # Get API endpoint and fallback from mapping
    endpoint, fallback = _get_endpoint_info(object_type)

    # Build params with pagination (parameters override filters dict)
    params = filters.copy()
    params["limit"] = limit
    params["offset"] = offset

    if fields:
        params["fields"] = ",".join(fields)

    if brief:
        params["brief"] = "1"

    if ordering:
        if isinstance(ordering, list):
            ordering = ",".join(ordering)
        if ordering.strip() != "":
            params["ordering"] = ordering

    # Make API call
    return netbox.get(endpoint, params=params, fallback_endpoint=fallback)


@mcp.tool(annotations={"readOnlyHint": True})
def netbox_get_object_by_id(
    object_type: str,
    object_id: int,
    fields: list[str] | None = None,
    brief: bool = False,
):
    """
    Get detailed information about a specific NetBox object by its ID.

    Args:
        object_type: String representing the NetBox object type (e.g. "dcim.device", "ipam.ipaddress")
        object_id: The numeric ID of the object
        fields: Optional list of specific fields to return
                **IMPORTANT: ALWAYS USE THIS PARAMETER TO MINIMIZE TOKEN USAGE**
                Field filtering reduces response payload by 80-90% and is critical for performance.

                - None or [] = returns all fields (NOT RECOMMENDED - use only when you need complete objects)
                - ['id', 'name'] = returns only specified fields (RECOMMENDED)

                Examples:
                - For basic info: ['id', 'name', 'status']
                - For devices: ['id', 'name', 'status', 'site']
                - For IP addresses: ['address', 'dns_name', 'vrf', 'status']

                Uses NetBox's native field filtering via ?fields= parameter.
                **Always specify only the fields you actually need.**
        brief: returns only a minimal representation of the object in the response.
               This is useful when you need only a summary of the object without any related data.

    Returns:
        Object dict (complete or with only requested fields based on fields parameter)
    """
    # Validate object_type exists in mapping
    if object_type not in NETBOX_OBJECT_TYPES:
        valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
        raise ValueError(f"Invalid object_type. Must be one of:\n{valid_types}")

    # Get API endpoint and fallback from mapping
    endpoint, fallback = _get_endpoint_info(object_type)
    full_endpoint = f"{endpoint}/{object_id}"
    full_fallback = f"{fallback}/{object_id}" if fallback else None

    params = {}
    if fields:
        params["fields"] = ",".join(fields)

    if brief:
        params["brief"] = "1"

    return netbox.get(full_endpoint, params=params, fallback_endpoint=full_fallback)


@mcp.tool(annotations={"readOnlyHint": True})
def netbox_get_changelogs(filters: dict):
    """
    Get object change records (changelogs) from NetBox based on filters.

    Args:
        filters: dict of filters to apply to the API call based on the NetBox API filtering options

    Returns:
        Paginated response dict with the following structure:
            - count: Total number of changelog entries matching the query
                     ALWAYS REFER TO THIS FIELD FOR THE TOTAL NUMBER OF CHANGELOG ENTRIES MATCHING THE QUERY
            - next: URL to next page (or null if no more pages)
                    ALWAYS REFER TO THIS FIELD FOR THE NEXT PAGE OF RESULTS
            - previous: URL to previous page (or null if on first page)
                        ALWAYS REFER TO THIS FIELD FOR THE PREVIOUS PAGE OF RESULTS
            - results: Array of changelog entries for this page
                       ALWAYS REFER TO THIS FIELD FOR THE CHANGELOG ENTRIES ON THIS PAGE

    Filtering options include:
    - user_id: Filter by user ID who made the change
    - user: Filter by username who made the change
    - changed_object_type_id: Filter by numeric ContentType ID (e.g., 21 for dcim.device)
                              Note: This expects a numeric ID, not an object type string
    - changed_object_id: Filter by ID of the changed object
    - object_repr: Filter by object representation (usually contains object name)
    - action: Filter by action type (created, updated, deleted)
    - time_before: Filter for changes made before a given time (ISO 8601 format)
    - time_after: Filter for changes made after a given time (ISO 8601 format)
    - q: Search term to filter by object representation

    Examples:
    To find all changes made to a specific object by ID:
    {"changed_object_id": 123}

    To find changes by object name pattern:
    {"object_repr": "router-01"}

    To find all deletions in the last 24 hours:
    {"action": "delete", "time_after": "2023-01-01T00:00:00Z"}

    Each changelog entry contains:
    - id: The unique identifier of the changelog entry
    - user: The user who made the change
    - user_name: The username of the user who made the change
    - request_id: The unique identifier of the request that made the change
    - action: The type of action performed (created, updated, deleted)
    - changed_object_type: The type of object that was changed
    - changed_object_id: The ID of the object that was changed
    - object_repr: String representation of the changed object
    - object_data: The object's data after the change (null for deletions)
    - object_data_v2: Enhanced data representation
    - prechange_data: The object's data before the change (null for creations)
    - postchange_data: The object's data after the change (null for deletions)
    - time: The timestamp when the change was made
    """
    validate_filters(filters)
    endpoint = "core/object-changes"

    # Make API call
    return netbox.get(endpoint, params=filters)


@mcp.tool(
    annotations={"readOnlyHint": True},
    description="""
    Perform global search across NetBox infrastructure.

    Searches names, descriptions, IP addresses, serial numbers, asset tags,
    and other key fields across multiple object types.

    Args:
        query: Search term (device names, IPs, serial numbers, hostnames, site names)
               Examples: 'switch01', '192.168.1.1', 'NYC-DC1', 'SN123456'
        object_types: Limit search to specific types (optional)
                     Default: ["""
    + "', '".join(DEFAULT_SEARCH_TYPES)
    + """]
                     Examples: ['dcim.device', 'ipam.ipaddress', 'dcim.site']
        fields: Optional list of specific fields to return (reduces response size) IT IS STRONGLY RECOMMENDED TO USE THIS PARAMETER TO MINIMIZE TOKEN USAGE.
                - None or [] = returns all fields (no filtering)
                - ['id', 'name'] = returns only specified fields
                Examples: ['id', 'name', 'status'], ['address', 'dns_name']
                Uses NetBox's native field filtering via ?fields= parameter
        limit: Max results per object type (default 5, max 100)

    Returns:
        Dictionary with object_type keys and list of matching objects.
        All searched types present in result (empty list if no matches).

    Example:
        # Search for anything matching "switch"
        results = netbox_search_objects('switch')
        # Returns: {
        #   'dcim.device': [{'id': 1, 'name': 'switch-01', ...}],
        #   'dcim.site': [],
        #   ...
        # }

        # Search for IP address
        results = netbox_search_objects('192.168.1.100')
        # Returns: {
        #   'ipam.ipaddress': [{'id': 42, 'address': '192.168.1.100/24', ...}],
        #   ...
        # }

        # Limit search to specific types with field projection
        results = netbox_search_objects(
            'NYC',
            object_types=['dcim.site', 'dcim.location'],
            fields=['id', 'name', 'status']
        )
    """,
)
def netbox_search_objects(
    query: str,
    object_types: list[str] | None = None,
    fields: list[str] | None = None,
    limit: Annotated[int, Field(default=5, ge=1, le=100)] = 5,
) -> dict[str, list[dict]]:
    """
    Perform global search across NetBox infrastructure.
    """
    search_types = object_types if object_types is not None else DEFAULT_SEARCH_TYPES

    # Validate all object types exist in mapping
    for obj_type in search_types:
        if obj_type not in NETBOX_OBJECT_TYPES:
            valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
            raise ValueError(f"Invalid object_type '{obj_type}'. Must be one of:\n{valid_types}")

    results = {obj_type: [] for obj_type in search_types}

    # Build results dictionary (error-resilient)
    for obj_type in search_types:
        try:
            endpoint, fallback = _get_endpoint_info(obj_type)
            response = netbox.get(
                endpoint,
                params={
                    "q": query,
                    "limit": limit,
                    "fields": ",".join(fields) if fields else None,
                },
                fallback_endpoint=fallback,
            )
            # Extract results array from paginated response
            results[obj_type] = response.get("results", [])
        except Exception:  # noqa: S112 - intentional error-resilient search
            # Continue searching other types if one fails
            # results[obj_type] already has empty list
            continue

    return results


# ---------------------------------------------------------------------------
# WHITELISTED WRITE TOOLS (fork addition) — physical asset and part-history tracking.
#
# Upstream is read-only by design and points users at forking (Apache 2.0) for
# anything more. This fork adds a narrow set of create/update tools for one
# workflow: documenting physical servers and recording which part was fitted to
# which server, and when. There is deliberately NO delete and NO bulk tool: the
# workflow never needs them, and their absence is a safety property on a
# production DCIM that an LLM can drive.
#
# Writes require a NetBox API token with write permission on the whitelisted
# object types. Scope the token to exactly those permissions.
# ---------------------------------------------------------------------------

# Only these object types may be written. Anything else is refused, so a
# mistaken object_type cannot touch prefixes, circuits, sites, etc.
WRITE_ALLOWED_CREATE = {
    "dcim.inventoryitem",
    "extras.journalentry",
    # Part vendors attribute a DIMM/disk to its real maker (Samsung, Hynix, Micron,
    # Seagate…) rather than to the server's vendor. Name + slug only.
    "dcim.manufacturer",
    # Physical servers missing from NetBox must be creatable, otherwise their part
    # history has nothing to hang off. Decide presence on the hardware serial / service
    # tag, not the hostname: inventories often hold devices named by serial or by IP,
    # and name-only matching creates duplicates.
    "dcim.device",
    # Document physical servers fully: interfaces + MACs, OOB/primary IPs, cables to
    # the switches (e.g. from BMC LLDP data) and the racks they sit in. Create only.
    # Check for an existing IP/interface/cable before creating, so nothing is duplicated.
    "dcim.interface",
    "dcim.macaddress",
    "ipam.ipaddress",
    "dcim.cable",
    "dcim.rack",
    # Tags mark lifecycle state, e.g. a decommission cooling period or a released spare.
    "extras.tag",
    # Blade chassis need their bays so sleds can be installed in them (parent_device),
    # and site photos (service tag, front, rear, modules) belong on the device.
    # Image attachments are only created through netbox_upload_image_attachment.
    "dcim.devicebay",
    "extras.imageattachment",
}
WRITE_ALLOWED_UPDATE = {
    "dcim.inventoryitem",
    "extras.journalentry",
    "dcim.device",
    # Set an interface's primary MAC, and correct an IP's assignment.
    "dcim.interface",
    "ipam.ipaddress",
    # Install / move a sled in a chassis bay (installed_device).
    "dcim.devicebay",
}

# Image attachments: what they may hang off, and which files may be sent. The upload
# reads a local file, so it is limited to real images (extension AND magic bytes) to
# keep it from becoming a way to ship arbitrary local files into NetBox.
IMAGE_ATTACH_OBJECT_TYPES = {"dcim.device", "dcim.rack", "dcim.location", "dcim.site"}
IMAGE_MAX_BYTES = 25 * 1024 * 1024
IMAGE_NAME_MAX = 50
IMAGE_TYPES = {
    ".png": ("image/png", (b"\x89PNG\r\n\x1a\n",)),
    ".jpg": ("image/jpeg", (b"\xff\xd8\xff",)),
    ".jpeg": ("image/jpeg", (b"\xff\xd8\xff",)),
    ".gif": ("image/gif", (b"GIF87a", b"GIF89a")),
    ".webp": ("image/webp", (b"RIFF",)),
}


def _assert_writable(object_type: str, allowed: set[str], verb: str) -> None:
    if object_type not in NETBOX_OBJECT_TYPES:
        raise ValueError(f"Unknown object_type '{object_type}'.")
    if object_type not in allowed:
        raise ValueError(
            f"Refusing to {verb} '{object_type}'. This server only permits {verb} on: "
            f"{', '.join(sorted(allowed))}. Widen WRITE_ALLOWED_* in server.py only with "
            f"a deliberate decision — this whitelist is the guardrail."
        )


def _resolve_device(device: int | str) -> int:
    """Accept a device id or an exact device name and return the id."""
    if isinstance(device, int):
        return device
    if str(device).isdigit():
        return int(device)
    found = netbox.get("dcim/devices", params={"name": device, "fields": "id,name"})
    results = found.get("results", []) if isinstance(found, dict) else found
    if not results:
        raise ValueError(f"No device named '{device}' in NetBox.")
    if len(results) > 1:
        raise ValueError(f"'{device}' matched {len(results)} devices — pass the numeric id.")
    return results[0]["id"]


@mcp.tool
def netbox_create_inventory_item(
    device: int | str,
    name: str,
    part_id: str | None = None,
    serial: str | None = None,
    manufacturer: int | None = None,
    description: str | None = None,
    label: str | None = None,
):
    """
    Record a physical part fitted to a device (NetBox inventory item).

    Use this after a part is REPLACED, or to register a known-suspect part, so the
    history lives with the asset instead of in a ticket that gets closed. Do not
    bulk-load every DIMM in the fleet — a curated record means "this was replaced or
    is suspect"; a stale exhaustive inventory is worse than none.

    Args:
        device: device id, or its exact name (e.g. "server01")
        name: the slot exactly as the HARDWARE names it — "DIMM_A1",
              "Disk.Bay.5:Enclosure.Internal.0-1". Matching the SEL / racadm / Redfish
              naming is what lets these records join up later.
        part_id: vendor part number, e.g. "M393A4K40BB0-CPB"
        serial: the serial of THIS unit
        manufacturer: NetBox manufacturer id (optional)
        description: free text — put the date, the ticket key and the serial it replaced,
                     e.g. "fitted 2026-01-15, CHG-1234, replaced S/N ABC12345"
        label: optional physical label

    Returns:
        The created inventory item dict (includes its new id).
    """
    _assert_writable("dcim.inventoryitem", WRITE_ALLOWED_CREATE, "create")
    data: dict[str, Any] = {"device": _resolve_device(device), "name": name}
    for key, value in (
        ("part_id", part_id),
        ("serial", serial),
        ("manufacturer", manufacturer),
        ("description", description),
        ("label", label),
    ):
        if value is not None:
            data[key] = value
    endpoint, _ = _get_endpoint_info("dcim.inventoryitem")
    return netbox.create(endpoint, data)


@mcp.tool
def netbox_create_journal_entry(
    object_type: str,
    object_id: int | str,
    comments: str,
    kind: str = "info",
):
    """
    Add a dated journal entry to a NetBox object — the narrative of what happened.

    Pair this with netbox_create_inventory_item: the inventory item is the part that is
    fitted NOW, the journal entry is the event ("swapped DIMM_A1, CHG-1234, old S/N
    ABC12345 -> new S/N XYZ67890, fitted by data-center remote hands").

    Args:
        object_type: the object being journalled, e.g. "dcim.device"
        object_id: its id, or (for dcim.device) its exact name
        comments: the entry text. Include the ticket key and old -> new serials.
        kind: one of "info", "success", "warning", "danger"

    Returns:
        The created journal entry dict.
    """
    _assert_writable("extras.journalentry", WRITE_ALLOWED_CREATE, "create")
    if kind not in {"info", "success", "warning", "danger"}:
        raise ValueError('kind must be one of "info", "success", "warning", "danger".')
    if object_type == "dcim.device":
        object_id = _resolve_device(object_id)
    elif not str(object_id).isdigit():
        raise ValueError(f"object_id must be numeric for {object_type}.")
    data = {
        "assigned_object_type": object_type,
        "assigned_object_id": int(object_id),
        "kind": kind,
        "comments": comments,
    }
    endpoint, _ = _get_endpoint_info("extras.journalentry")
    return netbox.create(endpoint, data)


@mcp.tool
def netbox_create_object(object_type: str, data: dict):
    """
    Create a NetBox object of a whitelisted type. For the two common part-history objects
    prefer the purpose-built tools (netbox_create_inventory_item /
    netbox_create_journal_entry) — they document the expected fields. Use this for the
    supporting records those need, e.g. a part manufacturer.

    Args:
        object_type: must be in the create whitelist (see WRITE_ALLOWED_CREATE)
        data: the object's fields, e.g. {"name": "Samsung"}

    Returns:
        The created object dict (includes its new id).
    """
    _assert_writable(object_type, WRITE_ALLOWED_CREATE, "create")
    if not isinstance(data, dict) or not data:
        raise ValueError("data must be a non-empty dict of fields.")
    # NetBox requires a slug on manufacturers; derive it so callers don't have to.
    if object_type == "dcim.manufacturer" and "slug" not in data and data.get("name"):
        slug = "".join(c.lower() if c.isalnum() else "-" for c in str(data["name"]))
        data = {**data, "slug": "-".join(p for p in slug.split("-") if p)}
    endpoint, _ = _get_endpoint_info(object_type)
    return netbox.create(endpoint, data)


@mcp.tool
def netbox_update_object(object_type: str, object_id: int, data: dict):
    """
    PATCH specific fields of an existing NetBox object. Whitelisted object types only.

    Intended for small corrections in the part-history workflow — fixing a serial,
    editing a description, adding or clearing a tag such as "part-on-order".
    Only the keys you pass are changed. There is deliberately NO delete tool.

    Args:
        object_type: must be in the update whitelist (see WRITE_ALLOWED_UPDATE), e.g.
                     dcim.device, dcim.inventoryitem, dcim.devicebay
        object_id: numeric id of the object
        data: dict of fields to change, e.g. {"serial": "XYZ67890"},
              {"tags": [{"slug": "part-on-order"}]} or, on a device bay,
              {"installed_device": 123}

    Returns:
        The updated object dict.
    """
    _assert_writable(object_type, WRITE_ALLOWED_UPDATE, "update")
    if not isinstance(data, dict) or not data:
        raise ValueError("data must be a non-empty dict of fields to change.")
    endpoint, _ = _get_endpoint_info(object_type)
    return netbox.update(endpoint, int(object_id), data)


@mcp.tool
def netbox_upload_image_attachment(
    object_type: str,
    object_id: int | str,
    file_path: str,
    name: str | None = None,
    description: str | None = None,
):
    """
    Attach a local photo to a NetBox object (image attachment).

    Use it for site-visit evidence that should live with the asset: the service-tag
    pull-out tag, front and rear of a chassis, a module that was pulled. Check the
    object's existing attachments first (netbox_get_objects 'extras.imageattachment'
    with object_type/object_id filters) so the same photo is not uploaded twice.

    Args:
        object_type: one of dcim.device, dcim.rack, dcim.location, dcim.site
        object_id: its id, or (for dcim.device) its exact name
        file_path: absolute path to a .png/.jpg/.jpeg/.gif/.webp file, max 25 MB
        name: caption shown in NetBox, max 50 characters (NetBox's limit),
              e.g. "Front tag ST ABC1234 (2026-01-15)". It also names the stored file.
        description: longer free text, e.g. who took it and the ticket key

    Returns:
        The created image attachment dict (includes its id and image URL).
    """
    _assert_writable("extras.imageattachment", WRITE_ALLOWED_CREATE, "create")
    # NetBox rejects a longer name with a bare 400, and an attachment's name cannot be
    # fixed afterwards over the API (PATCH returned 500 on NetBox 4.4), so check up front.
    if name and len(name) > IMAGE_NAME_MAX:
        raise ValueError(
            f"name is {len(name)} characters; NetBox allows {IMAGE_NAME_MAX}. "
            "Put the extra detail in description."
        )
    if object_type not in IMAGE_ATTACH_OBJECT_TYPES:
        raise ValueError(
            f"Images may only be attached to: {', '.join(sorted(IMAGE_ATTACH_OBJECT_TYPES))}."
        )
    if object_type == "dcim.device":
        object_id = _resolve_device(object_id)
    elif not str(object_id).isdigit():
        raise ValueError(f"object_id must be numeric for {object_type}.")

    path = os.path.realpath(os.path.expanduser(file_path))
    ext = os.path.splitext(path)[1].lower()
    if ext not in IMAGE_TYPES:
        raise ValueError(f"Only image files are accepted ({', '.join(sorted(IMAGE_TYPES))}).")
    if not os.path.isfile(path):
        raise ValueError(f"No such file: {path}")
    size = os.path.getsize(path)
    if size == 0 or size > IMAGE_MAX_BYTES:
        raise ValueError(f"Image must be 1 byte to {IMAGE_MAX_BYTES // (1024 * 1024)} MB.")
    mime, magics = IMAGE_TYPES[ext]
    with open(path, "rb") as fh:
        head = fh.read(12)
        if not any(head.startswith(m) for m in magics) or (
            ext == ".webp" and head[8:12] != b"WEBP"
        ):
            raise ValueError(f"{path} does not look like a real {ext} image.")
        fh.seek(0)
        endpoint, _ = _get_endpoint_info("extras.imageattachment")
        data = {"object_type": object_type, "object_id": str(int(object_id))}
        if name:
            data["name"] = name
        if description:
            data["description"] = description
        return netbox.upload(endpoint, data, files={"image": (os.path.basename(path), fh, mime)})


# ----------------------- end whitelisted write tools -----------------------


def _get_endpoint_info(object_type: str) -> tuple[str, str | None]:
    """
    Returns (endpoint, fallback_endpoint) for the given object type.

    The fallback_endpoint is used for NetBox version compatibility when
    an endpoint path has changed between versions.

    Args:
        object_type: The NetBox object type (e.g., "dcim.device")

    Returns:
        Tuple of (endpoint, fallback_endpoint). fallback_endpoint is None
        if no fallback is needed for this object type.
    """
    type_info = NETBOX_OBJECT_TYPES[object_type]
    return type_info["endpoint"], type_info.get("fallback_endpoint")


def discover_plugin_types(client: NetBoxRestClient) -> dict[str, dict[str, str]]:
    """Discover plugin object types from NetBox's object-types API.

    Queries the NetBox instance for installed plugin models that have REST API
    endpoints and returns them in the same format as NETBOX_OBJECT_TYPES.

    Args:
        client: Initialized NetBox REST API client

    Returns:
        Dict mapping type keys (e.g. "netbox_dns.zone") to endpoint info dicts.
        Returns empty dict on any error (graceful degradation).
    """
    logger = logging.getLogger(__name__)
    plugin_types: dict[str, dict[str, str]] = {}

    try:
        # Paginate through all object types
        offset = 0
        limit = 100
        api_path = urlsplit(client.api_url).path.strip("/")
        while True:
            response = client.get(
                "core/object-types",
                params={"limit": limit, "offset": offset},
                fallback_endpoint="extras/object-types",  # NetBox < 4.4
            )

            results = response.get("results", [])
            for obj_type in results:
                # Only include plugin models with REST API endpoints
                if not obj_type.get("is_plugin_model", False):
                    continue

                rest_url = obj_type.get("rest_api_endpoint")
                if not rest_url:
                    continue

                app_label = obj_type.get("app_label", "")
                model = obj_type.get("model", "")
                if not app_label or not model:
                    continue

                type_key = f"{app_label}.{model}"

                # Skip if it would collide with a core type
                if type_key in NETBOX_OBJECT_TYPES:
                    logger.debug(f"Skipping plugin type '{type_key}': collides with core type")
                    continue

                # Convert REST URL to endpoint path:
                # "/api/plugins/netbox-dns/zones/" -> "plugins/netbox-dns/zones"
                endpoint = rest_url.strip("/")
                if api_path and endpoint.startswith(f"{api_path}/"):
                    endpoint = endpoint[len(api_path) + 1 :]
                if endpoint.startswith("api/"):
                    endpoint = endpoint[4:]

                # Build a display name from the model name
                display_name = obj_type.get("display", model)

                plugin_types[type_key] = {
                    "name": display_name,
                    "endpoint": endpoint,
                }

            # Check if there are more pages
            if not results or not response.get("next"):
                break
            offset += len(results)

    except (httpx.HTTPError, ValueError, KeyError) as e:
        logger.warning(f"Plugin discovery failed, continuing with core types only: {e}")
        return {}

    if plugin_types:
        logger.info(
            f"Discovered {len(plugin_types)} plugin object types: "
            + ", ".join(sorted(plugin_types.keys()))
        )
    else:
        logger.info("No plugin object types discovered")

    return plugin_types


async def _update_tool_descriptions() -> None:
    """Update tool descriptions to reflect the current NETBOX_OBJECT_TYPES registry.

    The type list in netbox_get_objects's description is built at import time.
    After plugin discovery adds new types, this refreshes the description so
    LLMs see the full list of available types.
    """
    type_list = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
    tool = await mcp.get_tool("netbox_get_objects")
    if tool:
        # Replace the type list portion of the description
        desc = tool.description
        marker = "Valid object_type values:"
        idx = desc.find(marker)
        if idx != -1:
            # Keep everything up to and including the marker, then append new list
            prefix = desc[: idx + len(marker)]
            suffix_marker = "See NetBox API documentation"
            suffix_idx = desc.find(suffix_marker)
            suffix = (
                f"\n\n    {suffix_marker}" + desc[suffix_idx + len(suffix_marker) :]
                if suffix_idx != -1
                else ""
            )
            tool.description = f"{prefix}\n\n{type_list}{suffix}"


def main() -> None:
    """Main entry point for the MCP server."""
    global netbox

    cli_overlay: dict[str, Any] = parse_cli_args()

    try:
        settings = Settings(**cli_overlay)
    except Exception as e:
        print(f"Configuration error: {e}", file=sys.stderr)  # noqa: T201 - before logging configured
        sys.exit(1)

    configure_logging(settings.log_level)
    logger = logging.getLogger(__name__)

    logger.info("Starting NetBox MCP Server")
    logger.info(f"Effective configuration: {settings.get_effective_config_summary()}")

    if not settings.verify_ssl:
        logger.warning(
            "SSL certificate verification is DISABLED. "
            "This is insecure and should only be used for testing."
        )

    if settings.transport == "http" and settings.host in ["0.0.0.0", "::", "[::]"]:  # noqa: S104 - checking, not binding
        logger.warning(
            f"HTTP transport is bound to {settings.host}:{settings.port}, which exposes the "
            "service to all network interfaces (IPv4/IPv6). This is insecure and should only be "
            "used for testing. Ensure this is secured with TLS/reverse proxy if exposed to network."
        )
    elif settings.transport == "http" and settings.host not in [
        "127.0.0.1",
        "localhost",
    ]:
        logger.info(
            f"HTTP transport is bound to {settings.host}:{settings.port}. "
            "Ensure this is secured with TLS/reverse proxy if exposed to network."
        )

    try:
        netbox = NetBoxRestClient(
            url=str(settings.netbox_url),
            token=settings.netbox_token.get_secret_value(),
            verify_ssl=settings.verify_ssl,
        )
        logger.debug("NetBox client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize NetBox client: {e}")
        sys.exit(1)

    if settings.enable_plugin_discovery:
        plugin_types = discover_plugin_types(netbox)
        if plugin_types:
            NETBOX_OBJECT_TYPES.update(plugin_types)
            asyncio.run(_update_tool_descriptions())

    try:
        if settings.transport == "stdio":
            logger.info("Starting stdio transport")
            mcp.run(transport="stdio")
        elif settings.transport == "http":
            logger.info(f"Starting HTTP transport on {settings.host}:{settings.port}")
            auth = build_http_auth(settings.mcp_auth_token)
            if auth is not None:
                # FastMCP reads mcp.auth when it builds the HTTP app at run time,
                # so this assignment wires it (the 401 tests verify enforcement).
                mcp.auth = auth
                logger.info("HTTP transport authentication enabled (bearer token required)")
            else:
                logger.warning(
                    "HTTP transport is running without authentication. Set "
                    "MCP_AUTH_TOKEN, or place the server behind an authenticating "
                    "TLS reverse proxy or gateway before exposing it to a network."
                )
            middleware = [
                Middleware(
                    CORSMiddleware,
                    allow_origins=settings.cors_origins,
                    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
                    allow_headers=[
                        "Authorization",
                        "mcp-protocol-version",
                        "mcp-session-id",
                    ],
                    expose_headers=["mcp-session-id"],
                )
            ]
            mcp.run(transport="http", host=settings.host, port=settings.port, middleware=middleware)
    except Exception as e:
        logger.error(f"Failed to start MCP server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
