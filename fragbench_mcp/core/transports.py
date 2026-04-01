from __future__ import annotations

from contextlib import AsyncExitStack
from typing import Any, Tuple

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

try:
    from mcp.client.sse import sse_client
except Exception:  # pragma: no cover
    sse_client = None  # type: ignore

try:
    from mcp.client.streamable_http import streamablehttp_client
except Exception:  # pragma: no cover
    streamablehttp_client = None  # type: ignore


async def connect_stdio(
    exit_stack: AsyncExitStack,
    params: StdioServerParameters,
) -> Tuple[ClientSession, Any]:
    transport = await exit_stack.enter_async_context(stdio_client(params))
    read_stream, write_stream = transport
    session = await exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
    await session.initialize()
    return session, transport


async def connect_sse(
    exit_stack: AsyncExitStack,
    url: str,
) -> Tuple[ClientSession, Any]:
    if sse_client is None:
        raise RuntimeError("SSE transport unavailable in current MCP package.")
    transport = await exit_stack.enter_async_context(sse_client(url))
    read_stream, write_stream = transport
    session = await exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
    await session.initialize()
    return session, transport


async def connect_streamable_http(
    exit_stack: AsyncExitStack,
    url: str,
) -> Tuple[ClientSession, Any]:
    if streamablehttp_client is None:
        raise RuntimeError("Streamable HTTP transport unavailable in current MCP package.")
    transport = await exit_stack.enter_async_context(streamablehttp_client(url))
    read_stream, write_stream, *_ = transport
    session = await exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
    await session.initialize()
    return session, transport
