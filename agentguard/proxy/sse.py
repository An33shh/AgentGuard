"""
Provider-agnostic Server-Sent Events (SSE) wire protocol.

Every streaming LLM API (Anthropic Messages, OpenAI Chat Completions/
Responses) uses the same underlying `text/event-stream` grammar — only the
JSON payloads inside `data:` differ per provider. This module knows nothing
about any provider's payload shape; it only parses/encodes the wire format
itself, so it's never touched when a new provider is added.
"""

from __future__ import annotations

import codecs
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx


@dataclass
class SSEEvent:
    """One parsed SSE event. `data` is the still-encoded JSON string (or a
    comment payload for keep-alive pings), not yet json.loads()'d — callers
    that need the payload parse it themselves."""

    event: str | None = None
    data: str = ""
    id: str | None = None
    is_comment: bool = False  # a bare ": ..." keep-alive line, not a real event


class _SSELineParser:
    """Accumulates SSE fields line-by-line, yielding a complete SSEEvent on
    each blank-line terminator. One instance per stream — holds in-progress
    field state across possibly-many feed_line() calls."""

    def __init__(self) -> None:
        self._event: str | None = None
        self._data_lines: list[str] = []
        self._id: str | None = None
        self._is_comment = False
        self._has_content = False

    def feed_line(self, line: str) -> SSEEvent | None:
        if line == "":
            if not self._has_content:
                return None
            result = SSEEvent(
                event=self._event,
                data="\n".join(self._data_lines),
                id=self._id,
                is_comment=self._is_comment,
            )
            self._reset()
            return result
        if line.startswith(":"):
            self._is_comment = True
            self._has_content = True
            return None
        if line.startswith("event:"):
            self._event = line[len("event:"):].lstrip(" ")
            self._has_content = True
        elif line.startswith("data:"):
            self._data_lines.append(line[len("data:"):].lstrip(" "))
            self._has_content = True
        elif line.startswith("id:"):
            self._id = line[len("id:"):].lstrip(" ")
            self._has_content = True
        # Unrecognized field names are ignored per the SSE spec.
        return None

    def _reset(self) -> None:
        self._event = None
        self._data_lines = []
        self._id = None
        self._is_comment = False
        self._has_content = False


async def iter_sse_events(response: httpx.Response) -> AsyncIterator[SSEEvent]:
    """
    Parse an httpx streaming response (opened via `client.stream(...)`) into
    discrete SSEEvents.

    Iterates raw bytes (not aiter_lines()) so line-splitting is handled
    explicitly here, correctly handling a "data:" field arriving split
    across two separate network reads/chunks.

    Decodes via an incremental UTF-8 decoder rather than decoding each raw
    byte chunk independently — a multi-byte UTF-8 character (e.g. an em
    dash or accented letter inside a text_delta) can legitimately land split
    across two separate network reads, and decoding each half independently
    with errors="replace" corrupts it into replacement characters on both
    sides instead of correctly holding the incomplete sequence until the
    rest arrives.
    """
    parser = _SSELineParser()
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    buffer = ""
    async for chunk in response.aiter_bytes():
        buffer += decoder.decode(chunk)
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.removesuffix("\r")
            event = parser.feed_line(line)
            if event is not None:
                yield event
    # Flush any bytes the incremental decoder held back — a genuinely
    # truncated multi-byte sequence at end-of-stream, not a normal split.
    buffer += decoder.decode(b"", final=True)
    while "\n" in buffer:
        line, buffer = buffer.split("\n", 1)
        line = line.removesuffix("\r")
        event = parser.feed_line(line)
        if event is not None:
            yield event
    # Flush a trailing event that wasn't terminated by a final blank line.
    trailing = parser.feed_line("")
    if trailing is not None:
        yield trailing


def encode_sse_event(event: SSEEvent) -> bytes:
    """Serialize an SSEEvent back to wire bytes ('event: ...\\ndata: ...\\n\\n')."""
    lines: list[str] = []
    if event.event is not None:
        lines.append(f"event: {event.event}")
    for data_line in event.data.split("\n"):
        lines.append(f"data: {data_line}")
    if event.id is not None:
        lines.append(f"id: {event.id}")
    return ("\n".join(lines) + "\n\n").encode("utf-8")
