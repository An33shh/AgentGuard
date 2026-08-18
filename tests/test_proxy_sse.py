"""Tests for the provider-agnostic SSE wire protocol (agentguard/proxy/sse.py)."""

from __future__ import annotations

import pytest

from agentguard.proxy.sse import SSEEvent, encode_sse_event, iter_sse_events


class FakeResponse:
    """Minimal stand-in for httpx.Response, yielding pre-scripted byte chunks
    from aiter_bytes() — lets us control exactly how the wire bytes are split
    across reads, which is the thing this parser has to get right."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def aiter_bytes(self):
        for chunk in self._chunks:
            yield chunk


async def collect(chunks: list[bytes]) -> list[SSEEvent]:
    return [e async for e in iter_sse_events(FakeResponse(chunks))]


class TestIterSSEEvents:
    @pytest.mark.asyncio
    async def test_single_event_single_chunk(self) -> None:
        events = await collect([b'event: message_start\ndata: {"type":"message_start"}\n\n'])
        assert len(events) == 1
        assert events[0].event == "message_start"
        assert events[0].data == '{"type":"message_start"}'

    @pytest.mark.asyncio
    async def test_multiple_events_one_chunk(self) -> None:
        raw = (
            b'event: a\ndata: {"x":1}\n\n'
            b'event: b\ndata: {"x":2}\n\n'
        )
        events = await collect([raw])
        assert [e.event for e in events] == ["a", "b"]
        assert events[0].data == '{"x":1}'
        assert events[1].data == '{"x":2}'

    @pytest.mark.asyncio
    async def test_event_split_across_chunk_boundary(self) -> None:
        raw = b'event: content_block_delta\ndata: {"delta":{"text":"hello world"}}\n\n'
        # Split mid-field, mid-line, and mid-terminator to exercise every
        # boundary case a real TCP stream could produce.
        for split_point in range(1, len(raw)):
            chunks = [raw[:split_point], raw[split_point:]]
            events = await collect(chunks)
            assert len(events) == 1, f"failed at split_point={split_point}"
            assert events[0].event == "content_block_delta"
            assert events[0].data == '{"delta":{"text":"hello world"}}'

    @pytest.mark.asyncio
    async def test_multibyte_utf8_character_split_across_chunk_boundary(self) -> None:
        # Code-review finding: decoding each raw byte chunk independently
        # with errors="replace" corrupts a multi-byte UTF-8 character (here,
        # an em dash, 3 bytes: \xe2\x80\x94) that legitimately lands split
        # across two separate network reads — each half decodes to a
        # replacement character instead of the incremental decoder
        # correctly holding the incomplete sequence until the rest arrives.
        text = "café — test"
        raw = ('event: content_block_delta\ndata: {"delta":{"text":"' + text + '"}}\n\n').encode("utf-8")
        for split_point in range(1, len(raw)):
            chunks = [raw[:split_point], raw[split_point:]]
            events = await collect(chunks)
            assert len(events) == 1, f"failed at split_point={split_point}"
            assert text in events[0].data, f"corrupted at split_point={split_point}: {events[0].data!r}"

    @pytest.mark.asyncio
    async def test_multiline_data_field_joined_with_newline(self) -> None:
        raw = b"event: x\ndata: line one\ndata: line two\n\n"
        events = await collect([raw])
        assert events[0].data == "line one\nline two"

    @pytest.mark.asyncio
    async def test_comment_line_is_a_ping_event(self) -> None:
        events = await collect([b": keep-alive\n\n"])
        assert len(events) == 1
        assert events[0].is_comment is True
        assert events[0].event is None
        assert events[0].comment == "keep-alive"

    @pytest.mark.asyncio
    async def test_bare_comment_with_no_text_round_trips(self) -> None:
        events = await collect([b":\n\n"])
        assert events[0].is_comment is True
        assert events[0].comment == ""

    @pytest.mark.asyncio
    async def test_blank_lines_between_events_dont_produce_empty_events(self) -> None:
        raw = b"event: a\ndata: {}\n\n\n\nevent: b\ndata: {}\n\n"
        events = await collect([raw])
        assert [e.event for e in events] == ["a", "b"]

    @pytest.mark.asyncio
    async def test_trailing_event_without_final_blank_line_still_flushed(self) -> None:
        # Some servers close the connection right after the last data line
        # without a trailing blank-line terminator — must not be dropped.
        events = await collect([b"event: message_stop\ndata: {}"])
        assert len(events) == 1
        assert events[0].event == "message_stop"

    @pytest.mark.asyncio
    async def test_id_field_parsed(self) -> None:
        events = await collect([b"id: 42\nevent: a\ndata: {}\n\n"])
        assert events[0].id == "42"

    @pytest.mark.asyncio
    async def test_crlf_line_endings_handled(self) -> None:
        raw = b'event: a\r\ndata: {"x":1}\r\n\r\n'
        events = await collect([raw])
        assert events[0].event == "a"
        assert events[0].data == '{"x":1}'


class TestEncodeSSEEvent:
    def test_roundtrip_basic_event(self) -> None:
        event = SSEEvent(event="content_block_delta", data='{"a":1}')
        encoded = encode_sse_event(event)
        assert encoded == b'event: content_block_delta\ndata: {"a":1}\n\n'

    def test_encode_without_event_name(self) -> None:
        # OpenAI-style: data-only frames, no "event:" line.
        event = SSEEvent(data='{"a":1}')
        encoded = encode_sse_event(event)
        assert encoded == b'data: {"a":1}\n\n'

    def test_encode_multiline_data(self) -> None:
        event = SSEEvent(event="x", data="line one\nline two")
        encoded = encode_sse_event(event)
        assert encoded == b"event: x\ndata: line one\ndata: line two\n\n"

    @pytest.mark.asyncio
    async def test_encode_then_parse_is_identity(self) -> None:
        original = SSEEvent(event="content_block_stop", data='{"index":0}', id="7")
        encoded = encode_sse_event(original)
        parsed = await collect([encoded])
        assert len(parsed) == 1
        assert parsed[0].event == original.event
        assert parsed[0].data == original.data
        assert parsed[0].id == original.id

    def test_comment_keep_alive_encodes_as_a_real_comment_not_malformed_data(self) -> None:
        # Regression: this used to fall through to the data-line branch and
        # produce b'data: \n\n' — a malformed empty JSON-shaped event that
        # crashes a client (e.g. the OpenAI SDK) doing json.loads() on every
        # non-"[DONE]" event it receives. Real upstream gateways (OpenRouter,
        # nginx-fronted proxies) send comment keep-alives mid-stream.
        event = SSEEvent(is_comment=True, comment="OPENROUTER PROCESSING")
        encoded = encode_sse_event(event)
        assert encoded == b": OPENROUTER PROCESSING\n\n"
        assert b"data:" not in encoded

    @pytest.mark.asyncio
    async def test_comment_keep_alive_round_trips_through_parse_encode_parse(self) -> None:
        original_wire = b": OPENROUTER PROCESSING\n\n"
        parsed = await collect([original_wire])
        assert len(parsed) == 1
        re_encoded = encode_sse_event(parsed[0])
        assert re_encoded == original_wire
        re_parsed = await collect([re_encoded])
        assert re_parsed[0].is_comment is True
        assert re_parsed[0].comment == "OPENROUTER PROCESSING"
