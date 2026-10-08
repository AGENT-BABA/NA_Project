"""
bproto.py - Shared Binary Protocol Implementation
Protocol: BHTTP/1.0 (Binary HTTP Protocol)
"""

import struct
from typing import Dict, List, Tuple, Optional

# Frame Header Format:
# Length: 24 bits (3 bytes)
# Type:    8 bits (1 byte)
# Flags:   8 bits (1 byte)
# Stream: 32 bits (4 bytes)
# Total Header Size: 9 bytes
FRAME_HEADER_SIZE = 9

# Frame Types
FRAME_TYPE_REQ  = 0x01
FRAME_TYPE_RESP = 0x02
FRAME_TYPE_DATA = 0x03
# Unknown frame type for testing v2 extensibility
FRAME_TYPE_EXT_PING = 0xFE

# Frame Flags
FLAG_END_STREAM = 0x01

# Static Header Table (HPACK Mechanism 1: 10 frequent header names)
STATIC_HEADER_TABLE = {
    1: "content-type",
    2: "content-length",
    3: "host",
    4: "user-agent",
    5: "accept",
    6: "connection",
    7: "date",
    8: "server",
    9: "if-modified-since",
    10: "last-modified",
}

NAME_TO_STATIC_INDEX = {v.lower(): k for k, v in STATIC_HEADER_TABLE.items()}

# Method Encodings
METHOD_MAP = {
    "GET": 0x01,
    "HEAD": 0x02,
    "POST": 0x03,
}
CODE_TO_METHOD = {v: k for k, v in METHOD_MAP.items()}


class FrameHeader:
    def __init__(self, length: int, frame_type: int, flags: int, stream_id: int):
        self.length = length
        self.frame_type = frame_type
        self.flags = flags
        self.stream_id = stream_id

    def serialize(self) -> bytes:
        if not (0 <= self.length < (1 << 24)):
            raise ValueError(f"Payload length {self.length} exceeds 24-bit maximum (16777215)")
        # 3 bytes length, 1 byte type, 1 byte flags, 4 bytes stream ID
        b0 = (self.length >> 16) & 0xFF
        b1 = (self.length >> 8) & 0xFF
        b2 = self.length & 0xFF
        return struct.pack("!BBBB", b0, b1, b2, self.frame_type) + struct.pack("!BI", self.flags, self.stream_id)

    @classmethod
    def parse(cls, data: bytes) -> "FrameHeader":
        if len(data) < FRAME_HEADER_SIZE:
            raise ValueError("Buffer too short for frame header")
        b0, b1, b2, frame_type = struct.unpack("!BBBB", data[:4])
        length = (b0 << 16) | (b1 << 8) | b2
        flags, stream_id = struct.unpack("!BI", data[4:9])
        return cls(length, frame_type, flags, stream_id)


def encode_headers(headers: List[Tuple[str, str]]) -> bytes:
    """
    Encode headers using HPACK's first two mechanisms:
    1. Static Table Index: If name in 1..10, 1 byte descriptor: 0x80 | index
       Followed by uint16 value_len + value bytes.
    2. Literal Name: 1 byte descriptor 0x00
       Followed by uint16 name_len + name bytes + uint16 value_len + value bytes.
    """
    out = bytearray()
    # 2 bytes header count
    out.extend(struct.pack("!H", len(headers)))
    for name, value in headers:
        name_lower = name.strip().lower()
        val_bytes = value.strip().encode("utf-8")
        if name_lower in NAME_TO_STATIC_INDEX:
            idx = NAME_TO_STATIC_INDEX[name_lower]
            descriptor = 0x80 | (idx & 0x7F)
            out.append(descriptor)
            out.extend(struct.pack("!H", len(val_bytes)))
            out.extend(val_bytes)
        else:
            out.append(0x00)
            name_bytes = name_lower.encode("utf-8")
            out.extend(struct.pack("!H", len(name_bytes)))
            out.extend(name_bytes)
            out.extend(struct.pack("!H", len(val_bytes)))
            out.extend(val_bytes)
    return bytes(out)


def decode_headers(data: bytes, offset: int = 0) -> Tuple[List[Tuple[str, str]], int]:
    """
    Decode headers from binary buffer starting at offset.
    Returns (headers, new_offset).
    """
    if len(data) - offset < 2:
        raise ValueError("Malformed header count")
    (count,) = struct.unpack("!H", data[offset:offset + 2])
    offset += 2
    headers = []

    for _ in range(count):
        if offset >= len(data):
            raise ValueError("Unexpected EOF reading header descriptor")
        desc = data[offset]
        offset += 1
        if desc & 0x80:
            # Indexed static name
            idx = desc & 0x7F
            if idx not in STATIC_HEADER_TABLE:
                raise ValueError(f"Unknown static header index: {idx}")
            name = STATIC_HEADER_TABLE[idx]
            if len(data) - offset < 2:
                raise ValueError("Unexpected EOF reading indexed value length")
            (v_len,) = struct.unpack("!H", data[offset:offset + 2])
            offset += 2
            if len(data) - offset < v_len:
                raise ValueError("Unexpected EOF reading indexed value payload")
            val = data[offset:offset + v_len].decode("utf-8", errors="replace")
            offset += v_len
            headers.append((name, val))
        else:
            # Literal name
            if len(data) - offset < 2:
                raise ValueError("Unexpected EOF reading literal name length")
            (n_len,) = struct.unpack("!H", data[offset:offset + 2])
            offset += 2
            if len(data) - offset < n_len:
                raise ValueError("Unexpected EOF reading literal name bytes")
            name = data[offset:offset + n_len].decode("utf-8", errors="replace")
            offset += n_len
            if len(data) - offset < 2:
                raise ValueError("Unexpected EOF reading literal value length")
            (v_len,) = struct.unpack("!H", data[offset:offset + 2])
            offset += 2
            if len(data) - offset < v_len:
                raise ValueError("Unexpected EOF reading literal value bytes")
            val = data[offset:offset + v_len].decode("utf-8", errors="replace")
            offset += v_len
            headers.append((name, val))

    return headers, offset


def build_request_frame(path: str, method: str = "GET", headers: Optional[List[Tuple[str, str]]] = None, stream_id: int = 1) -> bytes:
    if headers is None:
        headers = []
    method_code = METHOD_MAP.get(method.upper(), 0x01)
    path_bytes = path.encode("utf-8")
    
    payload = bytearray()
    payload.append(method_code)
    payload.extend(struct.pack("!H", len(path_bytes)))
    payload.extend(path_bytes)
    payload.extend(encode_headers(headers))
    
    header = FrameHeader(
        length=len(payload),
        frame_type=FRAME_TYPE_REQ,
        flags=FLAG_END_STREAM,
        stream_id=stream_id
    )
    return header.serialize() + bytes(payload)


def parse_request_payload(payload: bytes) -> Tuple[str, str, List[Tuple[str, str]]]:
    if len(payload) < 3:
        raise ValueError("Payload too short for request")
    method_code = payload[0]
    method = CODE_TO_METHOD.get(method_code, "GET")
    (path_len,) = struct.unpack("!H", payload[1:3])
    offset = 3
    if len(payload) - offset < path_len:
        raise ValueError("Unexpected EOF reading request path")
    path = payload[offset:offset + path_len].decode("utf-8", errors="replace")
    offset += path_len
    headers, _ = decode_headers(payload, offset)
    return method, path, headers


def build_response_frame(status_code: int, headers: List[Tuple[str, str]], body: bytes, stream_id: int = 1) -> bytes:
    payload = bytearray()
    payload.extend(struct.pack("!H", status_code))
    payload.extend(encode_headers(headers))
    payload.extend(body)

    header = FrameHeader(
        length=len(payload),
        frame_type=FRAME_TYPE_RESP,
        flags=FLAG_END_STREAM,
        stream_id=stream_id
    )
    return header.serialize() + bytes(payload)


def parse_response_payload(payload: bytes) -> Tuple[int, List[Tuple[str, str]], bytes]:
    if len(payload) < 2:
        raise ValueError("Payload too short for response")
    (status_code,) = struct.unpack("!H", payload[:2])
    offset = 2
    headers, body_offset = decode_headers(payload, offset)
    body = payload[body_offset:]
    return status_code, headers, body


def hexdump(data: bytes, prefix: str = "") -> str:
    """Format bytes into canonical hexdump format."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex part to 48 characters for 16 bytes
        hex_part = f"{hex_part:<48}"
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{i:04x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)
