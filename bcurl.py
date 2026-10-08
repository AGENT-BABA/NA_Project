#!/usr/bin/env python3
"""
bcurl - Binary HTTP Client (Track 2)
Usage: ./bcurl [-v] <host:port/path>
"""

import sys
import socket
import urllib.parse
from bproto import (
    FRAME_HEADER_SIZE,
    FRAME_TYPE_REQ,
    FRAME_TYPE_RESP,
    FrameHeader,
    build_request_frame,
    parse_response_payload,
    hexdump,
)


def read_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from socket, or raise EOFError if closed."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            if len(buf) == 0:
                raise EOFError("Connection closed by peer before reading expected bytes")
            raise ConnectionError(f"Premature EOF: expected {n} bytes, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)


def parse_target_url(target: str):
    """
    Parse strings like:
    - localhost:9000/index.html
    - http://localhost:9000/test.txt
    - 127.0.0.1:8080/
    """
    if not target.startswith("http://") and not target.startswith("https://") and not target.startswith("//"):
        target_parsed = urllib.parse.urlsplit("//" + target)
    else:
        target_parsed = urllib.parse.urlsplit(target)

    host = target_parsed.hostname or "127.0.0.1"
    port = target_parsed.port or 80
    path = target_parsed.path or "/"
    if target_parsed.query:
        path += "?" + target_parsed.query
    return host, port, path


def main():
    args = sys.argv[1:]
    verbose = False
    url_target = None

    for arg in args:
        if arg in ("-v", "--verbose"):
            verbose = True
        elif not arg.startswith("-"):
            url_target = arg

    if not url_target:
        sys.stderr.write("Usage: ./bcurl [-v] <host:port/path>\n")
        sys.exit(1)

    try:
        host, port, path = parse_target_url(url_target)
    except Exception as e:
        sys.stderr.write(f"Error parsing URL '{url_target}': {e}\n")
        sys.exit(1)

    # Establish TCP connection (never open a second connection)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
    except Exception as e:
        sys.stderr.write(f"Connection failed to {host}:{port}: {e}\n")
        sys.exit(1)

    try:
        # Build binary request frame
        req_headers = [
            ("host", f"{host}:{port}"),
            ("user-agent", "bcurl/1.0"),
            ("accept", "*/*"),
        ]
        stream_id = 1
        req_bytes = build_request_frame(path, method="GET", headers=req_headers, stream_id=stream_id)

        if verbose:
            sys.stderr.write(f"* Connected to {host}:{port}\n")
            sys.stderr.write(f"* Sending REQ frame (stream_id={stream_id}, total_size={len(req_bytes)} bytes):\n")
            sys.stderr.write(hexdump(req_bytes, prefix="> ") + "\n\n")

        sock.sendall(req_bytes)

        # Read response frames
        while True:
            hdr_bytes = read_exact(sock, FRAME_HEADER_SIZE)
            header = FrameHeader.parse(hdr_bytes)
            payload_bytes = read_exact(sock, header.length)
            full_frame = hdr_bytes + payload_bytes

            if verbose:
                sys.stderr.write(
                    f"* Received frame: type=0x{header.frame_type:02x}, length={header.length}, "
                    f"flags=0x{header.flags:02x}, stream={header.stream_id}\n"
                )
                sys.stderr.write(hexdump(full_frame, prefix="< ") + "\n\n")

            # Spec requirement: unknown frame types MUST be cleanly skipped!
            if header.frame_type != FRAME_TYPE_RESP:
                if verbose:
                    sys.stderr.write(f"* Skipping unknown/extension frame type 0x{header.frame_type:02x} cleanly\n")
                continue

            # Parse response payload
            status_code, resp_headers, body = parse_response_payload(payload_bytes)

            if verbose:
                sys.stderr.write(f"* Status: {status_code}\n")
                for h_name, h_val in resp_headers:
                    sys.stderr.write(f"* Header: {h_name}: {h_val}\n")
                sys.stderr.write(f"* Body length: {len(body)} bytes\n\n")

            # Output body to stdout
            try:
                sys.stdout.buffer.write(body)
                sys.stdout.buffer.flush()
            except BrokenPipeError:
                pass

            # Exit non-zero on 4xx or 5xx
            if status_code >= 400:
                if verbose:
                    sys.stderr.write(f"\n* Exiting with failure status {status_code}\n")
                sys.exit(1)

            sys.exit(0)

    except Exception as e:
        sys.stderr.write(f"Protocol error: {e}\n")
        sys.exit(2)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
