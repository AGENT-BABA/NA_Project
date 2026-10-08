#!/usr/bin/env python3
"""
bserve - Binary HTTP Server (Track 1)
Usage: ./bserve <root_dir> <port>
"""

import os
import sys
import socket
import mimetypes
import traceback
from pathlib import Path
from bproto import (
    FRAME_HEADER_SIZE,
    FRAME_TYPE_REQ,
    FRAME_TYPE_RESP,
    FrameHeader,
    parse_request_payload,
    build_response_frame,
    hexdump,
)


def read_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from socket, or raise EOFError if closed."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            if len(buf) == 0:
                raise EOFError("Connection closed by peer")
            raise ConnectionError(f"Connection closed prematurely, expected {n} bytes, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)


def handle_client(conn: socket.socket, addr: tuple, root_dir: Path):
    print(f"[*] Connection accepted from {addr[0]}:{addr[1]}")
    try:
        while True:
            # 1. Read the 9-byte frame header
            try:
                hdr_bytes = read_exact(conn, FRAME_HEADER_SIZE)
            except EOFError:
                print(f"[*] Client {addr[0]}:{addr[1]} closed connection.")
                break
            except Exception as e:
                print(f"[!] Read error from {addr[0]}:{addr[1]}: {e}")
                break

            try:
                header = FrameHeader.parse(hdr_bytes)
            except Exception as e:
                print(f"[!] Malformed frame header from {addr[0]}:{addr[1]}: {e}")
                # Send 400 Bad Request
                err_resp = build_response_frame(400, [("content-type", "text/plain"), ("server", "bserve/1.0")], b"400 Malformed Frame Header\n", stream_id=0)
                conn.sendall(err_resp)
                break

            # 2. Read frame payload
            try:
                payload = read_exact(conn, header.length)
            except Exception as e:
                print(f"[!] Error reading payload from {addr[0]}:{addr[1]}: {e}")
                err_resp = build_response_frame(400, [("content-type", "text/plain"), ("server", "bserve/1.0")], b"400 Incomplete Frame Payload\n", stream_id=header.stream_id)
                conn.sendall(err_resp)
                break

            # 3. Check frame type: MUST skip cleanly if unknown!
            if header.frame_type != FRAME_TYPE_REQ:
                print(f"[?] Received unknown frame type 0x{header.frame_type:02x} (len={header.length}). Skipping cleanly as per protocol spec.")
                continue

            # 4. Parse request frame
            try:
                method, req_path, req_headers = parse_request_payload(payload)
                print(f"[>] Request stream={header.stream_id}: {method} {req_path}")
            except Exception as e:
                print(f"[!] Malformed request payload: {e}")
                err_resp = build_response_frame(400, [("content-type", "text/plain"), ("server", "bserve/1.0")], b"400 Malformed Request\n", stream_id=header.stream_id)
                conn.sendall(err_resp)
                continue

            # 5. Map path to file under root
            clean_path = req_path.split("?")[0].split("#")[0]
            if clean_path.startswith("/"):
                clean_path = clean_path[1:]
            if not clean_path or clean_path.endswith("/"):
                clean_path = clean_path + "index.html"

            target_file = (root_dir / clean_path).resolve()

            # Ensure file is under root_dir (prevent directory traversal)
            try:
                target_file.relative_to(root_dir)
                is_safe = True
            except ValueError:
                is_safe = False

            if not is_safe:
                print(f"[!] Forbidden path traversal attempt: {req_path}")
                err_resp = build_response_frame(400, [("content-type", "text/plain"), ("server", "bserve/1.0")], b"400 Bad Request: Path Traversal Prohibited\n", stream_id=header.stream_id)
                conn.sendall(err_resp)
                continue

            if not target_file.is_file():
                print(f"[-] File not found: {target_file}")
                body = f"404 Not Found: {req_path}\n".encode("utf-8")
                resp_headers = [
                    ("content-type", "text/plain; charset=utf-8"),
                    ("content-length", str(len(body))),
                    ("server", "bserve/1.0"),
                    ("connection", "keep-alive"),
                ]
                resp = build_response_frame(404, resp_headers, body, stream_id=header.stream_id)
                conn.sendall(resp)
            else:
                try:
                    with open(target_file, "rb") as f:
                        file_bytes = f.read()
                    mime_type, _ = mimetypes.guess_type(str(target_file))
                    if not mime_type:
                        mime_type = "application/octet-stream"

                    resp_headers = [
                        ("content-type", mime_type),
                        ("content-length", str(len(file_bytes))),
                        ("server", "bserve/1.0"),
                        ("connection", "keep-alive"),
                    ]
                    resp = build_response_frame(200, resp_headers, file_bytes, stream_id=header.stream_id)
                    conn.sendall(resp)
                    print(f"[<] Replied 200 OK ({len(file_bytes)} bytes) for {req_path}")
                except Exception as e:
                    print(f"[!] File read error: {e}")
                    body = b"500 Internal Server Error\n"
                    resp = build_response_frame(500, [("content-type", "text/plain"), ("server", "bserve/1.0")], body, stream_id=header.stream_id)
                    conn.sendall(resp)

    finally:
        conn.close()
        print(f"[*] Closed connection with {addr[0]}:{addr[1]}")


def main():
    if len(sys.argv) < 3:
        print("Usage: ./bserve <root_dir> <port>", file=sys.stderr)
        sys.exit(1)

    root_arg = sys.argv[1]
    port_arg = int(sys.argv[2])

    root_dir = Path(root_arg).resolve()
    if not root_dir.exists():
        print(f"[!] Warning: Root directory '{root_dir}' does not exist. Creating it.")
        root_dir.mkdir(parents=True, exist_ok=True)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", port_arg))
    server_sock.listen(128)

    print(f"[*] bserve listening on 0.0.0.0:{port_arg}")
    print(f"[*] Document root: {root_dir}")
    print("[*] Ready to accept binary HTTP frames...\n")

    try:
        while True:
            conn, addr = server_sock.accept()
            handle_client(conn, addr, root_dir)
    except KeyboardInterrupt:
        print("\n[*] Shutting down bserve.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
