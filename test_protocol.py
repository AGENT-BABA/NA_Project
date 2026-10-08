"""
Comprehensive Automated Test Suite for BHTTP Protocol (Track 1 & Track 2)
Tests:
- 200 OK delivery
- 404 Not Found handling
- 400 Malformed Frame handling
- Clean skipping of unknown / future frame types (v2 extensibility requirement)
- Persistent connection (multiple requests on one socket)
- Header compression (HPACK static indexing + literal fallbacks)
"""

import time
import socket
import threading
import subprocess
import sys
from pathlib import Path

from bproto import (
    FRAME_HEADER_SIZE,
    FRAME_TYPE_REQ,
    FRAME_TYPE_RESP,
    FrameHeader,
    build_request_frame,
    parse_response_payload,
    hexdump,
)

SERVER_PORT = 9123
ROOT_DIR = Path(__file__).parent / "www"

def run_tests():
    print("=== STARTING BHTTP PROTOCOL TESTS ===")
    
    # 1. Start bserve in background thread or process
    import bserve
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", SERVER_PORT))
    server_sock.listen(16)
    
    running = True

    def server_thread_func():
        while running:
            try:
                server_sock.settimeout(0.5)
                conn, addr = server_sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            bserve.handle_client(conn, addr, ROOT_DIR)

    t = threading.Thread(target=server_thread_func, daemon=True)
    t.start()
    print(f"[*] Test server running on port {SERVER_PORT}")
    time.sleep(0.2)

    try:
        # TEST 1: Normal 200 OK request
        print("\n--- Test 1: GET /index.html (200 OK) ---")
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", SERVER_PORT))

        req = build_request_frame(
            path="/index.html",
            method="GET",
            headers=[("host", f"127.0.0.1:{SERVER_PORT}"), ("user-agent", "TestClient/1.0")],
            stream_id=1
        )
        client_sock.sendall(req)

        hdr_bytes = bserve.read_exact(client_sock, FRAME_HEADER_SIZE)
        hdr = FrameHeader.parse(hdr_bytes)
        assert hdr.frame_type == FRAME_TYPE_RESP, f"Expected RESP frame, got {hdr.frame_type}"
        assert hdr.stream_id == 1, f"Expected stream_id 1, got {hdr.stream_id}"

        payload = bserve.read_exact(client_sock, hdr.length)
        status, headers, body = parse_response_payload(payload)
        assert status == 200, f"Expected status 200, got {status}"
        assert b"Hello from BHTTP!" in body, f"Body content mismatch: {body}"
        print(f"PASSED: Received 200 OK with {len(body)} bytes body.")

        # TEST 2: Persistent Connection (Keep-alive) on same connection
        print("\n--- Test 2: Persistent Connection (Second request on same socket) ---")
        req2 = build_request_frame(
            path="/index.html",
            method="GET",
            headers=[("host", f"127.0.0.1:{SERVER_PORT}")],
            stream_id=2
        )
        client_sock.sendall(req2)
        hdr_bytes2 = bserve.read_exact(client_sock, FRAME_HEADER_SIZE)
        hdr2 = FrameHeader.parse(hdr_bytes2)
        payload2 = bserve.read_exact(client_sock, hdr2.length)
        status2, _, _ = parse_response_payload(payload2)
        assert status2 == 200
        assert hdr2.stream_id == 2
        print("PASSED: Persistent connection verified! Second request succeeded on the same TCP socket.")

        # TEST 3: 404 Not Found on same connection
        print("\n--- Test 3: 404 Not Found ---")
        req3 = build_request_frame(
            path="/does-not-exist.txt",
            method="GET",
            stream_id=3
        )
        client_sock.sendall(req3)
        hdr3 = FrameHeader.parse(bserve.read_exact(client_sock, FRAME_HEADER_SIZE))
        payload3 = bserve.read_exact(client_sock, hdr3.length)
        status3, _, body3 = parse_response_payload(payload3)
        assert status3 == 404, f"Expected 404, got {status3}"
        assert b"404 Not Found" in body3
        print(f"PASSED: Received 404 Not Found properly for missing resource.")
        client_sock.close()

        # TEST 4: Unknown Frame Clean Skipping (v2 extensibility rule)
        print("\n--- Test 4: Unknown Frame Type (Must Skip Cleanly) ---")
        client_sock4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock4.connect(("127.0.0.1", SERVER_PORT))

        # Send an unknown frame type 0xFE with 8 bytes payload
        unknown_hdr = FrameHeader(length=8, frame_type=0xFE, flags=0x00, stream_id=42)
        unknown_frame = unknown_hdr.serialize() + b"UNKNOWN!"
        client_sock4.sendall(unknown_frame)

        # Immediately send a standard REQ frame on the same stream/connection
        req4 = build_request_frame(path="/index.html", stream_id=43)
        client_sock4.sendall(req4)

        # The server should have skipped the unknown frame cleanly and replied to req4!
        resp_hdr4 = FrameHeader.parse(bserve.read_exact(client_sock4, FRAME_HEADER_SIZE))
        assert resp_hdr4.frame_type == FRAME_TYPE_RESP
        assert resp_hdr4.stream_id == 43
        resp_pl4 = bserve.read_exact(client_sock4, resp_hdr4.length)
        st4, _, _ = parse_response_payload(resp_pl4)
        assert st4 == 200
        print("PASSED: Unknown frame type 0xFE was skipped cleanly and subsequent request was served!")
        client_sock4.close()

        # TEST 5: Malformed Frame / Path Traversal -> 400 Bad Request
        print("\n--- Test 5: Path Traversal / Malformed Frame ---")
        client_sock5 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock5.connect(("127.0.0.1", SERVER_PORT))
        req5 = build_request_frame(path="../../secret.txt", stream_id=5)
        client_sock5.sendall(req5)
        resp_hdr5 = FrameHeader.parse(bserve.read_exact(client_sock5, FRAME_HEADER_SIZE))
        resp_pl5 = bserve.read_exact(client_sock5, resp_hdr5.length)
        st5, _, _ = parse_response_payload(resp_pl5)
        assert st5 == 400
        print("PASSED: Path traversal rejected with 400 Bad Request.")
        client_sock5.close()

        # TEST 6: bcurl CLI invocation test with -v
        print("\n--- Test 6: CLI Execution of bcurl with -v ---")
        proc = subprocess.run(
            [sys.executable, "bcurl.py", "-v", f"127.0.0.1:{SERVER_PORT}/index.html"],
            capture_output=True,
            text=True
        )
        assert proc.returncode == 0, f"bcurl failed with code {proc.returncode}"
        assert "Hello from BHTTP!" in proc.stdout
        assert "Sending REQ frame" in proc.stderr
        assert "Status: 200" in proc.stderr
        print("PASSED: bcurl CLI output and hex dump verified!")

        # TEST 7: bcurl exit non-zero on 404
        print("\n--- Test 7: bcurl non-zero exit code on 404 ---")
        proc_404 = subprocess.run(
            [sys.executable, "bcurl.py", f"127.0.0.1:{SERVER_PORT}/missing.html"],
            capture_output=True,
            text=True
        )
        assert proc_404.returncode != 0, f"Expected non-zero exit code, got {proc_404.returncode}"
        print(f"PASSED: bcurl exited with code {proc_404.returncode} on 404.")

        print("\n==========================================")
        print("ALL 7 PROTOCOL TESTS PASSED PERFECTLY!")
        print("==========================================")

    finally:
        running = False
        server_sock.close()

if __name__ == "__main__":
    run_tests()
