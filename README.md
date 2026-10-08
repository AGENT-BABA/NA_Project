# HTTP in Binary: Two Tracks, One Protocol

Implementation of the **BHTTP** (Binary HTTP/1.0) course project specification.

## Deliverables Summary

1. **The Spec (Two pages)**: [`SPEC.md`](file:///k:/Classes/Network%20Architecture/Project/SPEC.md)
   - Fixed-size frame header: 24-bit Length, 8-bit Type, 8-bit Flags, 31-bit Stream ID.
   - Comprehensive defense against HTTP/2's 24 / 8 / 8 / 31 decision.
   - HPACK-derived header compression (10 static table indexed names + length-prefixed literals).
   - Mandatory rule: Receiver skips unknown frame types cleanly for v2 forward compatibility.
2. **The Programs**:
   - Server: [`bserve`](file:///k:/Classes/Network%20Architecture/Project/bserve) (Python: [`bserve.py`](file:///k:/Classes/Network%20Architecture/Project/bserve.py))
   - Client: [`bcurl`](file:///k:/Classes/Network%20Architecture/Project/bcurl) (Python: [`bcurl.py`](file:///k:/Classes/Network%20Architecture/Project/bcurl.py))
   - Shared Protocol Module: [`bproto.py`](file:///k:/Classes/Network%20Architecture/Project/bproto.py)
3. **Annotated Hexdump**: [`HEXDUMP.md`](file:///k:/Classes/Network%20Architecture/Project/HEXDUMP.md)
   - Byte-by-byte table annotating each bit, byte offset, field, and value for both request and response frames.

---

## Quick Start & Usage

### 1. Track 1 — Start the Server
```bash
# On Linux / macOS / Bash:
./bserve ./www 9000

# On Windows PowerShell / CMD:
python bserve.py ./www 9000
# or:
.\bserve.bat ./www 9000
```

### 2. Track 2 — Run the Client
```bash
# On Linux / macOS / Bash:
./bcurl -v localhost:9000/index.html

# On Windows PowerShell / CMD:
python bcurl.py -v localhost:9000/index.html
# or:
.\bcurl.bat -v localhost:9000/index.html
```

### 3. Run Automated Protocol Verification
```bash
python test_protocol.py
```
This runs 7 tests verifying:
- 200 OK delivery
- Persistent connection (reusing single TCP connection)
- 404 Not Found error handling
- Unknown / Extension frame clean skipping (v2 compatibility)
- Malformed frame & path traversal rejection (400 Bad Request)
- Hex dump formatting in verbose mode (`-v`)
- Non-zero exit code on 4xx/5xx responses
