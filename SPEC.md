# BHTTP/1.0 Protocol Specification (Binary HTTP)

**Status:** Final Standard  
**Authors:** Network Architecture Working Group  
**Target Audience:** Implementers of `bserve` (Server) and `bcurl` (Client)  

---

## 1. Introduction and Architectural Motivation

Traditional HTTP/1.1 relies on ASCII text delimiters (CRLF `\r\n`), line-by-line parsing, chunked transfer encoding hacks, and verbose repetitive headers. This text framing incurs significant CPU parsing overhead, introduces request smuggling vulnerabilities, and prevents safe protocol extensibility.

**BHTTP/1.0** replaces textual parsing with deterministic binary framing. Every transmission unit is an explicitly-sized binary frame. The protocol guarantees:
1. **Zero Delimiter Scanning:** Framed data boundaries are known before reading the payload.
2. **Deterministic Extensibility:** Receivers safely ignore unknown future frame types.
3. **Compact Headers:** Frequent header names are indexed via static dictionary lookups, eliminating redundant byte transmission.
4. **Persistent Connections:** A single TCP transport session serves multiple sequential or interleaved request/response exchanges without connection teardown.

---

## 2. Frame Format & Field Justification

All BHTTP communication occurs through fixed-header binary frames over a reliable stream (TCP).

### 2.1 The 9-Octet Frame Header Layout

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Length (24)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type (8)    |   Flags (8)   |       R (1)   |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                       Stream Identifier (31)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Frame Payload (0...2^24-1)              ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.2 Field Width Defense & The HTTP/2 Comparison (24 / 8 / 8 / 31)

Why did HTTP/2 select 24 / 8 / 8 / 31, and why does BHTTP adopt this exact design?

1. **Payload Length (24 bits — 3 Octets):**
   - *Capacity:* Allows frame payloads up to $2^{24} - 1 = 16,777,215$ bytes (16 MB).
   - *Defense:* A 16-bit field (64 KB) is too constrained for transmitting modern web assets (images, scripts) in a single frame, forcing fragmentation overhead. Conversely, a 32-bit field (4 GB) encourages buffer bloat, invites memory-exhaustion denial-of-service attacks, and creates Head-of-Line (HoL) blocking on multiplexed connections. 24 bits strikes the optimal balance between high throughput and predictable memory allocation.
2. **Frame Type (8 bits — 1 Octet):**
   - *Capacity:* Accommodates up to 256 distinct frame types.
   - *Defense:* 8 bits reserves ample namespace for core types (`0x01` REQ, `0x02` RESP, `0x03` DATA) while leaving $>250$ codes open for future v2 extensions (e.g. `PING`, `GOAWAY`, `WINDOW_UPDATE`).
3. **Flags (8 bits — 1 Octet):**
   - *Capacity:* Provides 8 boolean flags specific to the frame type.
   - *Defense:* Enables rapid, bitmask-level state inspection without parsing payloads. For instance, `END_STREAM (0x01)` signals EOF semantics directly in the header.
4. **Reserved Bit (1 bit) + Stream Identifier (31 bits — 4 Octets total):**
   - *Capacity:* $2^{31} - 1$ unique concurrent streams (~2.14 billion streams).
   - *Defense:* Correlates requests and responses over a long-lived persistent TCP connection. Stream ID 0 is reserved for connection-level signaling. Client-initiated requests utilize odd stream IDs (`1, 3, 5...`), preventing ID collisions without centralized lock synchronization.

---

## 3. The Extensibility Rule (Forward Compatibility)

> **Mandatory Rule:** A receiver (client or server) encountering a frame type it does not know **MUST skip it cleanly**.

Because every frame begins with an unambiguous 24-bit Length field:
```python
if frame_type not in KNOWN_FRAME_TYPES:
    discard_bytes_from_socket(frame_length)
    continue
```
The receiver consumes exactly `Length` octets from the TCP stream and resumes normal protocol processing. **A receiver must NOT terminate the TCP connection or emit an error upon receiving an unknown frame type.** This rule guarantees non-breaking forward compatibility for Version 2 extensions.

---

## 4. Header Compression (HPACK-Derived Mechanisms)

To reduce header bloat without requiring stateful dynamic table synchronization, BHTTP implements the first two foundational mechanisms of HPACK:

### 4.1 Mechanism 1: Static Table Name Indexing
The 10 most common HTTP header names are mapped to static 7-bit integer indices (1–10):

| Index | Header Name | Index | Header Name |
|:---:|:---|:---:|:---|
| **1** | `content-type` | **6** | `connection` |
| **2** | `content-length` | **7** | `date` |
| **3** | `host` | **8** | `server` |
| **4** | `user-agent` | **9** | `if-modified-since` |
| **5** | `accept` | **10** | `last-modified` |

When a header name matches an entry in the static table:
- **Descriptor Byte:** High bit is set to `1` (`0x80 | Index`).
- **Value:** Length-prefixed string: 2-octet big-endian length (`uint16`) followed by UTF-8 bytes.

### 4.2 Mechanism 2: Literal Names with Length-Prefixing
Headers whose names fall outside the static table are transmitted as literals:
- **Descriptor Byte:** Set to `0x00`.
- **Name Field:** 2-octet big-endian length (`uint16`) followed by raw UTF-8 name bytes.
- **Value Field:** 2-octet big-endian length (`uint16`) followed by raw UTF-8 value bytes.

Header blocks begin with a 2-octet `uint16` count of total headers.

---

## 5. Frame Type Specifications

### 5.1 Request Frame (`Type = 0x01`, `REQ`)
Transmitted by the client to request a server resource.

**Flags:**
- `0x01` (`END_STREAM`): Signals that no additional request data frames follow.

**Payload Layout:**
```text
+---------------+-------------------+-----------------------------------+
| Method (8)    | Path Length (16)  | Path String (Path Length octets)  |
+---------------+-------------------+-----------------------------------+
| Hdr Count(16) | Encoded Headers Block (Variable)                     ...
+---------------+-------------------------------------------------------+
```
- **Method (1 Octet):** `0x01` = GET, `0x02` = HEAD, `0x03` = POST.
- **Path Length (2 Octets):** Big-endian `uint16`.
- **Path String:** Resource URI (e.g. `/index.html`).
- **Headers:** Encoded as defined in Section 4.

### 5.2 Response Frame (`Type = 0x02`, `RESP`)
Transmitted by the server to reply to a client request.

**Flags:**
- `0x01` (`END_STREAM`): Signals completion of the response payload.

**Payload Layout:**
```text
+-------------------+-------------------+-------------------------------+
| Status Code (16)  | Hdr Count (16)    | Encoded Headers Block (Var)   |
+-------------------+-------------------+-------------------------------+
| Body Data (Length - Payload Offset)                                  ...
+-----------------------------------------------------------------------+
```
- **Status Code (2 Octets):** Big-endian `uint16` (e.g. `200`, `400`, `404`, `500`).
- **Headers:** Encoded as defined in Section 4.
- **Body Data:** Raw resource octets continuing to the end of the frame payload.

---

## 6. Error Handling & Connection Lifecycle

1. **200 OK:** Resource exists under root directory; payload carries file contents and headers (`content-type`, `content-length`).
2. **404 Not Found:** Resource does not exist; returns status 404 with descriptive diagnostic body.
3. **400 Bad Request:** Sent when:
   - Header or payload framing violates specification bounds.
   - Path traversal attempt detected (e.g. containing `..`).
4. **Connection Preservation:** The TCP connection remains open after every transaction. Both server and client MUST loop over the established connection. A client must never open a secondary TCP connection for sequential requests.
5. **Client Exit Codes:** `bcurl` terminates with exit code `0` on 2xx/3xx responses, and exits with a non-zero code on 4xx/5xx responses.
