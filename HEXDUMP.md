# Annotated Hexdump: BHTTP Protocol Exchange

This document provides a byte-by-byte annotated hexdump for a complete BHTTP request and response transaction.

---

## 1. Request Frame (Client to Server)

### Hexdump
```text
0000  00 00 33 01 01 00 00 00 01 01 00 0b 2f 69 6e 64   |..3........./ind|
0010  65 78 2e 68 74 6d 6c 00 03 83 00 0e 6c 6f 63 61   |ex.html.....loca|
0020  6c 68 6f 73 74 3a 39 30 30 30 84 00 09 62 63 75   |lhost:9000...bcu|
0030  72 6c 2f 31 2e 30 85 00 03 2a 2f 2a               |rl/1.0...*/*|
```

### Field Breakdown & Byte-by-Byte Annotation

| Offset (Hex) | Offset (Dec) | Raw Bytes | Field Name | Type / Width | Value / Interpretation | Rationale & Description |
|---|---|---|---|---|---|---|
| `0x0000 - 0x0002` | `0 - 2` | `00 00 33` | **Payload Length** | uint24 (3 bytes) | `51` | Frame payload size is 51 bytes (excluding 9-byte header). |
| `0x0003` | `3` | `01` | **Frame Type** | uint8 (1 byte) | `0x01` (`REQ`) | Indicates a Client Request frame. |
| `0x0004` | `4` | `01` | **Flags** | uint8 (1 byte) | `0x01` (`END_STREAM`) | Bit 0 is set: signals end of client request data. |
| `0x0005 - 0x0008` | `5 - 8` | `00 00 00 01` | **Stream ID** | uint32 (4 bytes) | `1` | Stream identifier 1 in big-endian network byte order. |
| `0x0009` | `9` | `01` | **Method** | uint8 (1 byte) | `0x01` (`GET`) | HTTP Method code (`0x01 = GET`, `0x02 = HEAD`, `0x03 = POST`). |
| `0x000A - 0x000B` | `10 - 11` | `00 0b` | **Path Length** | uint16 (2 bytes) | `11` | UTF-8 URI path length is 11 bytes. |
| `0x000C - 0x0016` | `12 - 22` | `2f 69 6e 64 65 78 2e 68 74 6d 6c` | **Path** | String[11] | `"/index.html"` | ASCII bytes for the requested target path. |
| `0x0017 - 0x0018` | `23 - 24` | `00 03` | **Header Count** | uint16 (2 bytes) | `3` | Exactly 3 headers follow in the payload. |
| `0x0019` | `25` | `83` | **H1 Descriptor** | uint8 (1 byte) | Index `3` (`host`) | Bit 7 = 1 (`0x80`), static table index 3 (`host`). |
| `0x001A - 0x001B` | `26 - 27` | `00 0e` | **H1 Value Len** | uint16 (2 bytes) | `14` | Length of value string is 14 bytes. |
| `0x001C - 0x0029` | `28 - 41` | `6c 6f 63 61 ... 30 30` | **H1 Value** | String[14] | `"localhost:9000"` | ASCII bytes for host header value. |
| `0x002A` | `42` | `84` | **H2 Descriptor** | uint8 (1 byte) | Index `4` (`user-agent`) | Bit 7 = 1 (`0x80`), static table index 4 (`user-agent`). |
| `0x002B - 0x002C` | `43 - 44` | `00 09` | **H2 Value Len** | uint16 (2 bytes) | `9` | Length of value string is 9 bytes. |
| `0x002D - 0x0035` | `45 - 53` | `62 63 75 72 6c 2f 31 2e 30` | **H2 Value** | String[9] | `"bcurl/1.0"` | ASCII bytes for user-agent value. |
| `0x0036` | `54` | `85` | **H3 Descriptor** | uint8 (1 byte) | Index `5` (`accept`) | Bit 7 = 1 (`0x80`), static table index 5 (`accept`). |
| `0x0037 - 0x0038` | `55 - 56` | `00 03` | **H3 Value Len** | uint16 (2 bytes) | `3` | Length of value string is 3 bytes. |
| `0x0039 - 0x003B` | `57 - 59` | `2a 2f 2a` | **H3 Value** | String[3] | `"*/*"` | ASCII bytes for accept header value. |

**Total Frame Length**: 60 bytes (9-byte header + 51-byte payload).

---

## 2. Response Frame (Server to Client)

### Hexdump
```text
0000  00 00 43 02 01 00 00 00 01 00 c8 00 04 81 00 09   |..C.............|
0010  74 65 78 74 2f 68 74 6d 6c 82 00 02 32 30 88 00   |text/html...20..|
0020  0a 62 73 65 72 76 65 2f 31 2e 30 86 00 0a 6b 65   |.bserve/1.0...ke|
0030  65 70 2d 61 6c 69 76 65 3c 68 31 3e 48 65 6c 6c   |ep-alive<h1>Hell|
0040  6f 20 57 6f 72 6c 64 3c 2f 68 31 3e               |o World</h1>|
```

### Field Breakdown & Byte-by-Byte Annotation

| Offset (Hex) | Offset (Dec) | Raw Bytes | Field Name | Type / Width | Value / Interpretation | Rationale & Description |
|---|---|---|---|---|---|---|
| `0x0000 - 0x0002` | `0 - 2` | `00 00 43` | **Payload Length** | uint24 (3 bytes) | `67` | Frame payload size is 67 bytes (excluding 9-byte header). |
| `0x0003` | `3` | `02` | **Frame Type** | uint8 (1 byte) | `0x02` (`RESP`) | Indicates a Server Response frame. |
| `0x0004` | `4` | `01` | **Flags** | uint8 (1 byte) | `0x01` (`END_STREAM`) | Bit 0 = 1: terminates the stream payload. |
| `0x0005 - 0x0008` | `5 - 8` | `00 00 00 01` | **Stream ID** | uint32 (4 bytes) | `1` | Matches client request stream ID 1. |
| `0x0009 - 0x000A` | `9 - 10` | `00 c8` | **Status Code** | uint16 (2 bytes) | `200` | HTTP Status 200 OK (`0x00C8 = 200`). |
| `0x000B - 0x000C` | `11 - 12` | `00 04` | **Header Count** | uint16 (2 bytes) | `4` | Exactly 4 response headers follow. |
| `0x000D` | `13` | `81` | **H1 Descriptor** | uint8 (1 byte) | Index `1` (`content-type`) | Bit 7 = 1 (`0x80`), static table index 1. |
| `0x000E - 0x000F` | `14 - 15` | `00 09` | **H1 Value Len** | uint16 (2 bytes) | `9` | Length of value string is 9 bytes. |
| `0x0010 - 0x0018` | `16 - 24` | `74 65 78 74 2f 68 74 6d 6c` | **H1 Value** | String[9] | `"text/html"` | ASCII bytes for MIME type. |
| `0x0019` | `25` | `82` | **H2 Descriptor** | uint8 (1 byte) | Index `2` (`content-length`)| Bit 7 = 1 (`0x80`), static table index 2. |
| `0x001A - 0x001B` | `26 - 27` | `00 02` | **H2 Value Len** | uint16 (2 bytes) | `2` | Length of content-length string is 2 bytes. |
| `0x001C - 0x001D` | `28 - 29` | `32 30` | **H2 Value** | String[2] | `"20"` | ASCII characters '2' '0' (20 bytes body). |
| `0x001E` | `30` | `88` | **H3 Descriptor** | uint8 (1 byte) | Index `8` (`server`) | Bit 7 = 1 (`0x80`), static table index 8. |
| `0x001F - 0x0020` | `31 - 32` | `00 0a` | **H3 Value Len** | uint16 (2 bytes) | `10` | Length of server string is 10 bytes. |
| `0x0021 - 0x002A` | `33 - 42` | `62 73 65 72 76 65 2f 31 2e 30` | **H3 Value** | String[10] | `"bserve/1.0"` | ASCII bytes for server name. |
| `0x002B` | `43` | `86` | **H4 Descriptor** | uint8 (1 byte) | Index `6` (`connection`) | Bit 7 = 1 (`0x80`), static table index 6. |
| `0x002C - 0x002D` | `44 - 45` | `00 0a` | **H4 Value Len** | uint16 (2 bytes) | `10` | Length of connection string is 10 bytes. |
| `0x002E - 0x0037` | `46 - 55` | `6b 65 65 ... 69 76 65` | **H4 Value** | String[10] | `"keep-alive"` | ASCII bytes for keep-alive. |
| `0x0038 - 0x004B` | `56 - 75` | `3c 68 31 3e ... 3c 2f 68 31 3e` | **Body Payload** | Bytes[20] | `"<h1>Hello World</h1>"` | Raw file body bytes (`20` bytes). |

**Total Frame Length**: 76 bytes (9-byte header + 67-byte payload).
