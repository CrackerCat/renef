---
title: Memory Operations
layout: default
parent: Command Reference
nav_order: 4
---

# Memory Operations

## `ms <hex_pattern>`

Scan memory for hex pattern in all readable .so regions.

```bash
# Scan for bytes
ms DEADBEEF

# Scan for Java string signature
ms 4A617661
```

**Output:**
```
Found 2 match(es):
------------------------------------------------------------
[1] /system/lib64/libc.so + 0x1a2b0 (addr: 0x7f8a1c2b0)
    Hex:   01 02 03 [DE AD BE EF] 90 90 90 90
    ASCII: ....[....]....
[2] /data/app/com.example/lib/arm64/libapp.so + 0x5f80 (addr: 0x7f9b3f80)
    Hex:   FF FF [DE AD BE EF] 00 00
    ASCII: ..[....]..
------------------------------------------------------------
```

## `msi <hex_pattern>`

Interactive memory scan with TUI. Allows you to select results and perform actions (dump, patch, watch, copy address).

```bash
msi DEADBEEF
```

Opens interactive interface:
```
Memory Scan Results (2 matches)
────────────────────────────────────────
[1] libc.so + 0x1a2b0
[2] libapp.so + 0x5f80
────────────────────────────────────────
Actions: [d]ump [p]atch [w]atch [c]opy [q]uit
```

## `md <address> <size> [-d]`

Dump memory at address. Use `-d` flag to disassemble as ARM64 code.

```bash
# Hex dump
md 0x7f8a1c2b0 256

# Disassemble
md 0x7f8a1c2b0 64 -d
```

**Output (hex dump):**
```
Memory at 0x7f8a1c2b0 (256 bytes):
0x7f8a1c2b0:  01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10  |................|
0x7f8a1c2c0:  de ad be ef 90 90 90 90 00 00 00 00 ff ff ff ff  |................|
```

**Output (disassembly):**
```
Memory at 0x7f8a1c2b0 (64 bytes):
0x7f8a1c2b0:  stp x29, x30, [sp, #-0x10]!
0x7f8a1c2b4:  mov x29, sp
0x7f8a1c2b8:  bl #0x7f8a1d000
0x7f8a1c2bc:  ldp x29, x30, [sp], #0x10
0x7f8a1c2c0:  ret
```
