---
title: Memory API
layout: default
parent: Lua API Reference
nav_order: 2
---

# Memory API

## `Memory.scan(pattern)`

Scan memory for byte pattern. Returns all matches in readable .so regions.

```lua
local pattern = "\xDE\xAD\xBE\xEF"
local results = Memory.scan(pattern)

for i, result in ipairs(results) do
    print(string.format("[%d] %s + 0x%x", i, result.library, result.offset))
    print("    Hex: " .. result.hex)
    print("    ASCII: " .. result.ascii)
    print(string.format("    Address: 0x%x", result.offset))
end
```

**Returns:** Table of results with fields:
- `library` - Library path
- `offset` - Offset from library base
- `hex` - Hex dump with context (pattern highlighted)
- `ascii` - ASCII representation
- `address` - Absolute address (for internal use)

## `Memory.patch(address, bytes)`

Patch memory at address with raw bytes.

```lua
local addr = 0x7f8a1c2b0
local patch = "\x1f\x20\x03\xd5"  -- ARM64 NOP

local success, err = Memory.patch(addr, patch)
if success then
    print("Patched successfully")
else
    print("Patch failed: " .. err)
end
```

**Returns:** `true` on success, or `false, error_message` on failure

**Note:** Automatically handles mprotect() to make memory writable.

## `Memory.read(address, size)`

Read raw bytes from memory.

```lua
local addr = 0x7f8a1c2b0
local data = Memory.read(addr, 16)

-- Convert to hex
for i = 1, #data do
    print(string.format("%02x", string.byte(data, i)))
end
```

**Returns:** String containing raw bytes (max 4096 bytes)

## `Memory.readString(address)`

Read null-terminated string from memory.

```lua
local str_ptr = 0x7f8a1c2b0
local str = Memory.readString(str_ptr)
print("String: " .. str)
```

**Returns:** String up to null terminator (max 1024 bytes) or `nil` if address is 0
