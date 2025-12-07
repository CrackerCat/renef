---
title: Module API
layout: default
parent: Lua API Reference
nav_order: 1
---

# Module API

## `Module.list()`

Get list of all loaded modules as a formatted string.

```lua
local libs = Module.list()
print(libs)
```

**Returns:** String containing all loaded libraries

## `Module.find(library_name)`

Find base address of a loaded library.

```lua
local base = Module.find("libc.so")
if base then
    print(string.format("libc.so base: 0x%x", base))
end
```

**Returns:** `number` (base address) or `nil` if not found

## `Module.exports(library_name)`

Get exported functions from a library.

```lua
local exports = Module.exports("libc.so")
if exports then
    for i, exp in ipairs(exports) do
        print(string.format("%s @ 0x%x", exp.name, exp.offset))
    end
end
```

**Returns:** Table of exports with `name` and `offset` fields, or `nil`

**Example output:**
```
malloc @ 0x12340
free @ 0x12380
calloc @ 0x123c0
```
