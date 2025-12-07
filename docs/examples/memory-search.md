---
title: Interactive Memory Search
layout: default
parent: Real-World Examples
nav_order: 5
---

# Interactive Memory Search

```lua
-- Search for specific values in memory
print(YELLOW .. "Scanning for int32 value: 12345..." .. RESET)

-- Convert int to bytes (little-endian)
local value = 12345
local b1 = value & 0xFF
local b2 = (value >> 8) & 0xFF
local b3 = (value >> 16) & 0xFF
local b4 = (value >> 24) & 0xFF

local pattern = string.char(b1, b2, b3, b4)
local results = Memory.scan(pattern)

print(GREEN .. "Found " .. #results .. " matches:" .. RESET)
for i, result in ipairs(results) do
    print(string.format("  [%d] %s + 0x%x (addr: 0x%x)",
          i, result.library, result.offset,
          Module.find(result.library) + result.offset))
end
```
