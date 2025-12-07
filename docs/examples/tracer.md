---
title: Function Call Tracer
layout: default
parent: Real-World Examples
nav_order: 4
---

# Function Call Tracer

```lua
-- Trace all calls to a specific library
local target_lib = "libapp.so"
local base = Module.find(target_lib)

if not base then
    print(RED .. "Library not found: " .. target_lib .. RESET)
    return
end

-- Get all exports
local exports = Module.exports(target_lib)
local hook_count = 0

-- Hook first 10 exports for demonstration
for i, exp in ipairs(exports) do
    if i > 10 then break end

    hook(target_lib, exp.offset, {
        onEnter = function(args)
            print(CYAN .. "[TRACE] " .. exp.name .. "(" ..
                  string.format("0x%x, 0x%x, 0x%x", args[0], args[1], args[2]) ..
                  ")" .. RESET)
        end,
        onLeave = function(retval)
            print(CYAN .. "    └─> " .. string.format("0x%x", retval) .. RESET)
            return retval
        end
    })

    hook_count = hook_count + 1
end

print(GREEN .. "✓ Installed " .. hook_count .. " trace hooks" .. RESET)
```
