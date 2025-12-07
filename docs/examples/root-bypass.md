---
title: Root Detection Bypass
layout: default
parent: Real-World Examples
nav_order: 2
---

# Root Detection Bypass

```lua
-- Common root detection functions
local patterns = {
    "access",
    "fopen",
    "stat"
}

local libc_exports = Module.exports("libc.so")

-- Hook file access functions
for _, pattern in ipairs(patterns) do
    for i, exp in ipairs(libc_exports) do
        if exp.name == pattern then
            hook("libc.so", exp.offset, {
                onEnter = function(args)
                    local path_ptr = args[0]
                    local path = Memory.readString(path_ptr)

                    -- Block access to su and Magisk paths
                    if path and (
                        string.find(path, "/su") or
                        string.find(path, "magisk") or
                        string.find(path, "supersu")
                    ) then
                        print(RED .. "[ROOT] Blocked: " .. path .. RESET)
                        -- Return -1 (file not found)
                        args.block = true
                    end
                end,
                onLeave = function(retval)
                    if args.block then
                        return -1
                    end
                    return retval
                end
            })
        end
    end
end
```
