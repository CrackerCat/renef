---
title: Scripting Guide
layout: default
nav_order: 8
---

# Scripting Guide

## Basic Hook Example

```lua
-- Hook malloc
local libc_base = Module.find("libc.so")
local malloc_offset = 0x12340

hook("libc.so", malloc_offset, {
    onEnter = function(args)
        local size = args[0]
        print(GREEN .. "[+] malloc(" .. size .. ")" .. RESET)
    end,

    onLeave = function(retval)
        print(GREEN .. "[-] malloc returned: " ..
              string.format("0x%x", retval) .. RESET)
        return retval
    end
})
```

## Java Method Hook Example

```lua
-- Hook MainActivity.getSecretValue()
hook("io/byterialab/moduletest/MainActivity",
     "getSecretValue",
     "(Ljava/lang/String;)Ljava/lang/String;", {
    onEnter = function(args)
        print(CYAN .. "MainActivity.getSecretValue() called!" .. RESET)
        print("  class: " .. tostring(args.class))
        print(string.format("  this: 0x%x", args[0]))
        print(string.format("  key param: 0x%x", args[1]))
    end
})
```

## Memory Scanning Example

```lua
-- Scan for "Java" string signature
local pattern = "\x4A\x61\x76\x61"  -- "Java" in hex
local results = Memory.scan(pattern)

print(YELLOW .. "Found " .. #results .. " matches:" .. RESET)
for i, result in ipairs(results) do
    print(string.format("[%d] %s + 0x%x", i, result.library, result.offset))
end
```

## Memory Patching Example

```lua
-- Find and patch a function
local base = Module.find("libapp.so")
local target = base + 0x5678

-- ARM64 NOP (nop instruction)
local nop = "\x1f\x20\x03\xd5"

-- Patch 4 NOPs
local patch = nop .. nop .. nop .. nop

local success = Memory.patch(target, patch)
if success then
    print(GREEN .. "✓ Patched 16 bytes at " ..
          string.format("0x%x", target) .. RESET)
else
    print(RED .. "✗ Patch failed" .. RESET)
end
```

## Finding Exported Functions

```lua
-- Find malloc in libc
local exports = Module.exports("libc.so")
local malloc_offset = nil

for i, exp in ipairs(exports) do
    if exp.name == "malloc" then
        malloc_offset = exp.offset
        break
    end
end

if malloc_offset then
    print(string.format("malloc @ 0x%x", malloc_offset))

    -- Hook it
    hook("libc.so", malloc_offset, {
        onEnter = function(args)
            print("malloc size: " .. args[0])
        end
    })
end
```

## Multiple Hooks Script

```lua
print(CYAN .. "=== Setting up hooks ===" .. RESET)

-- Hook malloc
hook("libc.so", 0x12340, {
    onEnter = function(args)
        print("[malloc] size: " .. args[0])
    end
})

-- Hook free
hook("libc.so", 0x12380, {
    onEnter = function(args)
        print(string.format("[free] ptr: 0x%x", args[0]))
    end
})

-- Hook custom function
local app_base = Module.find("libapp.so")
if app_base then
    hook("libapp.so", 0x5000, {
        onEnter = function(args)
            print("[custom_func] arg0: " .. args[0])
        end,
        onLeave = function(retval)
            print("[custom_func] returning: " .. retval)
            return retval
        end
    })
end

print(GREEN .. "✓ All hooks installed" .. RESET)
```
