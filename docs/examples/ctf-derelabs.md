---
title: CTF - DereLabs 0x9
layout: default
parent: Real-World Examples
nav_order: 6
---

# CTF Challenge: DereLabs 0x9

This example demonstrates solving the [DereLabs](https://derelabs.com) 0x9 Android CTF challenge using Renef.

## Challenge Overview

The challenge requires hooking a native library function and modifying its return value to `1337`.

## Solution

```lua
-- Hook liba0x9.so first export and return 1337

local lib_name = "liba0x9.so"

print("Looking for " .. lib_name .. "...")

-- Check if library is already loaded
if not Module.find(lib_name) then
    print("[WARN] Library not loaded yet")
    print("[INFO] Trigger the function in the app first, then reload this script")
    return
end

print("Library found! Getting exports...")

local exports = Module.exports(lib_name)
if not exports or #exports == 0 then
    print("[ERROR] No exports in " .. lib_name)
    return
end

-- Hook first export
local func = exports[1]
print("Hooking: " .. func.name .. " @ 0x" .. string.format("%x", func.offset))

hook(lib_name, func.offset, {
    onEnter = function(args)
        print("[CALLED] " .. func.name)
    end,
    onLeave = function(retval)
        print("Original retval: " .. retval)
        return 1337
    end
})

print("Hook installed! Return value will be 1337")
```

## How It Works

1. **Find the library** - Check if `liba0x9.so` is loaded in memory
2. **Get exports** - Enumerate all exported functions
3. **Hook first export** - The challenge function is the first export
4. **Modify return value** - Return `1337` instead of original value

## Usage

```bash
# Attach to the challenge app
renef -p com.derelabs.challenge0x9

# Load the solution script
l ctf_0x9.lua

# Trigger the function in the app
# The flag should appear!
```

## Tips for CTF Challenges

- **Library not loaded?** - Some libraries load lazily. Trigger the relevant functionality first, then reload your script.
- **Find exports** - Use `Module.exports("libname.so")` to list all exported functions
- **Unknown offset?** - Hook by export name when possible, or use memory search to find patterns
- **Debug output** - Add `print()` statements in `onEnter`/`onLeave` to understand function behavior
