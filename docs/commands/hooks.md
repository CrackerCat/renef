---
title: Hook Management
layout: default
parent: Command Reference
nav_order: 5
---

# Hook Management

## `hooks`

List all active hooks in the target process.

```bash
hooks
```

**Output:**
```
Active hooks:
  [0] libc.so + 0x12340 (malloc)
  [1] libapp.so + 0x5678 (custom_func)
```

## `unhook <id|all>`

Remove hook(s) by ID or remove all hooks.

```bash
# Remove hook by ID
unhook 0

# Remove all hooks
unhook all
```

**Output:**
```
Hook removed
```

## `hookgen <args>`

Generate Lua hook template code.

```bash
# Generate hook for library + offset
hookgen libc.so 0x12340

# Generate hook for library + symbol
hookgen libc.so malloc

# Search symbol in common libraries
hookgen malloc
```

**Output:**
```lua
hook("libc.so", 0x12340, {
    onEnter = function(args)
        print("[+] libc.so+0x12340 called")
        print("    arg0: " .. string.format("0x%x", args[0]))
        print("    arg1: " .. string.format("0x%x", args[1]))
    end,
    onLeave = function(retval)
        print("[-] Returning: " .. string.format("0x%x", retval))
        return retval
    end
})
```
