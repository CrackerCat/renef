---
title: Thread API
layout: default
parent: Lua API Reference
nav_order: 4
---

# Thread API

## `Thread.call(address, args...)`

Call a function at given address with arguments.

```lua
local malloc_addr = Module.find("libc.so") + 0x12340
local ptr = Thread.call(malloc_addr, 0x100)
print(string.format("Allocated: 0x%x", ptr))
```

**Returns:** Function return value
