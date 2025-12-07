---
title: Script Execution
layout: default
parent: Command Reference
nav_order: 3
---

# Script Execution

## `exec <lua_code>`

Execute Lua code in target process. If you type code without a known command prefix, it's automatically wrapped with `exec`.

```bash
# Explicit
exec print("Hello")

# Implicit (auto-wrapped)
print("Hello")
Module.list()
```

**Output:**
```
Hello
✓ Lua executed
```

## `l <file> [file2 ...] [-w|--watch]`

Load and execute one or more Lua scripts from files. Use `-w` or `--watch` to enable auto-watch mode after loading.

```bash
# Load single script
l hook.lua

# Load multiple scripts
l init.lua hooks.lua utils.lua

# Load with auto-watch (starts watching after loading)
l hook.lua -w
l script1.lua script2.lua --watch
```

**Output:**
```
Loading 2 script(s) (auto-watch enabled):
  ✓ script1.lua
  ✓ script2.lua

[Auto-watch enabled - Press Ctrl+C to exit]
📡 Watching hook output...
```
