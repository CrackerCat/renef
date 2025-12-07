---
title: Console API
layout: default
parent: Lua API Reference
nav_order: 5
---

# Console API

## `console.log(message)`

Print message to console (same as `print()`).

```lua
console.log("Hello from Lua")
```

## `print(...)`

Standard Lua print, outputs to renef client.

```lua
print("Value:", 42)
print(string.format("Hex: 0x%x", 255))
```

## Global Color Codes

Available color codes for terminal output:

```lua
print(RED .. "Error!" .. RESET)
print(GREEN .. "Success!" .. RESET)
print(YELLOW .. "Warning" .. RESET)
print(BLUE .. "Info" .. RESET)
print(CYAN .. "Debug" .. RESET)
print(MAGENTA .. "Trace" .. RESET)
print(WHITE .. "Normal" .. RESET)
```

Available colors:
- `RESET` - Reset to default
- `RED`, `GREEN`, `YELLOW`, `BLUE`, `MAGENTA`, `CYAN`, `WHITE`
