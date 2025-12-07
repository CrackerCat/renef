---
title: Troubleshooting
layout: default
nav_order: 10
---

# Troubleshooting

## Server Won't Start

```bash
# Check if port is already in use
adb shell "lsof | grep renef_server"

# Kill existing instance
adb shell "killall renef_server"

# Check permissions
adb shell "chmod +x /data/local/tmp/renef_server"
```

## Injection Fails

```bash
# Check if process is running
adb shell "ps | grep <package>"

# Check SELinux status (may need permissive mode)
adb shell "getenforce"

# Try with root
adb root
```

## Port Forwarding Issues

```bash
# Remove existing forward
adb forward --remove tcp:1907

# Re-setup forwarding
adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit

# Verify forwarding
adb forward --list
```

## Hooks Not Triggering

1. Verify the offset is correct:
```lua
local exports = Module.exports("libc.so")
for i, exp in ipairs(exports) do
    if exp.name == "malloc" then
        print(string.format("malloc offset: 0x%x", exp.offset))
    end
end
```

2. Check if hook type matches:
```bash
# Try PLT/GOT hooking instead of trampoline
spawn com.example.app --hook=pltgot
```

3. Verify library is loaded:
```lua
local base = Module.find("libapp.so")
if not base then
    print("Library not loaded yet")
end
```

## Memory Access Violations

```lua
-- Always check addresses before reading
local addr = 0x12345678
local success, err = pcall(function()
    local data = Memory.read(addr, 16)
    print("Data: " .. data)
end)

if not success then
    print("Memory read failed: " .. err)
end
```

## Client Connection Issues

```bash
# Check server is running
adb shell "ps | grep renef_server"

# Check port forwarding
adb forward --list

# Test connection
telnet localhost 1907

# Check firewall (macOS)
sudo pfctl -d  # Disable firewall temporarily
```

## Script Execution Errors

```lua
-- Use pcall for error handling
local success, err = pcall(function()
    -- Your code here
    hook("libc.so", 0x12340, {
        onEnter = function(args)
            print("Called")
        end
    })
end)

if not success then
    print(RED .. "Error: " .. err .. RESET)
end
```

## Build Errors

```bash
# Missing NDK
export NDK=$HOME/Library/Android/sdk/ndk/26.3.11579264

# Capstone not found
make setup

# Lua not found
make setup-lua

# Clean and rebuild
make clean
make all
```

---

# Advanced Topics

## Custom Hook Types

Renef supports two hooking methods:

**Trampoline Hooking (Default)**
- Inline hooking at function entry
- Modifies first instructions to jump to hook
- Works for any function
- Slight performance overhead

**PLT/GOT Hooking**
- Modifies Procedure Linkage Table / Global Offset Table
- Intercepts dynamic library calls
- Faster than trampoline
- Only works for imported functions

```bash
# Use trampoline (default)
spawn com.example.app

# Use PLT/GOT
spawn com.example.app --hook=pltgot
```

## Session Keys

Renef uses session keys for security. Each injection generates a 32-character authentication key that must be prepended to agent commands. This is handled automatically by the client.

## Filter Syntax

Many commands support filtering with the `~` operator:

```bash
# List apps containing "google"
la~google

# List specific package
la~com.example.app
```

The filter is sent to the agent, which applies it to the output.

## Background Execution

```bash
# Start server in background on device
adb shell "nohup /data/local/tmp/renef_server > /dev/null 2>&1 &"

# Check if running
adb shell "ps | grep renef_server"
```

## Multiple Devices

```bash
# List devices
adb devices

# Specify device
./build/renef -d emulator-5554 -s com.example.app
```

---

# Performance Considerations

## Hook Overhead

- Trampoline hooks add ~10-50ns per call
- PLT/GOT hooks add ~5-10ns per call
- Lua execution in hooks adds additional overhead
- Keep hook logic minimal for high-frequency functions

## Memory Scanning

- `Memory.scan()` scans all readable .so regions
- Can be slow for large processes
- Use specific patterns to reduce matches
- Results are limited to 1000 matches by default

## Script Loading

- Scripts are executed in the target process context
- Large scripts may cause temporary freeze
- Use `l script1.lua script2.lua` to load multiple files efficiently
- Auto-watch mode (`-w`) starts monitoring immediately after loading

---

# API Comparison with Frida

Renef aims for API compatibility with Frida where possible:

| Frida | Renef | Notes |
|-------|-------|-------|
| `Interceptor.attach()` | `hook()` | Similar API, different syntax |
| `Module.load()` | `Module.find()` | Returns base address |
| `Module.enumerateExports()` | `Module.exports()` | Returns table |
| `Memory.scan()` | `Memory.scan()` | Similar functionality |
| `Memory.readByteArray()` | `Memory.read()` | Returns string |
| `Memory.writeByteArray()` | `Memory.patch()` | Handles mprotect |
| `Java.use()` | `hook(class, method, sig)` | Direct JNI hooking |
| `send()` | `print()` | Output to client |
