# RENEF Complete Documentation

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture](#architecture)
3. [Installation & Build](#installation--build)
4. [Getting Started](#getting-started)
5. [Command Reference](#command-reference)
6. [Lua API Reference](#lua-api-reference)
7. [Scripting Guide](#scripting-guide)
8. [Real-World Examples](#real-world-examples)
9. [Troubleshooting](#troubleshooting)

---

## Introduction

RENEF is a dynamic instrumentation toolkit for Android ARM64 applications, focused primarily on native code analysis. It provides runtime manipulation capabilities through Lua scripting, allowing you to hook native functions, scan and patch memory, and analyze running processes.

The toolkit uses memfd-based injection (no ptrace required) and includes an embedded Lua 5.4 engine for scripting. It supports both PLT/GOT and inline trampoline hooking via Capstone disassembly engine.

RENEF is designed as a learning project and practical tool for security research and reverse engineering on Android ARM64 platforms.

> **Note:** This project was inspired by Frida and Radare2. Special thanks to their developers for creating such excellent tools that shaped the design of RENEF.

### Key Features

- **ARM64 Function Hooking** - PLT/GOT and inline trampoline hooking
- **Lua Scripting** - Frida-like API with Module, Memory, Hook, Thread
- **Process Injection** - memfd + shellcode injection into running processes
- **Memory Operations** - Scan, read, write, patch memory
- **Live Scripting** - Load multiple scripts at runtime with auto-watch
- **Interactive TUI** - Memory scanner with interactive interface
- **Java Hooks** - Hook Java methods via JNI

---

## Architecture

### Components

**Client (build/renef)**
- Native macOS/Linux CLI application
- Interactive REPL with tab completion
- Connects to server via TCP (localhost:1907)

**Server (renef_server)**
- ARM64 Android binary
- Listens on Unix Domain Socket (com.android.internal.os.RuntimeInit)
- Performs process injection via memfd + shellcode
- Routes commands to injected payload

**Payload (libagent.so)**
- Shared library injected into target
- Contains Lua 5.4 engine
- Implements hooking engine (Capstone-based)
- Executes user scripts in process context

### Communication Flow

```
Host Machine                          Android Device
┌─────────────┐                      ┌──────────────┐
│   Client    │ ───TCP:1907───────> │    Server    │
│ (renef CLI) │  (adb forwarded)     │              │
└─────────────┘                      └──────┬───────┘
                                            │ memfd+shellcode
                                            │ injection
                                            ▼
                                     ┌──────────────┐
                                     │   Payload    │
                                     │ libagent.so  │
                                     │              │
                                     │ ┌──────────┐ │
                                     │ │  Lua 5.4 │ │
                                     │ └──────────┘ │
                                     └──────────────┘
                Target Process Memory
```

### Injection Method

RENEF uses a sophisticated memfd-based injection technique:

1. **memfd_create()** - Server creates memfd from SO file
2. **Stage 1 Shellcode** - Hijacks malloc() temporarily
3. **Trigger** - Waits for target to call malloc()
4. **Stage 2 Shellcode** - Calls dlopen("/proc/self/fd/X") to load payload
5. **Restoration** - Restores original malloc() and continues execution

This approach does **not** use ptrace and works on most Android devices.

---

## Installation & Build

### Prerequisites

```bash
# Android NDK
export NDK=$HOME/Library/Android/sdk/ndk/26.3.11579264

# CMake
brew install cmake  # macOS
# or
sudo apt-get install cmake  # Linux

# ADB (Android SDK Platform Tools)
```

### Building

```bash
# Clone repository
git clone <repo_url>
cd renef

# Setup dependencies (Lua + Capstone)
make setup

# Build everything (client + server + payload)
make all

# Or build in release mode (optimized, stripped)
make release

# Deploy to Android device
make deploy

# Deploy and setup port forwarding
make install
```

### Build Targets

- `make all` - Build client, server, and payload
- `make client` - Build only the CLI client
- `make server` - Build only the Android server
- `make payload` - Build only the agent payload (libagent.so)
- `make setup` - Setup Lua and Capstone dependencies
- `make deploy` - Push server and payload to /data/local/tmp/
- `make install` - Deploy and setup adb port forwarding
- `make clean` - Clean build artifacts
- `make release` - Build in release mode (optimized)
- `make debug` - Build in debug mode (symbols + logging)

### Deployment

After building, deploy to your Android device:

```bash
# Deploy server and payload
make deploy

# Start server on device
adb shell /data/local/tmp/renef_server

# In another terminal, run client
./build/renef
```

---

## Getting Started

### Quick Start

```bash
# 1. Start server on Android device
adb shell /data/local/tmp/renef_server

# 2. Run client on host
./build/renef

# 3. Spawn an app
renef> spawn com.example.app

# 4. List installed apps (with filter)
renef> la~example

# 5. Execute Lua code
renef> print("Hello from " .. _VERSION)

# 6. Load and execute a script
renef> l scripts/hook.lua

# 7. Load multiple scripts with auto-watch
renef> l script1.lua script2.lua -w
```

### Command-line Options

```bash
# Spawn app and load script
./build/renef -s com.example.app -l hook.lua

# Attach to PID with PLT/GOT hooking
./build/renef -a 1234 --hook pltgot -l script.lua

# Spawn with trampoline hooking (default)
./build/renef -s com.example.app --hook trampoline

# Specify device ID
./build/renef -d emulator-5554 -s com.example.app
```

---

## Command Reference

### Process Management

#### `spawn <package> [--hook=type]`

Spawn a new process and inject payload.

```bash
# Spawn with default trampoline hooking
spawn com.example.app

# Spawn with PLT/GOT hooking
spawn com.example.app --hook=pltgot
```

**Output:**
```
OK 12345
```

#### `attach <pid> [--hook=type]`

Attach to running process by PID.

```bash
# Attach to PID
attach 1234

# Attach with PLT/GOT hooking
attach 1234 --hook=pltgot
```

**Output:**
```
OK
```

### Application Management

#### `la [~filter]`

List installed applications on device. Supports filtering with `~` operator.

```bash
# List all apps
la

# Filter by package name
la~google

# Filter for specific app
la~com.example
```

**Output:**
```
package:com.google.android.gms
package:com.google.android.gsf
package:com.google.android.telephony.satellite
package:com.android.vending
```

### Script Execution

#### `exec <lua_code>`

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

#### `l <file> [file2 ...] [-w|--watch]`

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

### Memory Operations

#### `ms <hex_pattern>`

Scan memory for hex pattern in all readable .so regions.

```bash
# Scan for bytes
ms DEADBEEF

# Scan for Java string signature
ms 4A617661
```

**Output:**
```
Found 2 match(es):
------------------------------------------------------------
[1] /system/lib64/libc.so + 0x1a2b0 (addr: 0x7f8a1c2b0)
    Hex:   01 02 03 [DE AD BE EF] 90 90 90 90
    ASCII: ....[....]....
[2] /data/app/com.example/lib/arm64/libapp.so + 0x5f80 (addr: 0x7f9b3f80)
    Hex:   FF FF [DE AD BE EF] 00 00
    ASCII: ..[....]..
------------------------------------------------------------
```

#### `msi <hex_pattern>`

Interactive memory scan with TUI. Allows you to select results and perform actions (dump, patch, watch, copy address).

```bash
msi DEADBEEF
```

Opens interactive interface:
```
Memory Scan Results (2 matches)
────────────────────────────────────────
[1] libc.so + 0x1a2b0
[2] libapp.so + 0x5f80
────────────────────────────────────────
Actions: [d]ump [p]atch [w]atch [c]opy [q]uit
```

#### `md <address> <size> [-d]`

Dump memory at address. Use `-d` flag to disassemble as ARM64 code.

```bash
# Hex dump
md 0x7f8a1c2b0 256

# Disassemble
md 0x7f8a1c2b0 64 -d
```

**Output (hex dump):**
```
Memory at 0x7f8a1c2b0 (256 bytes):
0x7f8a1c2b0:  01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10  |................|
0x7f8a1c2c0:  de ad be ef 90 90 90 90 00 00 00 00 ff ff ff ff  |................|
```

**Output (disassembly):**
```
Memory at 0x7f8a1c2b0 (64 bytes):
0x7f8a1c2b0:  stp x29, x30, [sp, #-0x10]!
0x7f8a1c2b4:  mov x29, sp
0x7f8a1c2b8:  bl #0x7f8a1d000
0x7f8a1c2bc:  ldp x29, x30, [sp], #0x10
0x7f8a1c2c0:  ret
```

### Hook Management

#### `hooks`

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

#### `unhook <id|all>`

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

#### `hookgen <args>`

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

### Real-time Monitoring

#### `watch [address]`

Watch hook output in real-time. Press 'q' to exit watch mode.

```bash
# Watch all hooks
watch

# Watch specific address (if supported)
watch 0x7f8a1c2b0
```

**Output:**
```
📡 Watching hook output... (waiting for hooks to trigger)
(Press 'q' to exit watch mode)

[+] malloc called
    size: 0x100
[-] Returning: 0x7f9b4000
[+] free called
    ptr: 0x7f9b4000
```

### Utility Commands

#### `help`

Show available commands.

#### `q`

Exit renef client.

#### `clear`

Clear the terminal screen.

#### `color <theme>=<COLOR>`

Set terminal color theme.

```bash
# List current theme
color

# Set prompt color
color prompt=CYAN

# Set response color
color response=GREEN
```

---

## Lua API Reference

### Module API

#### `Module.list()`

Get list of all loaded modules as a formatted string.

```lua
local libs = Module.list()
print(libs)
```

**Returns:** String containing all loaded libraries

#### `Module.find(library_name)`

Find base address of a loaded library.

```lua
local base = Module.find("libc.so")
if base then
    print(string.format("libc.so base: 0x%x", base))
end
```

**Returns:** `number` (base address) or `nil` if not found

#### `Module.exports(library_name)`

Get exported functions from a library.

```lua
local exports = Module.exports("libc.so")
if exports then
    for i, exp in ipairs(exports) do
        print(string.format("%s @ 0x%x", exp.name, exp.offset))
    end
end
```

**Returns:** Table of exports with `name` and `offset` fields, or `nil`

**Example output:**
```
malloc @ 0x12340
free @ 0x12380
calloc @ 0x123c0
```

### Memory API

#### `Memory.scan(pattern)`

Scan memory for byte pattern. Returns all matches in readable .so regions.

```lua
local pattern = "\xDE\xAD\xBE\xEF"
local results = Memory.scan(pattern)

for i, result in ipairs(results) do
    print(string.format("[%d] %s + 0x%x", i, result.library, result.offset))
    print("    Hex: " .. result.hex)
    print("    ASCII: " .. result.ascii)
    print(string.format("    Address: 0x%x", result.offset))
end
```

**Returns:** Table of results with fields:
- `library` - Library path
- `offset` - Offset from library base
- `hex` - Hex dump with context (pattern highlighted)
- `ascii` - ASCII representation
- `address` - Absolute address (for internal use)

#### `Memory.patch(address, bytes)`

Patch memory at address with raw bytes.

```lua
local addr = 0x7f8a1c2b0
local patch = "\x1f\x20\x03\xd5"  -- ARM64 NOP

local success, err = Memory.patch(addr, patch)
if success then
    print("Patched successfully")
else
    print("Patch failed: " .. err)
end
```

**Returns:** `true` on success, or `false, error_message` on failure

**Note:** Automatically handles mprotect() to make memory writable.

#### `Memory.read(address, size)`

Read raw bytes from memory.

```lua
local addr = 0x7f8a1c2b0
local data = Memory.read(addr, 16)

-- Convert to hex
for i = 1, #data do
    print(string.format("%02x", string.byte(data, i)))
end
```

**Returns:** String containing raw bytes (max 4096 bytes)

#### `Memory.readString(address)`

Read null-terminated string from memory.

```lua
local str_ptr = 0x7f8a1c2b0
local str = Memory.readString(str_ptr)
print("String: " .. str)
```

**Returns:** String up to null terminator (max 1024 bytes) or `nil` if address is 0

### Hook API

#### `hook(library, offset, callbacks)`

Hook a native function by library name and offset.

```lua
hook("libc.so", 0x12340, {
    onEnter = function(args)
        print("[+] malloc called")
        print(string.format("    size: 0x%x", args[0]))

        -- Modify argument
        args[0] = 0x200
    end,

    onLeave = function(retval)
        print(string.format("[-] malloc returning: 0x%x", retval))

        -- Modify return value
        return retval + 0x100
    end
})
```

**Parameters:**
- `library` - Library name (e.g., "libc.so")
- `offset` - Offset from library base (hex number)
- `callbacks` - Table with `onEnter` and/or `onLeave` functions

**onEnter arguments:**
- `args` - Table with function arguments (args[0], args[1], ...)
- Arguments can be modified by assignment

**onLeave arguments:**
- `retval` - Return value from function
- Return a value to replace the original return value

#### `hook(class, method, signature, callbacks)`

Hook a Java method via JNI.

```lua
hook("com/example/MainActivity", "getSecret", "(Ljava/lang/String;)Ljava/lang/String;", {
    onEnter = function(args)
        print("[+] MainActivity.getSecret() called")
        print(string.format("    class: %s", tostring(args.class)))
        print(string.format("    this: 0x%x", args[0]))
        print(string.format("    param0: 0x%x", args[1]))
    end
})
```

**Parameters:**
- `class` - Class name with `/` separators (e.g., "java/lang/String")
- `method` - Method name
- `signature` - JNI signature (e.g., "(I)V")
- `callbacks` - Table with `onEnter` and/or `onLeave` functions

**Java hook arguments:**
- `args.class` - Class object
- `args[0]` - `this` pointer (for instance methods)
- `args[1..n]` - Method arguments

### JNI Type Wrappers

For Java hooks, use these wrappers to create properly typed arguments:

#### `JNI.string(value)`

```lua
local jstr = JNI.string("Hello")
```

#### `JNI.int(value)`

```lua
local jint = JNI.int(42)
```

#### `JNI.long(value)`

```lua
local jlong = JNI.long(123456789)
```

#### `JNI.boolean(value)`

```lua
local jbool = JNI.boolean(true)
```

### Thread API

#### `Thread.call(address, args...)`

Call a function at given address with arguments.

```lua
local malloc_addr = Module.find("libc.so") + 0x12340
local ptr = Thread.call(malloc_addr, 0x100)
print(string.format("Allocated: 0x%x", ptr))
```

**Returns:** Function return value

### Console API

#### `console.log(message)`

Print message to console (same as `print()`).

```lua
console.log("Hello from Lua")
```

#### `print(...)`

Standard Lua print, outputs to renef client.

```lua
print("Value:", 42)
print(string.format("Hex: 0x%x", 255))
```

### Global Variables

#### Color Codes

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

---

## Scripting Guide

### Basic Hook Example

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

### Java Method Hook Example

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

### Memory Scanning Example

```lua
-- Scan for "Java" string signature
local pattern = "\x4A\x61\x76\x61"  -- "Java" in hex
local results = Memory.scan(pattern)

print(YELLOW .. "Found " .. #results .. " matches:" .. RESET)
for i, result in ipairs(results) do
    print(string.format("[%d] %s + 0x%x", i, result.library, result.offset))
end
```

### Memory Patching Example

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

### Finding Exported Functions

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

### Multiple Hooks Script

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

---

## Real-World Examples

### Example 1: SSL Pinning Bypass

```lua
-- Hook SSL verification function
local libssl = Module.find("libssl.so")
local exports = Module.exports("libssl.so")

-- Find SSL_CTX_set_verify
for i, exp in ipairs(exports) do
    if exp.name == "SSL_CTX_set_verify" then
        hook("libssl.so", exp.offset, {
            onEnter = function(args)
                print(YELLOW .. "[SSL] Bypassing certificate verification" .. RESET)
                -- Set verify mode to SSL_VERIFY_NONE (0)
                args[1] = 0
            end
        })
        break
    end
end

print(GREEN .. "✓ SSL pinning bypass installed" .. RESET)
```

### Example 2: Root Detection Bypass

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

### Example 3: Crypto Key Logger

```lua
-- Hook crypto functions to log encryption keys
local app_base = Module.find("libcrypto.so")

-- Hook AES_set_encrypt_key
local exports = Module.exports("libcrypto.so")
for i, exp in ipairs(exports) do
    if exp.name == "AES_set_encrypt_key" then
        hook("libcrypto.so", exp.offset, {
            onEnter = function(args)
                local key_ptr = args[0]
                local key_bits = args[1]

                -- Read the key
                local key_bytes = key_bits / 8
                local key = Memory.read(key_ptr, key_bytes)

                -- Log in hex
                local hex = ""
                for i = 1, #key do
                    hex = hex .. string.format("%02x", string.byte(key, i))
                end

                print(RED .. "[CRYPTO] AES Key (" .. key_bits .. " bits): " .. hex .. RESET)
            end
        })
        break
    end
end
```

### Example 4: Function Call Tracer

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

### Example 5: Interactive Memory Search

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

---

## Troubleshooting

### Server Won't Start

```bash
# Check if port is already in use
adb shell "lsof | grep renef_server"

# Kill existing instance
adb shell "killall renef_server"

# Check permissions
adb shell "chmod +x /data/local/tmp/renef_server"
```

### Injection Fails

```bash
# Check if process is running
adb shell "ps | grep <package>"

# Check SELinux status (may need permissive mode)
adb shell "getenforce"

# Try with root
adb root
```

### Port Forwarding Issues

```bash
# Remove existing forward
adb forward --remove tcp:1907

# Re-setup forwarding
adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit

# Verify forwarding
adb forward --list
```

### Hooks Not Triggering

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

### Memory Access Violations

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

### Client Connection Issues

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

### Script Execution Errors

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

### Build Errors

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

## Advanced Topics

### Custom Hook Types

RENEF supports two hooking methods:

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

### Session Keys

RENEF uses session keys for security. Each injection generates a 32-character authentication key that must be prepended to agent commands. This is handled automatically by the client.

### Filter Syntax

Many commands support filtering with the `~` operator:

```bash
# List apps containing "google"
la~google

# List specific package
la~com.example.app
```

The filter is sent to the agent, which applies it to the output.

### Background Execution

```bash
# Start server in background on device
adb shell "nohup /data/local/tmp/renef_server > /dev/null 2>&1 &"

# Check if running
adb shell "ps | grep renef_server"
```

### Multiple Devices

```bash
# List devices
adb devices

# Specify device
./build/renef -d emulator-5554 -s com.example.app
```

---

## Performance Considerations

### Hook Overhead

- Trampoline hooks add ~10-50ns per call
- PLT/GOT hooks add ~5-10ns per call
- Lua execution in hooks adds additional overhead
- Keep hook logic minimal for high-frequency functions

### Memory Scanning

- `Memory.scan()` scans all readable .so regions
- Can be slow for large processes
- Use specific patterns to reduce matches
- Results are limited to 1000 matches by default

### Script Loading

- Scripts are executed in the target process context
- Large scripts may cause temporary freeze
- Use `l script1.lua script2.lua` to load multiple files efficiently
- Auto-watch mode (`-w`) starts monitoring immediately after loading

---

## API Comparison with Frida

RENEF aims for API compatibility with Frida where possible:

| Frida | RENEF | Notes |
|-------|-------|-------|
| `Interceptor.attach()` | `hook()` | Similar API, different syntax |
| `Module.load()` | `Module.find()` | Returns base address |
| `Module.enumerateExports()` | `Module.exports()` | Returns table |
| `Memory.scan()` | `Memory.scan()` | Similar functionality |
| `Memory.readByteArray()` | `Memory.read()` | Returns string |
| `Memory.writeByteArray()` | `Memory.patch()` | Handles mprotect |
| `Java.use()` | `hook(class, method, sig)` | Direct JNI hooking |
| `send()` | `print()` | Output to client |

---

## Contributing

Contributions are welcome! Areas for improvement:

- Additional Lua APIs (file I/O, network, etc.)
- More hooking examples
- Performance optimizations
- Documentation improvements
- Bug fixes

---

## License

[Your license here]

---

## Credits

- **Lua 5.4** - Scripting engine
- **Capstone** - Disassembly and hooking engine
- **Android NDK** - Cross-compilation toolchain

### Inspiration & Special Thanks

RENEF was inspired by and built upon the ideas and methodologies of:

- **[Frida](https://frida.re/)** - The dynamic instrumentation toolkit that pioneered scriptable runtime manipulation. RENEF's Lua API design and hooking philosophy draw heavily from Frida's elegant approach to dynamic analysis.

- **[Radare2](https://rada.re/)** - The reverse engineering framework that demonstrated the power of modular, scriptable analysis tools. RENEF's command structure and memory operations were influenced by radare2's design principles.

We are grateful to these projects and their communities for paving the way and inspiring this work.
