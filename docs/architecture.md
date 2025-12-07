---
title: Architecture
layout: default
nav_order: 3
---

# Architecture

## Components

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

## Communication Flow

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

## Injection Method

Renef uses a sophisticated memfd-based injection technique:

1. **memfd_create()** - Server creates memfd from SO file
2. **Stage 1 Shellcode** - Hijacks malloc() temporarily
3. **Trigger** - Waits for target to call malloc()
4. **Stage 2 Shellcode** - Calls dlopen("/proc/self/fd/X") to load payload
5. **Restoration** - Restores original malloc() and continues execution

This approach does **not** use ptrace and works on most Android devices.
