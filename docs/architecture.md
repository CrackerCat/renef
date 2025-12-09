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
- Connects to server via ADB-forwarded TCP (localhost:1907)

**Server (renef_server)**
- ARM64 Android binary
- Listens on Abstract Unix Domain Socket
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

## Communication: Abstract Unix Domain Sockets

Renef uses **Abstract Unix Domain Sockets (UDS)** instead of TCP for on-device communication. This provides several advantages:

### Why Abstract Sockets?

| Feature | Abstract UDS | TCP |
|---------|-------------|-----|
| Namespace | Kernel-managed, no filesystem | Requires port binding |
| Security | Process-level isolation | Network accessible |
| Performance | Zero-copy, no network stack | TCP/IP overhead |
| Cleanup | Auto-removed on process exit | Port may linger |

### Abstract Socket Details

Abstract sockets are identified by a null byte prefix (`\0`) in the socket path:

```c
// Server binds to abstract socket
struct sockaddr_un addr;
addr.sun_family = AF_UNIX;
addr.sun_path[0] = '\0';  // Abstract namespace indicator
strcpy(&addr.sun_path[1], "com.android.internal.os.RuntimeInit");
```

**Benefits:**
- No filesystem permissions needed
- Socket automatically cleaned up when server exits
- Not visible in `/tmp` or other filesystem locations
- Isolated from network-based attacks

### ADB Port Forwarding

The client connects via ADB forward which bridges TCP to the abstract socket:

```bash
# Setup (done automatically by renef)
adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit

# Client connects to localhost:1907
# ADB forwards to abstract socket on device
```
