---
title: Getting Started
layout: default
nav_order: 5
---

# Getting Started

## Quick Start

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

## Command-line Options

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
