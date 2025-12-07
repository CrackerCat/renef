---
title: Introduction
layout: default
nav_order: 1
---

# Introduction

Renef is a dynamic instrumentation toolkit for Android ARM64 applications, focused primarily on native code analysis. It provides runtime manipulation capabilities through Lua scripting, allowing you to hook native functions, scan and patch memory, and analyze running processes.

The toolkit uses memfd-based injection (no ptrace required) and includes an embedded Lua 5.4 engine for scripting. It supports both PLT/GOT and inline trampoline hooking via Capstone disassembly engine.

Renef is designed as a learning project and practical tool for security research and reverse engineering on Android ARM64 platforms.

> **Note:** This project was inspired by Frida and Radare2. Special thanks to their developers for creating such excellent tools that shaped the design of Renef.

## Key Features

- **ARM64 Function Hooking** - PLT/GOT and inline trampoline hooking
- **Lua Scripting** - Frida-like API with Module, Memory, Hook, Thread
- **Process Injection** - memfd + shellcode injection into running processes
- **Memory Operations** - Scan, read, write, patch memory
- **Live Scripting** - Load multiple scripts at runtime with auto-watch
- **Interactive TUI** - Memory scanner with interactive interface
- **Java Hooks** - Hook Java methods via JNI
