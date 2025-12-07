---
title: Process Management
layout: default
parent: Command Reference
nav_order: 1
---

# Process Management

## `spawn <package> [--hook=type]`

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

## `attach <pid> [--hook=type]`

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
