---
title: Real-time Monitoring
layout: default
parent: Command Reference
nav_order: 6
---

# Real-time Monitoring

## `watch [address]`

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
