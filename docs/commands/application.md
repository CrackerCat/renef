---
title: Application Management
layout: default
parent: Command Reference
nav_order: 2
---

# Application Management

## `la [~filter]`

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
