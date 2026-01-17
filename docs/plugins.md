---
title: Plugin Development
layout: default
nav_order: 9
---

# Plugin Development

Renef supports native plugins that extend the CLI with custom commands. Plugins are shared libraries (`.so`, `.dylib`, `.dll`) that are automatically loaded at startup.

## Plugin Directory

Plugins are loaded from the following directories:

| Platform | User Directory | System Directory |
|----------|----------------|------------------|
| Linux | `~/.config/renef/plugins/` | `/usr/lib/renef/plugins/` |
| macOS | `~/.config/renef/plugins/` | `/usr/local/lib/renef/plugins/` |
| Windows | `%APPDATA%\renef\plugins\` | - |

**File extensions:**
- Linux: `.so`
- macOS: `.dylib`
- Windows: `.dll`

---

## Creating a Plugin

### Required Exports

Every plugin must export the following:

```c
#include <renef/plugin.h>

// Plugin metadata (required)
RENPluginMetadata ren_plugin_info = {
    .name = "my_plugin",
    .author = "Your Name",
    .version = "1.0.0",
    .description = "Description of your plugin",
    .command = "mycommand",    // CLI command prefix
    .type = PLUGIN_COMMAND
};

// Called when plugin is loaded (optional but recommended)
int ren_plugin_init(renef_ctx_t ctx);

// Called when CLI command is executed (required for PLUGIN_COMMAND)
int ren_plugin_exec(renef_ctx_t ctx, char* input);

// Called when plugin is unloaded (optional)
void ren_plugin_close(renef_ctx_t ctx);
```

### Plugin Metadata

| Field | Type | Description |
|-------|------|-------------|
| `name` | `const char*` | Plugin identifier |
| `author` | `const char*` | Author name |
| `version` | `const char*` | Version string |
| `description` | `const char*` | Short description |
| `command` | `const char*` | CLI command prefix (e.g., `"test"` → `test <args>`) |
| `type` | `PluginType` | Plugin type (`PLUGIN_COMMAND`, `PLUGIN_LUA`, `PLUGIN_NATIVE`) |

### Plugin API

Plugins have access to the following functions:

```c
// Print message to CLI output
void ren_print(renef_ctx_t ctx, char* msg);

// Send command to attached target (agent)
int ren_exec(const char* cmd);

// Receive response from target (blocking with 5s timeout)
char* ren_recv();  // Returns malloc'd string, caller must free()
```

---

## Example Plugin

### Basic Hello World

```c
// hello_plugin.c
#include <renef/plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

RENPluginMetadata ren_plugin_info = {
    .name = "hello",
    .author = "developer",
    .version = "1.0.0",
    .description = "Simple hello world plugin",
    .command = "hello",
    .type = PLUGIN_COMMAND
};

int ren_plugin_init(renef_ctx_t ctx) {
    (void)ctx;
    return 0;  // Success
}

int ren_plugin_exec(renef_ctx_t ctx, char* input) {
    if (!ctx) return -1;

    char msg[256];

    if (input && strlen(input) > 0) {
        snprintf(msg, sizeof(msg), "Hello, %s!\n", input);
    } else {
        snprintf(msg, sizeof(msg), "Hello, World!\n");
    }

    ren_print(ctx, msg);
    return 0;
}

void ren_plugin_close(renef_ctx_t ctx) {
    (void)ctx;
}
```

### Communicating with Target

Plugins can send commands to the attached target process:

```c
int ren_plugin_exec(renef_ctx_t ctx, char* input) {
    if (!ctx) return -1;

    // Send ping command to agent
    if (input && strcmp(input, "ping") == 0) {
        ren_exec("ping");

        char* response = ren_recv();
        if (response) {
            ren_print(ctx, response);
            free(response);
        }
    }

    return 0;
}
```

---

## Building Plugins

### Manual Build

```bash
# Linux
gcc -shared -fPIC -I/path/to/renef/include -o my_plugin.so my_plugin.c

# macOS
gcc -dynamiclib -fPIC -I/path/to/renef/include -o my_plugin.dylib my_plugin.c
```

### Using the Example Makefile

Renef includes a plugin build system in `examples/plugins/`:

```bash
cd examples/plugins

# Build all plugins in directory
make all

# Install to ~/.config/renef/plugins/
make install

# Clean build artifacts
make clean

# List available plugins
make list
```

**Makefile variables:**

| Variable | Description |
|----------|-------------|
| `RENEF_SDK` | Path to renef include directory |
| `PLUGIN_DIR` | Installation directory |
| `CC` | C compiler |
| `CFLAGS` | Compiler flags |

---

## CLI Commands

### `plugins`

List all loaded plugins:

```
renef> plugins
Loaded plugins (2):
  [1] hello - Simple hello world plugin
  [2] test_plugin - Test plugin for renef
```

### Using Plugin Commands

Plugin commands are invoked by their command prefix:

```
renef> hello World
Hello, World!

renef> hello
Hello, World!

renef> test ping
pong
```

---

## Plugin Lifecycle

1. **Autoload**: At startup, renef scans the plugin directory and loads all valid plugins
2. **Init**: `ren_plugin_init()` is called for each loaded plugin
3. **Registration**: Plugins with `PLUGIN_COMMAND` type register their command with the CLI
4. **Execution**: When user invokes the command, `ren_plugin_exec()` is called
5. **Unload**: `ren_plugin_close()` is called when renef exits or plugin is unloaded

---

## Best Practices

- Always check if `ctx` is valid before using it
- Free memory returned by `ren_recv()`
- Keep `ren_plugin_init()` lightweight (it may be called during autoload)
- Use descriptive command names to avoid conflicts
- Return `0` for success, `-1` for failure from `init` and `exec` functions
- Handle `NULL` input in `ren_plugin_exec()` gracefully
