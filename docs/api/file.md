---
title: File API
layout: default
parent: Lua API Reference
nav_order: 6
---

# File API

The `File` global provides file system operations for reading files and resolving paths within the target process.

---

## `File.exists(path)`

Check if a file exists.

```lua
if File.exists("/data/local/tmp/config.txt") then
    print("Config file found")
end

-- Check if app has a specific file
local pkg_path = "/data/data/com.example.app/files/secret.db"
if File.exists(pkg_path) then
    print("Secret database exists!")
end
```

**Parameters:**
- `path` - File path to check

**Returns:** `true` if file exists, `false` otherwise

---

## `File.read(path)`

Read entire file contents.

```lua
local content = File.read("/proc/self/maps")
if content then
    print("Maps file size: " .. #content .. " bytes")
    print(content)
else
    print("Failed to read file")
end

-- Read app config
local config = File.read("/data/data/com.example.app/shared_prefs/config.xml")
if config then
    print(config)
end
```

**Parameters:**
- `path` - File path to read

**Returns:** File contents as string, or `nil` on failure

**Note:** Maximum file size is limited to ~40KB for safety.

---

## `File.readlink(path)`

Read the target of a symbolic link.

```lua
-- Resolve a symlink
local target = File.readlink("/proc/self/exe")
if target then
    print("Executable: " .. target)
end

-- Check what library is linked
local lib = File.readlink("/system/lib64/libc.so")
print("libc.so -> " .. (lib or "not a symlink"))
```

**Parameters:**
- `path` - Symlink path to read

**Returns:** Link target as string, or `nil` if not a symlink or on error

---

## `File.fdpath(fd)`

Get the file path for an open file descriptor. This reads `/proc/self/fd/<fd>` symlink.

```lua
-- In a hook, resolve what file is being accessed
hook("libc.so", read_offset, {
    onEnter = function(args)
        local fd = args[0]
        local path = File.fdpath(fd)
        if path then
            print(string.format("read(fd=%d) -> %s", fd, path))
        end
    end
})

-- Check stdin/stdout/stderr
print("stdin:  " .. (File.fdpath(0) or "unknown"))
print("stdout: " .. (File.fdpath(1) or "unknown"))
print("stderr: " .. (File.fdpath(2) or "unknown"))
```

**Parameters:**
- `fd` - File descriptor number

**Returns:** File path as string, or `nil` if fd is invalid

---

## Examples

### Monitor file access

```lua
-- Hook open() to monitor file access
local open_offset = 0x12340  -- Find via Module.exports("libc.so")

hook("libc.so", open_offset, {
    onEnter = function(args)
        local path = Memory.readString(args[0])
        if path then
            print("[open] " .. path)
            
            -- Check if file exists before open
            if File.exists(path) then
                print("  (file exists)")
            else
                print("  (file will be created)")
            end
        end
    end,
    onLeave = function(retval)
        if retval >= 0 then
            local resolved = File.fdpath(retval)
            print("  fd=" .. retval .. " -> " .. (resolved or "?"))
        end
        return retval
    end
})
```

### Read app preferences

```lua
local prefs_path = "/data/data/com.example.app/shared_prefs/settings.xml"

if File.exists(prefs_path) then
    local content = File.read(prefs_path)
    if content then
        print("=== App Settings ===")
        print(content)
        
        -- Parse for specific values
        if content:find("premium.*true") then
            print(GREEN .. "Premium enabled!" .. RESET)
        end
    end
else
    print("Settings file not found")
end
```

### Resolve library paths

```lua
-- Find actual paths for loaded libraries
local libs = {
    "/system/lib64/libc.so",
    "/system/lib64/libm.so",
    "/apex/com.android.runtime/lib64/bionic/libc.so"
}

for _, lib in ipairs(libs) do
    if File.exists(lib) then
        local target = File.readlink(lib)
        if target then
            print(lib .. " -> " .. target)
        else
            print(lib .. " (regular file)")
        end
    end
end
```

### Debug file descriptor leaks

```lua
-- Enumerate open file descriptors
print("=== Open File Descriptors ===")
for fd = 0, 255 do
    local path = File.fdpath(fd)
    if path then
        print(string.format("fd %3d: %s", fd, path))
    end
end
```
