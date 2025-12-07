---
title: Hook API
layout: default
parent: Lua API Reference
nav_order: 3
---

# Hook API

## `hook(library, offset, callbacks)`

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

## `hook(class, method, signature, callbacks)`

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

## JNI Type Wrappers

For Java hooks, use these wrappers to create properly typed arguments:

### `JNI.string(value)`

```lua
local jstr = JNI.string("Hello")
```

### `JNI.int(value)`

```lua
local jint = JNI.int(42)
```

### `JNI.long(value)`

```lua
local jlong = JNI.long(123456789)
```

### `JNI.boolean(value)`

```lua
local jbool = JNI.boolean(true)
```
