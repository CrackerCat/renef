---
title: Crypto Key Logger
layout: default
parent: Real-World Examples
nav_order: 3
---

# Crypto Key Logger

```lua
-- Hook crypto functions to log encryption keys
local app_base = Module.find("libcrypto.so")

-- Hook AES_set_encrypt_key
local exports = Module.exports("libcrypto.so")
for i, exp in ipairs(exports) do
    if exp.name == "AES_set_encrypt_key" then
        hook("libcrypto.so", exp.offset, {
            onEnter = function(args)
                local key_ptr = args[0]
                local key_bits = args[1]

                -- Read the key
                local key_bytes = key_bits / 8
                local key = Memory.read(key_ptr, key_bytes)

                -- Log in hex
                local hex = ""
                for i = 1, #key do
                    hex = hex .. string.format("%02x", string.byte(key, i))
                end

                print(RED .. "[CRYPTO] AES Key (" .. key_bits .. " bits): " .. hex .. RESET)
            end
        })
        break
    end
end
```
