---
title: SSL Pinning Bypass
layout: default
parent: Real-World Examples
nav_order: 1
---

# SSL Pinning Bypass

```lua
-- Hook SSL verification function
local libssl = Module.find("libssl.so")
local exports = Module.exports("libssl.so")

-- Find SSL_CTX_set_verify
for i, exp in ipairs(exports) do
    if exp.name == "SSL_CTX_set_verify" then
        hook("libssl.so", exp.offset, {
            onEnter = function(args)
                print(YELLOW .. "[SSL] Bypassing certificate verification" .. RESET)
                -- Set verify mode to SSL_VERIFY_NONE (0)
                args[1] = 0
            end
        })
        break
    end
end

print(GREEN .. "✓ SSL pinning bypass installed" .. RESET)
```
