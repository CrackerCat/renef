#ifndef LUA_STRACE_H
#define LUA_STRACE_H

#include <lua.h>

#ifdef __cplusplus
extern "C" {
#endif

void register_strace_api(lua_State* L);

#ifdef __cplusplus
}
#endif

#endif
