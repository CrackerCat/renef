#ifndef RENEF_API_H
#define RENEF_API_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RenefSession RenefSession;

typedef struct {
    int success;
    char* output;
    char* error;
} RenefResult;

typedef void (*RenefMessageCallback)(const char* message, size_t len, void* user_data);

RenefSession* renef_spawn(const char* package, int hook_type);
RenefSession* renef_attach(int pid, int hook_type);
void renef_session_close(RenefSession* session);
int renef_session_pid(RenefSession* session);

RenefResult renef_eval(RenefSession* session, const char* lua_code);
RenefResult renef_memscan(RenefSession* session, const char* pattern);
RenefResult renef_load_script(RenefSession* session, const char* path);

// Module API
uint64_t renef_module_find(RenefSession* session, const char* name);
RenefResult renef_module_list(RenefSession* session);
RenefResult renef_module_exports(RenefSession* session, const char* name);
RenefResult renef_module_symbols(RenefSession* session, const char* name);

// Memory API
ssize_t renef_read_memory(RenefSession* session, uint64_t addr, size_t size, uint8_t* out);
ssize_t renef_write_memory(RenefSession* session, uint64_t addr, const uint8_t* data, size_t size);
uint8_t renef_read_u8(RenefSession* session, uint64_t addr);
uint16_t renef_read_u16(RenefSession* session, uint64_t addr);
uint32_t renef_read_u32(RenefSession* session, uint64_t addr);
uint64_t renef_read_u64(RenefSession* session, uint64_t addr);
RenefResult renef_read_string(RenefSession* session, uint64_t addr, size_t max_len);
int renef_write_u8(RenefSession* session, uint64_t addr, uint8_t val);
int renef_write_u16(RenefSession* session, uint64_t addr, uint16_t val);
int renef_write_u32(RenefSession* session, uint64_t addr, uint32_t val);
int renef_write_u64(RenefSession* session, uint64_t addr, uint64_t val);

// Thread API
RenefResult renef_thread_backtrace(RenefSession* session);
uint64_t renef_thread_id(RenefSession* session);

// Hook API
int renef_hook(RenefSession* session, const char* lib, uint64_t offset,
               const char* on_enter, const char* on_leave);
int renef_hook_java(RenefSession* session, const char* class_name, const char* method_name,
                    const char* signature, const char* on_enter, const char* on_leave);
int renef_unhook(RenefSession* session, int hook_id);
RenefResult renef_hooks_list(RenefSession* session);

void renef_result_free(RenefResult* result);

int renef_watch_start(RenefSession* session, RenefMessageCallback callback, void* user_data);
void renef_watch_stop(RenefSession* session);

#ifdef __cplusplus
}
#endif

#endif