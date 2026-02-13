#ifndef AGENT_AGENT_H
#define AGENT_AGENT_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

JNIEnv* get_jni_env(void);

void* elf_lookup_symbol(const char* lib_path, uintptr_t load_addr, const char* symbol_name);

#ifdef __cplusplus
}
#endif

#endif // AGENT_AGENT_H
