#include <agent/globals.h>
#include <agent/hook.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

LuaEngine* g_lua_engine = NULL;

int g_output_client_fd = -1;

bool g_verbose_mode = false;

void verbose_log(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", buf);

    if (g_verbose_mode && g_output_client_fd >= 0) {
        write(g_output_client_fd, "[DBG] ", 6);
        write(g_output_client_fd, buf, strlen(buf));
        write(g_output_client_fd, "\n", 1);
    }
}

JNIEnv* g_current_jni_env = NULL;

JavaVM* g_java_vm = NULL;

int g_default_hook_type = HOOK_TRAMPOLINE;

JNIEnv* get_current_jni_env(void) {
    JNIEnv* env = NULL;
    if (g_java_vm) {
        int status = (*g_java_vm)->GetEnv(g_java_vm, (void**)&env, JNI_VERSION_1_6);
        if (status == JNI_EDETACHED) {
            (*g_java_vm)->AttachCurrentThread(g_java_vm, &env, NULL);
        }
    }
    return env;
}
