#include <agent/lua_java.h>
#include <agent/lua_engine.h>
#include <agent/globals.h>
#include <agent/agent.h>
#include <agent/bridge_dex.h>
#include <agent/hook_java.h>

#include <dlfcn.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#define MAX_PARAMS 16
#define MAX_CLASS_NAME 256
#define MAX_REGISTERED_METHODS 16

typedef struct {
    char method_name[64];
    int lua_ref;
} RegisteredMethod;

typedef struct {
    RegisteredMethod methods[MAX_REGISTERED_METHODS];
    int method_count;
    lua_State* L;
} CallbackRegistry;

static jclass    g_bridge_class = NULL;
static jmethodID g_bridge_ctor  = NULL;

typedef struct {
    jclass clazz;
    char class_name[MAX_CLASS_NAME];
} JavaClassWrapper;

typedef struct {
    char param_types[MAX_PARAMS];           // 'I', 'Z', 'L', '[' etc.
    char param_class_names[MAX_PARAMS][MAX_CLASS_NAME];
    int param_count;
    char return_type;
    char return_class_name[MAX_CLASS_NAME];
} ParsedSignature;

static jobject g_class_loader = NULL;
static jmethodID g_load_class_method = NULL;

static bool setup_class_loader(JNIEnv* env) {
    if (g_class_loader != NULL) {
        return true;
    }

    jclass thread_class = (*env)->FindClass(env, "java/lang/Thread");
    if (!thread_class) {
        LOGE("Failed to find Thread class");
        return false;
    }

    jmethodID current_thread = (*env)->GetStaticMethodID(
            env, thread_class, "currentThread", "()Ljava/lang/Thread;");
    if (!current_thread) {
        LOGE("Failed to find currentThread method");
        return false;
    }

    jobject thread = (*env)->CallStaticObjectMethod(env, thread_class, current_thread);
    if (!thread) {
        LOGE("Failed to get current thread");
        return false;
    }

    jmethodID get_class_loader = (*env)->GetMethodID(
            env, thread_class, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
    if (!get_class_loader) {
        LOGE("Failed to find getContextClassLoader method");
        return false;
    }

    jobject class_loader = (*env)->CallObjectMethod(env, thread, get_class_loader);
    if (!class_loader) {
        LOGE("Failed to get ClassLoader");
        return false;
    }

    g_class_loader = (*env)->NewGlobalRef(env, class_loader);

    jclass class_loader_class = (*env)->FindClass(env, "java/lang/ClassLoader");
    g_load_class_method = (*env)->GetMethodID(
            env, class_loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");

    LOGI("ClassLoader setup complete");
    return true;
}

static jclass find_class(JNIEnv* env, const char* class_name) {
    // Convert dot notation to slash notation for JNI (e.g. "javax.net.ssl.SSLContext" -> "javax/net/ssl/SSLContext")
    char jni_class_name[256];
    strncpy(jni_class_name, class_name, sizeof(jni_class_name) - 1);
    jni_class_name[sizeof(jni_class_name) - 1] = '\0';
    for (size_t i = 0; jni_class_name[i] != '\0'; i++) {
        if (jni_class_name[i] == '.') {
            jni_class_name[i] = '/';
        }
    }

    jclass clazz = (*env)->FindClass(env, jni_class_name);
    if (clazz) {
        (*env)->ExceptionClear(env);
        LOGI("Found class via FindClass: %s", jni_class_name);
        return clazz;
    }
    (*env)->ExceptionClear(env);

    if (!setup_class_loader(env)) {
        LOGE("ClassLoader setup failed");
        return NULL;
    }

    // loadClass needs dot notation - convert back from slash to dot
    char java_class_name[256];
    strncpy(java_class_name, jni_class_name, sizeof(java_class_name) - 1);
    java_class_name[sizeof(java_class_name) - 1] = '\0';

    for (size_t i = 0; java_class_name[i] != '\0'; i++) {
        if (java_class_name[i] == '/') {
            java_class_name[i] = '.';
        }
    }

    jstring class_name_str = (*env)->NewStringUTF(env, java_class_name);
    clazz = (jclass)(*env)->CallObjectMethod(
            env, g_class_loader, g_load_class_method, class_name_str);

    (*env)->DeleteLocalRef(env, class_name_str);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        LOGE("Failed to load class: %s", class_name);
        return NULL;
    }

    LOGI("Found class via ClassLoader: %s", class_name);
    return clazz;
}

static ParsedSignature parse_signature(const char* sig) {
    ParsedSignature result;
    memset(&result, 0, sizeof(result));

    const char* p = sig;

    if (*p != '(') {
        LOGE("Invalid signature: %s", sig);
        return result;
    }
    p++;

    while (*p && *p != ')' && result.param_count < MAX_PARAMS) {
        if (*p == 'L') {
            result.param_types[result.param_count] = 'L';
            p++;

            size_t class_idx = 0;
            while (*p && *p != ';' && class_idx < MAX_CLASS_NAME - 1) {
                result.param_class_names[result.param_count][class_idx++] = *p++;
            }
            result.param_class_names[result.param_count][class_idx] = '\0';

            if (*p == ';') p++;
            result.param_count++;
        } else if (*p == '[') {
            result.param_types[result.param_count] = '[';
            result.param_class_names[result.param_count][0] = '\0';
            result.param_count++;
            p++;
            if (*p == 'L') {
                while (*p && *p != ';') p++;
                if (*p == ';') p++;
            } else if (*p) {
                p++;
            }
        } else {
            // Primitive type: I, Z, B, C, S, J, F, D, V
            result.param_types[result.param_count] = *p;
            result.param_class_names[result.param_count][0] = '\0';
            result.param_count++;
            p++;
        }
    }

    if (*p == ')') p++;

    // Return type
    if (*p == 'L') {
        result.return_type = 'L';
        p++;
        size_t class_idx = 0;
        while (*p && *p != ';' && class_idx < MAX_CLASS_NAME - 1) {
            result.return_class_name[class_idx++] = *p++;
        }
        result.return_class_name[class_idx] = '\0';
    } else if (*p == '[') {
        result.return_type = '[';
        result.return_class_name[0] = '\0';
    } else if (*p) {
        result.return_type = *p;
        result.return_class_name[0] = '\0';
    }

    LOGI("Parsed signature: %d params, return type: %c", result.param_count, result.return_type);

    return result;
}

//=============================================================================
// Java.use() 
//=============================================================================
static JavaClassWrapper* java_use(JNIEnv* env, const char* class_name) {
    jclass clazz = find_class(env, class_name);
    if (!clazz) {
        return NULL;
    }

    // Global reference al (wrapper'ın ömrü boyunca yaşasın)
    jclass global_clazz = (jclass)(*env)->NewGlobalRef(env, clazz);
    (*env)->DeleteLocalRef(env, clazz);

    // Wrapper oluştur
    JavaClassWrapper* wrapper = (JavaClassWrapper*)malloc(sizeof(JavaClassWrapper));
    if (!wrapper) {
        (*env)->DeleteGlobalRef(env, global_clazz);
        return NULL;
    }

    wrapper->clazz = global_clazz;
    strncpy(wrapper->class_name, class_name, MAX_CLASS_NAME - 1);
    wrapper->class_name[MAX_CLASS_NAME - 1] = '\0';

    return wrapper;
}


static jobject JNICALL native_invoke_callback(JNIEnv* env, jclass clazz,
    jlong callbackPtr, jstring methodName, jstring returnType, jobjectArray args)
{
    CallbackRegistry* reg = (CallbackRegistry*)(uintptr_t)callbackPtr;
    if (!reg || !reg->L) return NULL;

    const char* name = (*env)->GetStringUTFChars(env, methodName, NULL);
    if (!name) return NULL;

    int lua_ref = LUA_NOREF;
    for (int i = 0; i < reg->method_count; i++) {
        if (strcmp(reg->methods[i].method_name, name) == 0) {
            lua_ref = reg->methods[i].lua_ref;
            break;
        }
    }

    if (lua_ref == LUA_NOREF) {
        (*env)->ReleaseStringUTFChars(env, methodName, name);
        return NULL;
    }

    lua_State* L = reg->L;
    lua_rawgeti(L, LUA_REGISTRYINDEX, lua_ref);

    int arg_count = 0;
    if (args) {
        arg_count = (*env)->GetArrayLength(env, args);
        for (int i = 0; i < arg_count; i++) {
            jobject arg = (*env)->GetObjectArrayElement(env, args, i);
            if (!arg) {
                lua_pushnil(L);
            } else {
                jclass string_class = (*env)->FindClass(env, "java/lang/String");
                if ((*env)->IsInstanceOf(env, arg, string_class)) {
                    const char* str = (*env)->GetStringUTFChars(env, (jstring)arg, NULL);
                    lua_pushstring(L, str);
                    (*env)->ReleaseStringUTFChars(env, (jstring)arg, str);
                } else {
                    lua_pushinteger(L, (lua_Integer)(uintptr_t)arg);
                }
                (*env)->DeleteLocalRef(env, arg);
            }
        }
    }

    jobject result = NULL;
    if (lua_pcall(L, arg_count, 1, 0) != LUA_OK) {
        LOGE("registerClass callback error [%s]: %s", name, lua_tostring(L, -1));
        lua_pop(L, 1);
    } else {
        const char* ret_type = (*env)->GetStringUTFChars(env, returnType, NULL);

        if (ret_type && strcmp(ret_type, "boolean") == 0) {
            jclass bool_class = (*env)->FindClass(env, "java/lang/Boolean");
            jmethodID value_of = (*env)->GetStaticMethodID(env, bool_class, "valueOf", "(Z)Ljava/lang/Boolean;");
            jboolean val = lua_toboolean(L, -1);
            result = (*env)->CallStaticObjectMethod(env, bool_class, value_of, val);
        } else if (ret_type && strcmp(ret_type, "int") == 0) {
            jclass int_class = (*env)->FindClass(env, "java/lang/Integer");
            jmethodID value_of = (*env)->GetStaticMethodID(env, int_class, "valueOf", "(I)Ljava/lang/Integer;");
            jint val = (jint)lua_tointeger(L, -1);
            result = (*env)->CallStaticObjectMethod(env, int_class, value_of, val);
        } else if (!lua_isnil(L, -1) && lua_isuserdata(L, -1)) {
            jobject* obj_ud = (jobject*)lua_touserdata(L, -1);
            result = *obj_ud;
        }

        if (ret_type) (*env)->ReleaseStringUTFChars(env, returnType, ret_type);
        lua_pop(L, 1);
    }

    (*env)->ReleaseStringUTFChars(env, methodName, name);
    return result;
}

static JNINativeMethod g_native_methods[] = {
    { "nativeInvoke",
      "(JLjava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;",
      (void*)native_invoke_callback }
};

static int init_bridge_dex(JNIEnv* env) {
    if (g_bridge_class) return 0;

    jobject byte_buf = (*env)->NewDirectByteBuffer(env, (void*)bridge_dex, bridge_dex_len);
    if (!byte_buf) {
        LOGE("Failed to create ByteBuffer for bridge DEX");
        return -1;
    }

    jclass loader_class = (*env)->FindClass(env, "dalvik/system/InMemoryDexClassLoader");
    if (!loader_class) {
        LOGE("Failed to find InMemoryDexClassLoader");
        return -1;
    }

    jmethodID loader_ctor = (*env)->GetMethodID(env, loader_class, "<init>",
        "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject loader = (*env)->NewObject(env, loader_class, loader_ctor, byte_buf, NULL);
    if (!loader) {
        LOGE("Failed to create InMemoryDexClassLoader");
        return -1;
    }

    jmethodID load_class = (*env)->GetMethodID(env, loader_class, "loadClass",
        "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring class_name = (*env)->NewStringUTF(env, "com.renef.lab.RenefInvocationHandler");
    jclass bridge = (jclass)(*env)->CallObjectMethod(env, loader, load_class, class_name);
    if (!bridge || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        LOGE("Failed to load RenefInvocationHandler");
        return -1;
    }

    (*env)->RegisterNatives(env, bridge, g_native_methods, 1);

    g_bridge_class = (*env)->NewGlobalRef(env, bridge);
    g_bridge_ctor = (*env)->GetMethodID(env, g_bridge_class, "<init>", "(J)V");

    (*env)->DeleteLocalRef(env, byte_buf);
    (*env)->DeleteLocalRef(env, loader);
    (*env)->DeleteLocalRef(env, bridge);
    (*env)->DeleteLocalRef(env, class_name);

    LOGI("Bridge DEX loaded, native method registered");
    return 0;
}

//=============================================================================
// $new() 
//=============================================================================
static jobject java_new(JNIEnv* env, JavaClassWrapper* wrapper,
                        const char* constructor_sig, jvalue* args) {

    jmethodID constructor = (*env)->GetMethodID(env, wrapper->clazz, "<init>", constructor_sig);
    if (!constructor) {
        LOGE("Constructor not found: %s", constructor_sig);
        (*env)->ExceptionClear(env);
        return NULL;
    }

    jobject instance = (*env)->NewObjectA(env, wrapper->clazz, constructor, args);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        LOGE("Failed to create instance");
        return NULL;
    }

    LOGI("Created new instance of %s", wrapper->class_name);
    return instance;
}

//=============================================================================
// Static method CALL
//=============================================================================
static jvalue call_static_method(JNIEnv* env, JavaClassWrapper* wrapper,
                                 const char* method_name, const char* signature,
                                 jvalue* args) {
    jvalue result;
    memset(&result, 0, sizeof(result));

    jmethodID method = (*env)->GetStaticMethodID(env, wrapper->clazz, method_name, signature);
    if (!method) {
        LOGE("Static method not found: %s%s", method_name, signature);
        (*env)->ExceptionClear(env);
        return result;
    }

    ParsedSignature parsed = parse_signature(signature);

    switch (parsed.return_type) {
        case 'V':
            (*env)->CallStaticVoidMethodA(env, wrapper->clazz, method, args);
            break;
        case 'Z':
            result.z = (*env)->CallStaticBooleanMethodA(env, wrapper->clazz, method, args);
            break;
        case 'I':
            result.i = (*env)->CallStaticIntMethodA(env, wrapper->clazz, method, args);
            break;
        case 'J':
            result.j = (*env)->CallStaticLongMethodA(env, wrapper->clazz, method, args);
            break;
        case 'F':
            result.f = (*env)->CallStaticFloatMethodA(env, wrapper->clazz, method, args);
            break;
        case 'D':
            result.d = (*env)->CallStaticDoubleMethodA(env, wrapper->clazz, method, args);
            break;
        case 'L':
        case '[':
            result.l = (*env)->CallStaticObjectMethodA(env, wrapper->clazz, method, args);
            break;
        default:
            LOGE("Unknown return type: %c", parsed.return_type);
    }

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    return result;
}

static void lua_to_jvalue(JNIEnv* env, lua_State* L , ParsedSignature* sig, jvalue* args, int start_pos){
    for (int i = 0; i < sig->param_count; i++) {
        int stack_pos = start_pos + i;


        switch(sig->param_types[i]){
        case 'I':
            args[i].i = lua_tointeger(L, stack_pos);
            break;
        case 'Z':
            args[i].z = lua_toboolean(L, stack_pos);
            break;
        case '[':
        case 'L':
            if (lua_isnil(L, stack_pos)) {
                args[i].l = NULL;
            } else if (lua_isinteger(L, stack_pos)) {
                // Raw ART Object* from hook args (e.g. args[2] = x2 register)
                // Must convert to JNI reference before passing to JNI calls
                // NOTE: must check before lua_isstring, which returns true for integers in Lua 5.4
                void* raw_ptr = (void*)(uintptr_t)lua_tointeger(L, stack_pos);
                args[i].l = raw_ptr_to_jni_ref(env, raw_ptr);
            } else if (lua_type(L, stack_pos) == LUA_TSTRING) {
                args[i].l = (*env)->NewStringUTF(env, lua_tostring(L, stack_pos));
            } else if (lua_isuserdata(L, stack_pos)) {
                jobject* obj_ud = (jobject*)lua_touserdata(L, stack_pos);
                args[i].l = *obj_ud;
            } else {
                args[i].l = NULL;
            }
            break;
        case 'F':
            args[i].f = lua_tonumber(L, stack_pos);
            break;
        case 'D':
            args[i].d = lua_tonumber(L, stack_pos);
            break;
        case 'B':
            args[i].b = lua_tointeger(L, stack_pos);
            break;
        case 'S':
            args[i].s = lua_tointeger(L, stack_pos);
            break;
        case 'C':
            args[i].c = lua_tointeger(L, stack_pos);
            break;
        case 'J':
            args[i].j = lua_tointeger(L, stack_pos);
            break;
        }
    }
}

//=============================================================================
// Instance method CALL
//=============================================================================
static jvalue call_instance_method(JNIEnv* env, jobject instance,
                                   const char* method_name, const char* signature,
                                   jvalue* args) {
    jvalue result;
    memset(&result, 0, sizeof(result));

    jclass clazz = (*env)->GetObjectClass(env, instance);
    jmethodID method = (*env)->GetMethodID(env, clazz, method_name, signature);
    if (!method) {
        LOGE("Instance method not found: %s%s", method_name, signature);
        (*env)->ExceptionClear(env);
        return result;
    }

    ParsedSignature parsed = parse_signature(signature);

    switch (parsed.return_type) {
        case 'V':
            (*env)->CallVoidMethodA(env, instance, method, args);
            break;
        case 'Z':
            result.z = (*env)->CallBooleanMethodA(env, instance, method, args);
            break;
        case 'I':
            result.i = (*env)->CallIntMethodA(env, instance, method, args);
            break;
        case 'J':
            result.j = (*env)->CallLongMethodA(env, instance, method, args);
            break;
        case 'F':
            result.f = (*env)->CallFloatMethodA(env, instance, method, args);
            break;
        case 'D':
            result.d = (*env)->CallDoubleMethodA(env, instance, method, args);
            break;
        case 'L':
        case '[':
            result.l = (*env)->CallObjectMethodA(env, instance, method, args);
            break;
        default:
            LOGE("Unknown return type: %c", parsed.return_type);
    }

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    return result;
}

//=============================================================================
// Lua Bindings
//=============================================================================

#define JAVA_WRAPPER_MT "JavaClassWrapper"
#define JAVA_INSTANCE_MT "JavaInstance"

static int lua_java_register_class(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get JNIEnv");
        return 2;
    }

    if (init_bridge_dex(env) != 0) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to load bridge DEX");
        return 2;
    }

    lua_getfield(L, 1, "implements");
    if (!lua_istable(L, -1)) {
        lua_pushnil(L);
        lua_pushstring(L, "implements must be a table");
        return 2;
    }

    int iface_count = luaL_len(L, -1);
    jclass iface_classes[16];
    for (int i = 0; i < iface_count && i < 16; i++) {
        lua_rawgeti(L, -1, i + 1);
        const char* iface_name = lua_tostring(L, -1);
        iface_classes[i] = find_class(env, iface_name);
        if (!iface_classes[i]) {
            lua_pushnil(L);
            lua_pushfstring(L, "Interface not found: %s", iface_name);
            return 2;
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    CallbackRegistry* reg = (CallbackRegistry*)malloc(sizeof(CallbackRegistry));
    memset(reg, 0, sizeof(CallbackRegistry));
    reg->L = L;

    lua_getfield(L, 1, "methods");
    if (lua_istable(L, -1)) {
        lua_pushnil(L);
        while (lua_next(L, -2) != 0) {
            if (lua_isstring(L, -2) && lua_isfunction(L, -1)) {
                const char* mname = lua_tostring(L, -2);
                int ref = luaL_ref(L, LUA_REGISTRYINDEX);
                strncpy(reg->methods[reg->method_count].method_name, mname, 63);
                reg->methods[reg->method_count].lua_ref = ref;
                reg->method_count++;
            } else {
                lua_pop(L, 1);
            }
        }
    }
    lua_pop(L, 1);

    jlong ptr = (jlong)(uintptr_t)reg;
    jobject handler = (*env)->NewObject(env, g_bridge_class, g_bridge_ctor, ptr);
    if (!handler) {
        LOGE("Failed to create RenefInvocationHandler");
        free(reg);
        lua_pushnil(L);
        return 1;
    }

    jclass proxy_class = (*env)->FindClass(env, "java/lang/reflect/Proxy");
    jmethodID new_proxy = (*env)->GetStaticMethodID(env, proxy_class, "newProxyInstance",
        "(Ljava/lang/ClassLoader;[Ljava/lang/Class;Ljava/lang/reflect/InvocationHandler;)Ljava/lang/Object;");

    jclass class_class = (*env)->FindClass(env, "java/lang/Class");
    jobjectArray iface_array = (*env)->NewObjectArray(env, iface_count, class_class, NULL);
    for (int i = 0; i < iface_count; i++) {
        (*env)->SetObjectArrayElement(env, iface_array, i, iface_classes[i]);
    }

    jobject class_loader = NULL;
    if (g_class_loader) {
        class_loader = g_class_loader;
    } else {
        setup_class_loader(env);
        class_loader = g_class_loader;
    }

    jobject proxy = (*env)->CallStaticObjectMethod(env, proxy_class, new_proxy,
        class_loader, iface_array, handler);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        free(reg);
        lua_pushnil(L);
        lua_pushstring(L, "Proxy creation failed");
        return 2;
    }

    jobject global_proxy = (*env)->NewGlobalRef(env, proxy);
    (*env)->DeleteLocalRef(env, proxy);
    (*env)->DeleteLocalRef(env, handler);
    (*env)->DeleteLocalRef(env, iface_array);

    jobject* ud = (jobject*)lua_newuserdata(L, sizeof(jobject));
    *ud = global_proxy;
    luaL_getmetatable(L, JAVA_INSTANCE_MT);
    lua_setmetatable(L, -2);

    LOGI("registerClass: proxy created with %d methods, %d interfaces", reg->method_count, iface_count);
    return 1;
}

static int lua_java_array(lua_State* L) {
    const char* class_name = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get JNIEnv");
        return 2;
    }

    jclass element_class = find_class(env, class_name);
    if (!element_class) {
        lua_pushnil(L);
        lua_pushfstring(L, "Class not found: %s", class_name);
        return 2;
    }

    int len = luaL_len(L, 2);
    jobjectArray arr = (*env)->NewObjectArray(env, len, element_class, NULL);
    if (!arr) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to create array");
        return 2;
    }

    for (int i = 0; i < len; i++) {
        lua_rawgeti(L, 2, i + 1);
        if (lua_isuserdata(L, -1)) {
            jobject* ud = (jobject*)lua_touserdata(L, -1);
            (*env)->SetObjectArrayElement(env, arr, i, *ud);
        }
        lua_pop(L, 1);
    }

    jobject global = (*env)->NewGlobalRef(env, arr);
    (*env)->DeleteLocalRef(env, arr);

    jobject* result = (jobject*)lua_newuserdata(L, sizeof(jobject));
    *result = global;
    luaL_getmetatable(L, JAVA_INSTANCE_MT);
    lua_setmetatable(L, -2);
    return 1;
}

// Java.use("com.example.Class") -> JavaClassWrapper userdata
static int lua_java_use(lua_State* L) {
    const char* class_name = luaL_checkstring(L, 1);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get JNIEnv");
        return 2;
    }

    JavaClassWrapper* wrapper = java_use(env, class_name);
    if (!wrapper) {
        lua_pushnil(L);
        lua_pushstring(L, "Class not found");
        return 2;
    }

    JavaClassWrapper** ud = (JavaClassWrapper**)lua_newuserdata(L, sizeof(JavaClassWrapper*));
    *ud = wrapper;

    // Metatable ekle
    luaL_getmetatable(L, JAVA_WRAPPER_MT);
    lua_setmetatable(L, -2);

    return 1;
}

static int lua_java_new(lua_State* L) {
    JavaClassWrapper** ud = (JavaClassWrapper**)luaL_checkudata(L, 1, JAVA_WRAPPER_MT);
    JavaClassWrapper* wrapper = *ud;
    const char* sig = luaL_optstring(L, 2, "()V");

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get JNIEnv");
        return 2;
    }
    

    jvalue args[MAX_PARAMS];
    memset(args, 0, sizeof(args));

    ParsedSignature parsed = parse_signature(sig);
    lua_to_jvalue(env, L, &parsed, args, 3);
    
    jobject instance = java_new(env, wrapper, sig, args);
    if (!instance) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to create instance");
        return 2;
    }

    jobject global_instance = (*env)->NewGlobalRef(env, instance);
    (*env)->DeleteLocalRef(env, instance);

    jobject* inst_ud = (jobject*)lua_newuserdata(L, sizeof(jobject));
    *inst_ud = global_instance;

    luaL_getmetatable(L, JAVA_INSTANCE_MT);
    lua_setmetatable(L, -2);

    return 1;
}

static int lua_java_call_static(lua_State* L) {
    JavaClassWrapper** ud = (JavaClassWrapper**)luaL_checkudata(L, 1, JAVA_WRAPPER_MT);
    JavaClassWrapper* wrapper = *ud;
    const char* method_name = luaL_checkstring(L, 2);
    const char* sig = luaL_checkstring(L, 3);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        return 1;
    }

    jvalue args[MAX_PARAMS];
    memset(args, 0, sizeof(args));
    
    ParsedSignature parsed = parse_signature(sig);
    lua_to_jvalue(env,L,&parsed,args,4);
    

    jvalue result = call_static_method(env, wrapper, method_name, sig, args);



    switch (parsed.return_type) {
        case 'V':
            return 0;
        case 'Z':
            lua_pushboolean(L, result.z);
            return 1;
        case 'I':
            lua_pushinteger(L, result.i);
            return 1;
        case 'J':
            lua_pushinteger(L, (lua_Integer)result.j);
            return 1;
        case 'F':
            lua_pushnumber(L, result.f);
            return 1;
        case 'D':
            lua_pushnumber(L, result.d);
            return 1;
        case 'L':
        case '[':
            if (result.l) {
                jclass string_class = (*env)->FindClass(env, "java/lang/String");
                if ((*env)->IsInstanceOf(env, result.l, string_class)) {
                    const char* str = (*env)->GetStringUTFChars(env, (jstring)result.l, NULL);
                    lua_pushstring(L, str);
                    (*env)->ReleaseStringUTFChars(env, (jstring)result.l, str);
                } else {
                    jobject global = (*env)->NewGlobalRef(env, result.l);
                    jobject* obj_ud = (jobject*)lua_newuserdata(L, sizeof(jobject));
                    *obj_ud = global;
                    luaL_getmetatable(L, JAVA_INSTANCE_MT);
                    lua_setmetatable(L, -2);
                }
                (*env)->DeleteLocalRef(env, result.l);
            } else {
                lua_pushnil(L);
            }
            return 1;
        default:
            lua_pushnil(L);
            return 1;
    }
}

static int lua_java_call_instance(lua_State* L) {
    jobject* ud = (jobject*)luaL_checkudata(L, 1, JAVA_INSTANCE_MT);
    jobject instance = *ud;
    const char* method_name = luaL_checkstring(L, 2);
    const char* sig = luaL_checkstring(L, 3);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        return 1;
    }

    jvalue args[MAX_PARAMS];
    memset(args, 0, sizeof(args));

    ParsedSignature parsed = parse_signature(sig);
    lua_to_jvalue(env,L,&parsed,args,4);
    
    jvalue result = call_instance_method(env, instance, method_name, sig, args);

    switch (parsed.return_type) {
        case 'V':
            return 0;
        case 'Z':
            lua_pushboolean(L, result.z);
            return 1;
        case 'I':
            lua_pushinteger(L, result.i);
            return 1;
        case 'J':
            lua_pushinteger(L, (lua_Integer)result.j);
            return 1;
        case 'F':
            lua_pushnumber(L, result.f);
            return 1;
        case 'D':
            lua_pushnumber(L, result.d);
            return 1;
        case 'L':
        case '[':
            if (result.l) {
                jclass string_class = (*env)->FindClass(env, "java/lang/String");
                if ((*env)->IsInstanceOf(env, result.l, string_class)) {
                    const char* str = (*env)->GetStringUTFChars(env, (jstring)result.l, NULL);
                    lua_pushstring(L, str);
                    (*env)->ReleaseStringUTFChars(env, (jstring)result.l, str);
                } else {
                    jobject global = (*env)->NewGlobalRef(env, result.l);
                    jobject* obj_ud = (jobject*)lua_newuserdata(L, sizeof(jobject));
                    *obj_ud = global;
                    luaL_getmetatable(L, JAVA_INSTANCE_MT);
                    lua_setmetatable(L, -2);
                }
                (*env)->DeleteLocalRef(env, result.l);
            } else {
                lua_pushnil(L);
            }
            return 1;
        default:
            lua_pushnil(L);
            return 1;
    }
}

static int lua_java_wrapper_gc(lua_State* L) {
    JavaClassWrapper** ud = (JavaClassWrapper**)luaL_checkudata(L, 1, JAVA_WRAPPER_MT);
    JavaClassWrapper* wrapper = *ud;

    if (wrapper) {
        JNIEnv* env = get_jni_env();
        if (env && wrapper->clazz) {
            (*env)->DeleteGlobalRef(env, wrapper->clazz);
        }
        free(wrapper);
    }

    return 0;
}

static int lua_java_instance_gc(lua_State* L) {
    jobject* ud = (jobject*)luaL_checkudata(L, 1, JAVA_INSTANCE_MT);
    jobject instance = *ud;

    if (instance) {
        JNIEnv* env = get_jni_env();
        if (env) {
            (*env)->DeleteGlobalRef(env, instance);
        }
    }

    return 0;
}

static const luaL_Reg java_wrapper_methods[] = {
    {"new", lua_java_new},
    {"call", lua_java_call_static},
    {"__gc", lua_java_wrapper_gc},
    {NULL, NULL}
};

static int lua_java_instance_index(lua_State* L) {
    const char* key = luaL_checkstring(L, 2);
    if (strcmp(key, "raw") == 0) {
        jobject* ud = (jobject*)lua_touserdata(L, 1);
        if (*ud) {
            JNIEnv* env = get_jni_env();
            if (env) {
                void* raw = jni_ref_to_raw_ptr(env, *ud);
                lua_pushinteger(L, (lua_Integer)(uintptr_t)raw);
            } else {
                lua_pushinteger(L, (lua_Integer)(uintptr_t)*ud);
            }
        } else {
            lua_pushinteger(L, 0);
        }
        return 1;
    }
    if (strcmp(key, "call") == 0) {
        lua_pushcfunction(L, lua_java_call_instance);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

static const luaL_Reg java_instance_methods[] = {
    {"__gc", lua_java_instance_gc},
    {NULL, NULL}
};

void lua_register_java(lua_State* L) {
    luaL_newmetatable(L, JAVA_WRAPPER_MT);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, java_wrapper_methods, 0);
    lua_pop(L, 1);

    luaL_newmetatable(L, JAVA_INSTANCE_MT);
    lua_pushcfunction(L, lua_java_instance_index);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, java_instance_methods, 0);
    lua_pop(L, 1);

    lua_newtable(L);

    lua_pushcfunction(L, lua_java_use);
    lua_setfield(L, -2, "use");

    lua_pushcfunction(L, lua_java_register_class);
    lua_setfield(L, -2, "registerClass");

    lua_pushcfunction(L, lua_java_array);
    lua_setfield(L, -2, "array");

    lua_setglobal(L, "Java");

    LOGI("Java API registered");
}
