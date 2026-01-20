#include "renef.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <thread>
#include <atomic>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <string>

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 1907

// Opaque struct definition
struct RenefSession {
    int sock_fd;
    int pid;
    std::string session_key;

    // Watch state
    std::thread watch_thread;
    std::atomic<bool> watch_running{false};
    RenefMessageCallback message_callback;
    void* callback_user_data;
};

// Helper: connect to server
static int connect_to_server(const char* host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

static std::string send_command(int sock, const std::string& cmd, int timeout_ms = 5000) {
    ssize_t sent = send(sock, cmd.c_str(), cmd.length(), 0);
    if (sent < 0) return "";

    std::string response;
    char buffer[4096];
    int elapsed = 0;
    const int poll_interval = 100;

    while (elapsed < timeout_ms) {
        struct pollfd pfd = {sock, POLLIN, 0};
        int ret = poll(&pfd, 1, poll_interval);

        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (n > 0) {
                buffer[n] = '\0';
                response += buffer;

                if (response.find("\342\234\223 Lua") != std::string::npos ||  // ✓
                    response.find("\342\234\227 Lua") != std::string::npos ||  // ✗
                    (response.find("OK") == 0 && response.find("\n") != std::string::npos) ||
                    (response.find("FAIL") == 0 && response.find("\n") != std::string::npos) ||
                    (response.find("ERROR") == 0 && response.find("\n") != std::string::npos)) {
                    break;
                }
            } else if (n == 0) {
                break;
            }
        } else if (ret == 0) {
            elapsed += poll_interval;
        } else {
            break;
        }
    }

    return response;
}

RenefSession* renef_spawn(const char* package, int hook_type) {
    if (!package || strlen(package) == 0) return nullptr;

    int sock = connect_to_server(DEFAULT_HOST, DEFAULT_PORT);
    if (sock < 0) return nullptr;

    std::string hook_str = (hook_type == 0) ? "trampoline" : "plt";
    std::string cmd = std::string("spawn ") + package + " --hook=" + hook_str + "\n";

    std::string response = send_command(sock, cmd, 15000);  // 15s timeout for spawn

    int pid = 0;
    if (response.find("OK ") == 0) {
        sscanf(response.c_str(), "OK %d", &pid);
    }

    if (pid <= 0) {
        close(sock);
        return nullptr;
    }

    RenefSession* session = new RenefSession();
    session->sock_fd = sock;
    session->pid = pid;

    return session;
}

RenefSession* renef_attach(int pid, int hook_type) {
    if (pid <= 0) return nullptr;

    int sock = connect_to_server(DEFAULT_HOST, DEFAULT_PORT);
    if (sock < 0) return nullptr;

    std::string hook_str = (hook_type == 0) ? "trampoline" : "plt";
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "attach %d --hook=%s\n", pid, hook_str.c_str());

    std::string response = send_command(sock, cmd, 10000);

    if (response.find("OK") != 0) {
        close(sock);
        return nullptr;
    }

    RenefSession* session = new RenefSession();
    session->sock_fd = sock;
    session->pid = pid;

    return session;
}

void renef_session_close(RenefSession* session) {
    if (!session) return;
    renef_watch_stop(session);
    if (session->sock_fd >= 0) {
        close(session->sock_fd);
        session->sock_fd = -1;
    }
    delete session;
}

int renef_session_pid(RenefSession* session) {
    if (!session) return -1;
    return session->pid;
}

RenefResult renef_eval(RenefSession* session, const char* lua_code) {
    RenefResult result = {0, nullptr, nullptr};

    if (!session || !lua_code || session->sock_fd < 0) {
        result.error = strdup("Invalid arguments");
        return result;
    }

    std::string cmd = std::string("exec ") + lua_code + "\n";
    std::string response = send_command(session->sock_fd, cmd);

    result.success = 1;
    result.output = response.empty() ? nullptr : strdup(response.c_str());

    return result;
}

RenefResult renef_load_script(RenefSession* session, const char* path) {
    RenefResult result = {0, nullptr, nullptr};

    if (!session || !path || session->sock_fd < 0) {
        result.error = strdup("Invalid arguments");
        return result;
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        result.error = strdup("Failed to open script file");
        return result;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string script = buffer.str();

    std::string cmd = "load " + script + "\n";
    std::string response = send_command(session->sock_fd, cmd, 10000);

    result.success = 1;
    result.output = response.empty() ? nullptr : strdup(response.c_str());

    return result;
}

RenefResult renef_memscan(RenefSession* session, const char* pattern) {
    RenefResult result = {0, nullptr, nullptr};

    if (!session || !pattern || session->sock_fd < 0) {
        result.error = strdup("Invalid arguments");
        return result;
    }

    std::string cmd = std::string("ms ") + pattern + "\n";
    std::string response = send_command(session->sock_fd, cmd, 30000);

    result.success = 1;
    result.output = response.empty() ? nullptr : strdup(response.c_str());

    return result;
}

uint64_t renef_module_find(RenefSession* session, const char* name) {
    if (!session || !name) return 0;

    std::string lua = std::string("local addr = Module.find('") + name + "'); print(addr and string.format('0x%x', addr) or '0')";
    RenefResult result = renef_eval(session, lua.c_str());

    uint64_t addr = 0;
    if (result.success && result.output) {
        addr = strtoull(result.output, nullptr, 0);
    }

    renef_result_free(&result);
    return addr;
}

ssize_t renef_read_memory(RenefSession* session, uint64_t addr, size_t size, uint8_t* out) {
    if (!session || !out || size == 0) return -1;

    char lua[512];
    snprintf(lua, sizeof(lua),
             "local data = Memory.read(0x%lx, %zu); "
             "if data then "
             "  local hex = ''; "
             "  for i = 1, #data do hex = hex .. string.format('%%02x', string.byte(data, i)) end; "
             "  print(hex) "
             "else print('') end",
             (unsigned long)addr, size);

    RenefResult result = renef_eval(session, lua);
    if (!result.success || !result.output || strlen(result.output) == 0) {
        renef_result_free(&result);
        return -1;
    }

    const char* hex = result.output;
    size_t hex_len = strlen(hex);
    size_t bytes_read = 0;

    for (size_t i = 0; i + 1 < hex_len && bytes_read < size; i += 2) {
        char byte_str[3] = {hex[i], hex[i+1], '\0'};
        out[bytes_read++] = (uint8_t)strtoul(byte_str, nullptr, 16);
    }

    renef_result_free(&result);
    return (ssize_t)bytes_read;
}

ssize_t renef_write_memory(RenefSession* session, uint64_t addr, const uint8_t* data, size_t size) {
    if (!session || !data || size == 0) return -1;

    std::string hex;
    for (size_t i = 0; i < size; i++) {
        char buf[8];
        snprintf(buf, sizeof(buf), "\\x%02x", data[i]);
        hex += buf;
    }

    char lua[1024];
    snprintf(lua, sizeof(lua),
             "Memory.write(0x%lx, \"%s\")",
             (unsigned long)addr, hex.c_str());

    RenefResult result = renef_eval(session, lua);
    bool success = result.success;
    renef_result_free(&result);

    return success ? (ssize_t)size : -1;
}

int renef_hook(RenefSession* session, const char* lib, uint64_t offset,
               const char* on_enter, const char* on_leave) {
    if (!session || !lib) return -1;

    std::string lua = "hook('" + std::string(lib) + "', 0x";
    char offset_str[32];
    snprintf(offset_str, sizeof(offset_str), "%lx", (unsigned long)offset);
    lua += offset_str;
    lua += ", {";

    if (on_enter && strlen(on_enter) > 0) {
        lua += "onEnter = function(args) " + std::string(on_enter) + " end";
    }
    if (on_leave && strlen(on_leave) > 0) {
        if (on_enter && strlen(on_enter) > 0) lua += ", ";
        lua += "onLeave = function(retval) " + std::string(on_leave) + " end";
    }
    lua += "})";

    RenefResult result = renef_eval(session, lua.c_str());
    bool success = result.success;
    renef_result_free(&result);

    return success ? 0 : -1;
}

int renef_unhook(RenefSession* session, int hook_id) {
    if (!session) return -1;

    char lua[64];
    snprintf(lua, sizeof(lua), "unhook(%d)", hook_id);

    RenefResult result = renef_eval(session, lua);
    bool success = result.success;
    renef_result_free(&result);

    return success ? 0 : -1;
}

// Module API
RenefResult renef_module_list(RenefSession* session) {
    RenefResult result = {0, nullptr, nullptr};
    if (!session) {
        result.error = strdup("Invalid session");
        return result;
    }

    const char* lua = "local mods = Module.list(); for _, m in ipairs(mods) do print(string.format('0x%x %s', m.base, m.name)) end";
    return renef_eval(session, lua);
}

RenefResult renef_module_exports(RenefSession* session, const char* name) {
    RenefResult result = {0, nullptr, nullptr};
    if (!session || !name) {
        result.error = strdup("Invalid arguments");
        return result;
    }

    std::string lua = "local exp = Module.exports('" + std::string(name) + "'); if exp then for _, e in ipairs(exp) do print(string.format('0x%x %s', e.offset, e.name)) end end";
    return renef_eval(session, lua.c_str());
}

RenefResult renef_module_symbols(RenefSession* session, const char* name) {
    RenefResult result = {0, nullptr, nullptr};
    if (!session || !name) {
        result.error = strdup("Invalid arguments");
        return result;
    }

    std::string lua = "local syms = Module.symbols('" + std::string(name) + "'); if syms then for _, s in ipairs(syms) do print(string.format('0x%x %s', s.offset, s.name)) end end";
    return renef_eval(session, lua.c_str());
}

// Memory read helpers
uint8_t renef_read_u8(RenefSession* session, uint64_t addr) {
    if (!session) return 0;

    char lua[128];
    snprintf(lua, sizeof(lua), "local v = Memory.readU8(0x%lx); print(v or 0)", (unsigned long)addr);

    RenefResult result = renef_eval(session, lua);
    uint8_t val = 0;
    if (result.success && result.output) {
        val = (uint8_t)strtoul(result.output, nullptr, 10);
    }
    renef_result_free(&result);
    return val;
}

uint16_t renef_read_u16(RenefSession* session, uint64_t addr) {
    if (!session) return 0;

    char lua[128];
    snprintf(lua, sizeof(lua), "local v = Memory.readU16(0x%lx); print(v or 0)", (unsigned long)addr);

    RenefResult result = renef_eval(session, lua);
    uint16_t val = 0;
    if (result.success && result.output) {
        val = (uint16_t)strtoul(result.output, nullptr, 10);
    }
    renef_result_free(&result);
    return val;
}

uint32_t renef_read_u32(RenefSession* session, uint64_t addr) {
    if (!session) return 0;

    char lua[128];
    snprintf(lua, sizeof(lua), "local v = Memory.readU32(0x%lx); print(v or 0)", (unsigned long)addr);

    RenefResult result = renef_eval(session, lua);
    uint32_t val = 0;
    if (result.success && result.output) {
        val = (uint32_t)strtoul(result.output, nullptr, 10);
    }
    renef_result_free(&result);
    return val;
}

uint64_t renef_read_u64(RenefSession* session, uint64_t addr) {
    if (!session) return 0;

    char lua[128];
    snprintf(lua, sizeof(lua), "local v = Memory.readU64(0x%lx); print(v or 0)", (unsigned long)addr);

    RenefResult result = renef_eval(session, lua);
    uint64_t val = 0;
    if (result.success && result.output) {
        val = strtoull(result.output, nullptr, 10);
    }
    renef_result_free(&result);
    return val;
}

RenefResult renef_read_string(RenefSession* session, uint64_t addr, size_t max_len) {
    RenefResult result = {0, nullptr, nullptr};
    if (!session) {
        result.error = strdup("Invalid session");
        return result;
    }

    char lua[256];
    snprintf(lua, sizeof(lua), "local s = Memory.readString(0x%lx, %zu); print(s or '')", (unsigned long)addr, max_len);
    return renef_eval(session, lua);
}

// Memory write helpers
int renef_write_u8(RenefSession* session, uint64_t addr, uint8_t val) {
    if (!session) return -1;

    char lua[128];
    snprintf(lua, sizeof(lua), "Memory.writeU8(0x%lx, %u)", (unsigned long)addr, val);

    RenefResult result = renef_eval(session, lua);
    bool success = result.success;
    renef_result_free(&result);
    return success ? 0 : -1;
}

int renef_write_u16(RenefSession* session, uint64_t addr, uint16_t val) {
    if (!session) return -1;

    char lua[128];
    snprintf(lua, sizeof(lua), "Memory.writeU16(0x%lx, %u)", (unsigned long)addr, val);

    RenefResult result = renef_eval(session, lua);
    bool success = result.success;
    renef_result_free(&result);
    return success ? 0 : -1;
}

int renef_write_u32(RenefSession* session, uint64_t addr, uint32_t val) {
    if (!session) return -1;

    char lua[128];
    snprintf(lua, sizeof(lua), "Memory.writeU32(0x%lx, %u)", (unsigned long)addr, val);

    RenefResult result = renef_eval(session, lua);
    bool success = result.success;
    renef_result_free(&result);
    return success ? 0 : -1;
}

int renef_write_u64(RenefSession* session, uint64_t addr, uint64_t val) {
    if (!session) return -1;

    char lua[128];
    snprintf(lua, sizeof(lua), "Memory.writeU64(0x%lx, %llu)", (unsigned long)addr, (unsigned long long)val);

    RenefResult result = renef_eval(session, lua);
    bool success = result.success;
    renef_result_free(&result);
    return success ? 0 : -1;
}

// Thread API
RenefResult renef_thread_backtrace(RenefSession* session) {
    RenefResult result = {0, nullptr, nullptr};
    if (!session) {
        result.error = strdup("Invalid session");
        return result;
    }

    return renef_eval(session, "local bt = Thread.backtrace(); for _, frame in ipairs(bt) do print(frame) end");
}

uint64_t renef_thread_id(RenefSession* session) {
    if (!session) return 0;

    RenefResult result = renef_eval(session, "print(Thread.id())");
    uint64_t tid = 0;
    if (result.success && result.output) {
        tid = strtoull(result.output, nullptr, 10);
    }
    renef_result_free(&result);
    return tid;
}

// Java hook
int renef_hook_java(RenefSession* session, const char* class_name, const char* method_name,
                    const char* signature, const char* on_enter, const char* on_leave) {
    if (!session || !class_name || !method_name || !signature) return -1;

    std::string lua = "hook('" + std::string(class_name) + "', '" + method_name + "', '" + signature + "', {";

    if (on_enter && strlen(on_enter) > 0) {
        lua += "onEnter = function(args) " + std::string(on_enter) + " end";
    }
    if (on_leave && strlen(on_leave) > 0) {
        if (on_enter && strlen(on_enter) > 0) lua += ", ";
        lua += "onLeave = function(retval) " + std::string(on_leave) + " end";
    }
    lua += "})";

    RenefResult result = renef_eval(session, lua.c_str());
    bool success = result.success;
    renef_result_free(&result);

    return success ? 0 : -1;
}

RenefResult renef_hooks_list(RenefSession* session) {
    RenefResult result = {0, nullptr, nullptr};
    if (!session) {
        result.error = strdup("Invalid session");
        return result;
    }

    // Send hooks command directly
    std::string cmd = "hooks\n";
    std::string response = send_command(session->sock_fd, cmd);

    result.success = 1;
    result.output = response.empty() ? nullptr : strdup(response.c_str());
    return result;
}

int renef_watch_start(RenefSession* session, RenefMessageCallback callback, void* user_data) {
    if (!session || !callback) return -1;
    if (session->watch_running) return -1;

    session->message_callback = callback;
    session->callback_user_data = user_data;
    session->watch_running = true;

    session->watch_thread = std::thread([session]() {
        char buffer[4096];

        while (session->watch_running && session->sock_fd >= 0) {
            struct pollfd pfd = {session->sock_fd, POLLIN, 0};
            int ret = poll(&pfd, 1, 100);

            if (ret > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = recv(session->sock_fd, buffer, sizeof(buffer) - 1, 0);
                if (n > 0) {
                    buffer[n] = '\0';
                    session->message_callback(buffer, n, session->callback_user_data);
                } else if (n == 0) {
                    break;
                }
            }
        }
    });

    return 0;
}

void renef_watch_stop(RenefSession* session) {
    if (!session) return;
    session->watch_running = false;
    if (session->watch_thread.joinable()) {
        session->watch_thread.join();
    }
}

void renef_result_free(RenefResult* result) {
    if (!result) return;
    free(result->output);
    free(result->error);
    result->output = nullptr;
    result->error = nullptr;
}
