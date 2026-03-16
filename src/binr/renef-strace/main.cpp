#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <cstring>
#include <csignal>
#include <cerrno>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <getopt.h>

#define DEFAULT_TCP_PORT 1907
#define DEFAULT_HOST "127.0.0.1"

// ANSI color codes
#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"
#define C_RED     "\033[31m"
#define C_GREEN   "\033[32m"
#define C_YELLOW  "\033[33m"
#define C_CYAN    "\033[36m"
#define C_MAGENTA "\033[35m"

static volatile bool g_running = true;
static int g_sock_fd = -1;
static bool g_no_color = false;

// Colorize a single strace output line
// Format: [tid:1234] openat(AT_FDCWD, "/data/...", O_RDONLY) = 3
static void colorize_line(const std::string& line) {
    if (g_no_color || line.empty()) {
        std::cout << line << "\n";
        return;
    }

    size_t pos = 0;

    // [tid:XXXX] part — dim
    if (line[0] == '[') {
        size_t bracket_end = line.find(']');
        if (bracket_end != std::string::npos) {
            std::cout << C_DIM << line.substr(0, bracket_end + 1) << C_RESET << " ";
            pos = bracket_end + 1;
            while (pos < line.size() && line[pos] == ' ') pos++;
        }
    }

    // Find syscall name (until '(')
    size_t paren = line.find('(', pos);
    if (paren != std::string::npos) {
        std::string syscall_name = line.substr(pos, paren - pos);
        std::cout << C_BOLD << C_YELLOW << syscall_name << C_RESET;
        pos = paren;
    }

    size_t eq_pos = line.rfind(" = ");
    std::string args_part;
    std::string ret_part;

    if (eq_pos != std::string::npos && eq_pos > pos) {
        args_part = line.substr(pos, eq_pos - pos);
        ret_part = line.substr(eq_pos);
    } else {
        args_part = line.substr(pos);
    }

    size_t i = 0;
    while (i < args_part.size()) {
        if (args_part[i] == '"') {
            size_t end = args_part.find('"', i + 1);
            if (end != std::string::npos) {
                std::cout << C_CYAN << args_part.substr(i, end - i + 1) << C_RESET;
                i = end + 1;
                continue;
            }
        }
        if (args_part[i] == '<') {
            size_t end = args_part.find('>', i + 1);
            if (end != std::string::npos) {
                std::cout << C_CYAN << args_part.substr(i, end - i + 1) << C_RESET;
                i = end + 1;
                continue;
            }
        }
        if (args_part[i] == 'O' && i + 1 < args_part.size() && args_part[i + 1] == '_') {
            size_t end = i + 2;
            while (end < args_part.size() &&
                   (args_part[end] == '_' || (args_part[end] >= 'A' && args_part[end] <= 'Z') || args_part[end] == '|'))
                end++;
            std::cout << C_MAGENTA << args_part.substr(i, end - i) << C_RESET;
            i = end;
            continue;
        }
        // AT_FDCWD — magenta
        if (args_part.compare(i, 8, "AT_FDCWD") == 0) {
            std::cout << C_MAGENTA << "AT_FDCWD" << C_RESET;
            i += 8;
            continue;
        }
        std::cout << args_part[i];
        i++;
    }

    if (!ret_part.empty()) {
        size_t val_start = ret_part.find("= ");
        if (val_start != std::string::npos) {
            std::string val = ret_part.substr(val_start + 2);

            size_t vs = val.find_first_not_of(" ");
            if (vs != std::string::npos) val = val.substr(vs);

            bool is_error = false;
            if (!val.empty() && val[0] == '-') is_error = true;

            if (ret_part.find('(') != std::string::npos) is_error = true;

            if (is_error) {
                std::cout << C_RED << ret_part << C_RESET;
            } else {
                std::cout << " = " << C_GREEN << val << C_RESET;
            }
        } else {
            std::cout << ret_part;
        }
    }

    std::cout << "\n";
}

static std::string g_line_buffer;

static void process_output(const char* data, size_t len) {
    g_line_buffer.append(data, len);

    size_t start = 0;
    while (true) {
        size_t nl = g_line_buffer.find('\n', start);
        if (nl == std::string::npos) break;

        std::string line = g_line_buffer.substr(start, nl - start);
        if (!line.empty()) {
            colorize_line(line);
        }
        start = nl + 1;
    }

    if (start > 0) {
        g_line_buffer = g_line_buffer.substr(start);
    }
}

static void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " -p <pid> [options] [syscalls]\n\n"
              << "Options:\n"
              << "  -p <pid>          Target process PID (required)\n"
              << "  -c <category>     Trace by category: file, network, memory, process, ipc\n"
              << "  -f <library>      Filter by caller library\n"
              << "  -a                Trace all syscalls\n"
              << "  --list            List available syscalls\n"
              << "  --active          Show active traces\n"
              << "  --stop            Stop all tracing\n"
              << "  --no-color        Disable colored output\n"
              << "  -d <device>       ADB device ID (for multiple devices)\n"
              << "  -H <host>         Server host (default: 127.0.0.1)\n"
              << "  -P <port>         Server port (default: 1907)\n"
              << "  -h, --help        Show this help\n\n"
              << "Examples:\n"
              << "  " << prog << " -p 1234 open,read,write,close\n"
              << "  " << prog << " -p 1234 -c file\n"
              << "  " << prog << " -p 1234 -c network\n"
              << "  " << prog << " -p 1234 -a\n"
              << "  " << prog << " -p 1234 open,read -f libnative.so\n"
              << "  " << prog << " -p 1234 --stop\n";
}

static std::string generate_trace_lua(const std::string& syscalls, const std::string& filter_lib) {
    std::vector<std::string> names;
    std::istringstream ss(syscalls);
    std::string token;
    while (std::getline(ss, token, ',')) {
        size_t start = token.find_first_not_of(" \t");
        size_t end = token.find_last_not_of(" \t");
        if (start != std::string::npos) {
            names.push_back(token.substr(start, end - start + 1));
        }
    }

    if (names.empty()) return "print('No syscalls specified')";

    std::string lua = "Syscall.trace(";
    for (size_t i = 0; i < names.size(); i++) {
        if (i > 0) lua += ", ";
        lua += "'" + names[i] + "'";
    }

    if (!filter_lib.empty()) {
        lua += ", { caller = '" + filter_lib + "' }";
    }

    lua += ")";
    return lua;
}

static bool check_adb_devices(std::string& device_id) {
    FILE* pipe = popen("adb devices", "r");
    if (!pipe) return false;

    char buffer[256];
    std::vector<std::string> devices;

    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            std::string line(buffer);
            size_t start = line.find_first_not_of(" \t\n\r");
            size_t end = line.find_last_not_of(" \t\n\r");
            if (start != std::string::npos && end != std::string::npos) {
                line = line.substr(start, end - start + 1);
            }
            if (!line.empty() && line.find("device") != std::string::npos) {
                size_t tab_pos = line.find('\t');
                if (tab_pos == std::string::npos) tab_pos = line.find(' ');
                if (tab_pos != std::string::npos) {
                    devices.push_back(line.substr(0, tab_pos));
                }
            }
        }
    }
    pclose(pipe);

    if (devices.empty()) {
        std::cerr << "Error: No ADB devices connected\n";
        return false;
    }
    if (devices.size() == 1) {
        device_id = devices[0];
        return true;
    }
    if (device_id.empty()) {
        std::cerr << "Error: Multiple devices found. Use -d <device_id>:\n";
        for (const auto& dev : devices) std::cerr << "  - " << dev << "\n";
        return false;
    }
    for (const auto& dev : devices) {
        if (dev == device_id) return true;
    }
    std::cerr << "Error: Device '" << device_id << "' not found\n";
    return false;
}

// Setup ADB port forwarding (same as renef CLI)
static bool setup_adb_forward(const std::string& device_id, int port) {
    std::string cmd = "adb";
    if (!device_id.empty()) cmd += " -s " + device_id;
    cmd += " forward tcp:" + std::to_string(port) + " localabstract:com.android.internal.os.RuntimeInit";

    int ret = system(cmd.c_str());
    if (ret != 0) {
        std::cerr << "Warning: Failed to setup ADB port forwarding\n";
        return false;
    }
    return true;
}

static int try_tcp_connect(const std::string& host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host.c_str());

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int connect_to_server(const std::string& host, int port, const std::string& device_id) {
    int fd = try_tcp_connect(host, port);
    if (fd >= 0) return fd;

    std::cerr << "[*] Connection failed, setting up ADB forward...\n";

    std::string dev_id = device_id;
    if (!check_adb_devices(dev_id)) {
        return -1;
    }

    std::cerr << "[*] Using device: " << dev_id << "\n";

    if (!setup_adb_forward(dev_id, port)) {
        std::cerr << "Error: Failed to setup ADB port forwarding\n";
        return -1;
    }

    std::cerr << "[*] ADB forward established, connecting...\n";

    // Retry connection
    fd = try_tcp_connect(host, port);
    if (fd < 0) {
        std::cerr << "Error: Still cannot connect to renef_server at " << host << ":" << port << "\n";
        std::cerr << "Make sure renef_server is running on the Android device\n";
        return -1;
    }

    return fd;
}

static std::string send_and_receive(int fd, const std::string& cmd, int timeout_ms = 3000) {
    std::string full = cmd + "\n";
    ssize_t sent = send(fd, full.c_str(), full.length(), MSG_NOSIGNAL);
    if (sent <= 0) return "";

    std::string result;
    char buffer[4096];

    int elapsed = 0;
    bool got_data = false;

    while (elapsed < timeout_ms) {
        struct pollfd pfd = {fd, POLLIN, 0};
        int ret = poll(&pfd, 1, 100);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recv(fd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
            if (n > 0) {
                buffer[n] = '\0';
                result += buffer;
                got_data = true;
                elapsed = 0; // Reset on data
            } else if (n == 0) {
                break; // Connection closed
            }
        } else {
            elapsed += 100;
            if (got_data && elapsed >= 300) break;
        }
    }

    return result;
}

int main(int argc, char* argv[]) {
    int pid = -1;
    std::string category;
    std::string filter_lib;
    std::string host = DEFAULT_HOST;
    std::string device_id;
    int port = DEFAULT_TCP_PORT;
    bool trace_all = false;
    bool do_list = false;
    bool do_active = false;
    bool do_stop = false;

    static struct option long_options[] = {
        {"list",     no_argument, 0, 'L'},
        {"active",   no_argument, 0, 'A'},
        {"stop",     no_argument, 0, 'S'},
        {"no-color", no_argument, 0, 'N'},
        {"help",     no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:c:f:d:aH:P:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p': pid = atoi(optarg); break;
            case 'c': category = optarg; break;
            case 'f': filter_lib = optarg; break;
            case 'd': device_id = optarg; break;
            case 'a': trace_all = true; break;
            case 'H': host = optarg; break;
            case 'P': port = atoi(optarg); break;
            case 'L': do_list = true; break;
            case 'A': do_active = true; break;
            case 'S': do_stop = true; break;
            case 'N': g_no_color = true; break;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

    if (!isatty(STDOUT_FILENO)) g_no_color = true;

    if (pid <= 0) {
        std::cerr << "Error: -p <pid> is required\n";
        print_usage(argv[0]);
        return 1;
    }

    std::string syscalls;
    for (int i = optind; i < argc; i++) {
        if (!syscalls.empty()) syscalls += ",";
        syscalls += argv[i];
    }

    // Generate Lua code
    std::string lua_code;
    if (do_stop) {
        lua_code = "Syscall.stop()";
    } else if (do_list) {
        lua_code = "Syscall.list()";
    } else if (do_active) {
        lua_code = "Syscall.active()";
    } else if (trace_all) {
        lua_code = "Syscall.traceAll()";
    } else if (!category.empty()) {
        lua_code = "Syscall.trace({ category = '" + category + "' })";
    } else if (!syscalls.empty()) {
        lua_code = generate_trace_lua(syscalls, filter_lib);
    } else {
        std::cerr << "Error: No syscalls specified\n";
        print_usage(argv[0]);
        return 1;
    }

    // Step 1: Connect to renef_server via TCP (through ADB forward)
    int sock = connect_to_server(host, port, device_id);
    if (sock < 0) return 1;
    g_sock_fd = sock;

    // Step 2: Attach to target PID
    std::string attach_cmd = "attach " + std::to_string(pid);
    std::string attach_resp = send_and_receive(sock, attach_cmd, 5000);
    if (attach_resp.empty()) {
        std::cerr << "Error: No response from server for attach command\n";
        close(sock);
        return 1;
    }
    std::cerr << attach_resp;

    if (attach_resp.find("ERROR") != std::string::npos ||
        attach_resp.find("error") != std::string::npos ||
        attach_resp.find("Failed") != std::string::npos) {
        close(sock);
        return 1;
    }

    // Step 3: Build the renef-strace server command
    // Instead of exec+watch, we use the server's built-in renef-strace command
    // which handles Syscall.stop() cleanup directly via agent UDS
    std::string server_cmd;
    if (do_stop) {
        server_cmd = "renef-strace --stop";
    } else if (do_list) {
        server_cmd = "renef-strace --list";
    } else if (do_active) {
        server_cmd = "renef-strace --active";
    } else if (trace_all) {
        server_cmd = "renef-strace -a";
    } else if (!category.empty()) {
        server_cmd = "renef-strace -c " + category;
    } else {
        server_cmd = "renef-strace " + syscalls;
        if (!filter_lib.empty()) {
            server_cmd += " -f " + filter_lib;
        }
    }

    if (do_stop || do_list || do_active) {
        std::string resp = send_and_receive(sock, server_cmd, 3000);
        if (!resp.empty()) {
            std::cout << resp;
            if (resp.back() != '\n') std::cout << '\n';
        }
        close(sock);
        return 0;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::cerr << "Tracing syscalls on PID " << pid << "... (Ctrl+C to stop)\n";

    std::string full_cmd = server_cmd + "\n";
    send(sock, full_cmd.c_str(), full_cmd.length(), MSG_NOSIGNAL);

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    char buffer[4096];

    while (g_running) {
        struct pollfd pfd = {sock, POLLIN, 0};
        int ret = poll(&pfd, 1, 500);

        if (ret > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (n > 0) {
                buffer[n] = '\0';
                process_output(buffer, n);
            } else if (n == 0) {
                std::cerr << "Server disconnected\n";
                break;
            }
        } else if (ret < 0 && errno != EINTR) {
            std::cerr << "poll error: " << strerror(errno) << "\n";
            break;
        }
    }

    std::cerr << "\nStopping trace...\n";
    fcntl(sock, F_SETFL, flags);

    std::string quit_cmd = "q\n";
    send(sock, quit_cmd.c_str(), quit_cmd.length(), MSG_NOSIGNAL);

    {
        struct pollfd pfd = {sock, POLLIN, 0};
        for (int i = 0; i < 10; i++) {
            int ret = poll(&pfd, 1, 200);
            if (ret > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (n <= 0) break;
            } else {
                break;
            }
        }
    }

    close(sock);
    return 0;
}
