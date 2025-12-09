#include "hooks.h"
#include "socket_helper.h"
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <poll.h>

std::string HooksCommand::get_name() const {
    return "hooks";
}

std::string HooksCommand::get_description() const {
    return "List active hooks";
}

CommandResult HooksCommand::dispatch(int client_fd, const char* /* cmd_buffer */, size_t /* cmd_size */) {
    int pid = CommandRegistry::instance().get_current_pid();

    if (pid <= 0) {
        const char* error_msg = "ERROR: No target PID set. Please attach/spawn first.\n";
        write(client_fd, error_msg, strlen(error_msg));
        return CommandResult(false, "No target PID set");
    }

    SocketHelper& socket_helper = CommandRegistry::instance().get_socket_helper();
    int sock = socket_helper.ensure_connection(pid);

    if (sock < 0) {
        const char* error_msg = "ERROR: Failed to connect to agent\n";
        write(client_fd, error_msg, strlen(error_msg));
        return CommandResult(false, "Socket connection failed");
    }

    const char* cmd = "hooks\n";
    socket_helper.send_data(cmd, strlen(cmd));

    char buffer[1024];
    struct pollfd pfd = {sock, POLLIN, 0};
    int ret = poll(&pfd, 1, 2000);

    if (ret > 0 && (pfd.revents & POLLIN)) {
        ssize_t n = ::recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            write(client_fd, buffer, n);
        }
    } else {
        const char* error = "ERROR: No response from agent\n";
        write(client_fd, error, strlen(error));
    }

    return CommandResult(true, "Hooks listed");
}

std::string UnhookCommand::get_name() const {
    return "unhook";
}

std::string UnhookCommand::get_description() const {
    return "Remove hook(s): unhook [id] or unhook all";
}

CommandResult UnhookCommand::dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) {
    int pid = CommandRegistry::instance().get_current_pid();

    if (pid <= 0) {
        const char* error_msg = "ERROR: No target PID set. Please attach/spawn first.\n";
        write(client_fd, error_msg, strlen(error_msg));
        return CommandResult(false, "No target PID set");
    }

    SocketHelper& socket_helper = CommandRegistry::instance().get_socket_helper();
    int sock = socket_helper.ensure_connection(pid);

    if (sock < 0) {
        const char* error_msg = "ERROR: Failed to connect to agent\n";
        write(client_fd, error_msg, strlen(error_msg));
        return CommandResult(false, "Socket connection failed");
    }

    std::string cmd(cmd_buffer, cmd_size);
    if (cmd.empty() || cmd.back() != '\n') {
        cmd += "\n";
    }
    socket_helper.send_data(cmd.c_str(), cmd.size());

    char buffer[256];
    struct pollfd pfd = {sock, POLLIN, 0};
    int ret = poll(&pfd, 1, 2000);

    if (ret > 0 && (pfd.revents & POLLIN)) {
        ssize_t n = ::recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            write(client_fd, buffer, n);
        }
    } else {
        const char* error = "ERROR: No response from agent\n";
        write(client_fd, error, strlen(error));
    }

    return CommandResult(true, "Unhook completed");
}
