#include "ping.h"
#include <unistd.h>
#include <cstring>

std::string PingCommand::get_name() const {
    return "ping";
}

std::string PingCommand::get_description() const {
    return "Test connection with pong response";
}

CommandResult PingCommand::dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) {
    const char* response = "pong\n";
    write(client_fd, response, strlen(response));
    return CommandResult(true, "Pong sent");
}