#pragma once

#include "cmd.h"

class AttachCommand : public CommandDispatcher {
public:
    std::string get_name() const override;
    std::string get_description() const override;
    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override;
};