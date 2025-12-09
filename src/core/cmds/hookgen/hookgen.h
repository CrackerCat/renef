#ifndef HOOKGEN_H
#define HOOKGEN_H

#include "cmd.h"

class HookGen : public CommandDispatcher {
public:
    HookGen() = default;
    ~HookGen() override = default;
    std::string get_name() const override;
    std::string get_description() const override;
    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override;
};

#endif
