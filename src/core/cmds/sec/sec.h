#ifndef SEC_H
#define SEC_H

#include "cmd.h"

class SecCommand : public CommandDispatcher {
public:
    std::string get_name() const override;
    std::string get_description() const override;
    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override;
};

#endif
