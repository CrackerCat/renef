#ifndef EVAL_H
#define EVAL_H

#include "cmd.h"

class Eval : public CommandDispatcher {
public:
    ~Eval() override = default;
    std::string get_name() const override;
    std::string get_description() const override;
    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override;
};

#endif
