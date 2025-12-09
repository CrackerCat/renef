#ifndef MEMSCAN_H
#define MEMSCAN_H

#include "cmd.h"

class MemScan : public CommandDispatcher {
public:
    ~MemScan() override = default;
    std::string get_name() const override;
    std::string get_description() const override;
    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override;
};

class MemScanJson : public CommandDispatcher {
public:
    ~MemScanJson() override = default;
    std::string get_name() const override;
    std::string get_description() const override;
    CommandResult dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) override;
};

#endif
