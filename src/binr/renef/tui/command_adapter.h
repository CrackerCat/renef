#pragma once

#include <string>
#include <memory>
#include <functional>
#include <atomic>
#include "tui_state.h"

class CommandAdapter {
public:
    // Execute command through CommandRegistry dispatch, capture fd output
    static std::string execute(const std::string& command);

    // Execute on background thread, callback receives result
    static void execute_async(const std::string& command,
                              std::shared_ptr<TuiState> state,
                              std::function<void(const std::string&)> callback);

    // Execute via ServerConnection (for commands that go through the server path)
    static std::string execute_server(const std::string& command);
};
