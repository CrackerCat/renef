#pragma once

#include <memory>
#include "tui_state.h"

class TuiApp {
public:
    TuiApp();
    void set_initial_state(const ConnectionInfo& info);
    int run();

private:
    std::shared_ptr<TuiState> state_;
};
