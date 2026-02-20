#pragma once

#include <memory>
#include <string>
#include <vector>
#include <ftxui/component/component.hpp>
#include "../tui_state.h"

ftxui::Component CreateConsoleTab(std::shared_ptr<TuiState> state);
