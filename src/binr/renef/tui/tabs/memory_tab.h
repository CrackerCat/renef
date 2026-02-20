#pragma once

#include <memory>
#include <ftxui/component/component.hpp>
#include "../tui_state.h"

ftxui::Component CreateMemoryTab(std::shared_ptr<TuiState> state);
