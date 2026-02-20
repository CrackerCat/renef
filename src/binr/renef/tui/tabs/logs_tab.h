#pragma once

#include <memory>
#include <ftxui/component/component.hpp>
#include "../tui_state.h"

ftxui::Component CreateLogsTab(std::shared_ptr<TuiState> state);
