#pragma once

#include <memory>
#include <ftxui/dom/elements.hpp>
#include "tui_state.h"

ftxui::Element render_status_bar(std::shared_ptr<TuiState> state, int selected_tab);
