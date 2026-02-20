#include "tui_status_bar.h"
#include <ftxui/dom/elements.hpp>

using namespace ftxui;

static Color status_accent(const std::string& name) {
    if (name == "green")   return Color::Green;
    if (name == "yellow")  return Color::Yellow;
    if (name == "red")     return Color::Red;
    if (name == "blue")    return Color::Blue;
    if (name == "magenta") return Color::Magenta;
    if (name == "white")   return Color::White;
    return Color::Cyan;
}

Element render_status_bar(std::shared_ptr<TuiState> state, int /*focused_panel*/) {
    auto info = state->get_connection_info();
    auto hooks = state->get_hooks();
    auto modules = state->get_modules();
    auto accent = status_accent(state->get_accent());

    auto sep = text(" \u2502 ") | color(Color::GrayDark); // │

    Elements items;

    // Badge
    items.push_back(text(" RENEF ") | bold | color(Color::Black) | bgcolor(accent));
    items.push_back(text(" "));

    // Connection
    if (info.connected) {
        items.push_back(text("\u25CF ") | color(Color::Green)); // ●
        items.push_back(text("connected") | color(Color::Green));
    } else {
        items.push_back(text("\u25CF ") | color(Color::Red));
        items.push_back(text("disconnected") | color(Color::Red));
    }

    // Target
    if (info.target_pid > 0) {
        items.push_back(sep);
        if (!info.target_process.empty()) {
            items.push_back(text(info.target_process) | bold | color(Color::White));
        }
        items.push_back(text(" [" + std::to_string(info.target_pid) + "]") | color(Color::Yellow));
    }

    // Mode
    if (!info.mode.empty()) {
        items.push_back(sep);
        items.push_back(text(info.mode) | color(Color::GrayLight));
    }

    // Hook count
    if (!hooks.empty()) {
        items.push_back(sep);
        items.push_back(text(std::to_string(hooks.size())) | bold | color(accent));
        items.push_back(text(" hooks") | color(Color::GrayLight));
    }

    // Module count
    if (!modules.empty()) {
        items.push_back(sep);
        items.push_back(text(std::to_string(modules.size())) | color(Color::GrayLight));
        items.push_back(text(" modules") | color(Color::GrayLight));
    }

    // Busy
    if (state->is_busy()) {
        items.push_back(sep);
        items.push_back(text("\u25CF") | blink | color(Color::Yellow));
        items.push_back(text(" working...") | color(Color::Yellow));
    }

    items.push_back(filler());

    return hbox(std::move(items)) | bgcolor(Color::Palette256(235));
}
