#include "hooks_tab.h"
#include "../command_adapter.h"
#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
#include <sstream>

using namespace ftxui;

static std::vector<HookEntry> parse_hooks_output(const std::string& output) {
    std::vector<HookEntry> hooks;
    std::istringstream stream(output);
    std::string line;
    int id = 0;
    while (std::getline(stream, line)) {
        if (line.empty() || line.find("No hooks") != std::string::npos) continue;
        if (line.find("ERROR") != std::string::npos) continue;

        HookEntry entry;
        entry.id = ++id;

        size_t bracket_start = line.find('[');
        size_t bracket_end = line.find(']');
        if (bracket_start != std::string::npos && bracket_end != std::string::npos) {
            entry.type = line.substr(bracket_start + 1, bracket_end - bracket_start - 1);
        }

        size_t addr_pos = line.find("0x");
        if (addr_pos != std::string::npos) {
            size_t addr_end = line.find_first_of(" \t", addr_pos);
            entry.address = line.substr(addr_pos, addr_end - addr_pos);
        }

        entry.function_name = line;
        hooks.push_back(entry);
    }
    return hooks;
}

class HooksTabImpl : public ComponentBase {
public:
    explicit HooksTabImpl(std::shared_ptr<TuiState> state)
        : state_(std::move(state)) {}

    Element Render() override {
        auto hooks = state_->get_hooks();

        Elements rows;

        if (hooks.empty()) {
            rows.push_back(text("  no active hooks") | color(Color::GrayDark));
        }

        for (int i = 0; i < (int)hooks.size(); i++) {
            auto& h = hooks[i];

            std::string type_short;
            if (h.type.find("trampoline") != std::string::npos || h.type.find("TRAMP") != std::string::npos)
                type_short = "TRM";
            else if (h.type.find("plt") != std::string::npos || h.type.find("PLT") != std::string::npos)
                type_short = "PLT";
            else if (h.type.find("java") != std::string::npos || h.type.find("JAVA") != std::string::npos)
                type_short = "JVM";
            else
                type_short = h.type.substr(0, 3);

            auto marker = (i == selected_)
                ? text(" \u25B8 ") | color(Color::Cyan)   // ▸
                : text("   ");

            auto dot = text("\u25CF ") | color(Color::Green); // ●

            // Truncate address for compact display
            std::string addr = h.address;
            if (addr.size() > 12) addr = addr.substr(0, 12) + "..";

            auto row = hbox({
                marker,
                dot,
                text(h.function_name) | color(Color::White) | flex,
                text(" "),
                text(type_short) | color(Color::Yellow),
            });

            if (i == selected_) {
                row = row | bgcolor(Color::Palette256(236));
            }
            rows.push_back(row);
        }

        return vbox(std::move(rows)) | vscroll_indicator | yframe | flex;
    }

    bool OnEvent(Event event) override {
        auto hooks = state_->get_hooks();
        int count = (int)hooks.size();

        if (event == Event::Character('r')) {
            refresh_hooks();
            return true;
        }
        if (event == Event::Character('u') && count > 0 && selected_ < count) {
            unhook_selected(hooks[selected_]);
            return true;
        }
        if (event == Event::ArrowUp || event == Event::Character('k')) {
            if (selected_ > 0) selected_--;
            return true;
        }
        if (event == Event::ArrowDown || event == Event::Character('j')) {
            if (selected_ < count - 1) selected_++;
            return true;
        }
        return false;
    }

    bool Focusable() const override { return true; }

private:
    void refresh_hooks() {
        CommandAdapter::execute_async("hooks", state_,
            [this](const std::string& result) {
                state_->set_hooks(parse_hooks_output(result));
            });
    }

    void unhook_selected(const HookEntry& hook) {
        std::string cmd = "unhook " + std::to_string(hook.id);
        CommandAdapter::execute_async(cmd, state_,
            [this](const std::string&) { refresh_hooks(); });
    }

    std::shared_ptr<TuiState> state_;
    int selected_ = 0;
};

Component CreateHooksTab(std::shared_ptr<TuiState> state) {
    return Make<HooksTabImpl>(std::move(state));
}
