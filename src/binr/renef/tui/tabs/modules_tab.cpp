#include "modules_tab.h"
#include "../command_adapter.h"
#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
#include <sstream>

using namespace ftxui;

static std::vector<ModuleEntry> parse_modules_output(const std::string& output) {
    std::vector<ModuleEntry> modules;
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty() || line.find("ERROR") != std::string::npos) continue;

        ModuleEntry entry;
        std::istringstream ls(line);
        std::string token;
        std::vector<std::string> tokens;
        while (ls >> token) tokens.push_back(token);

        if (tokens.size() >= 1) {
            if (tokens[0].find("0x") == 0 && tokens.size() >= 2) {
                entry.base_address = tokens[0];
                entry.name = tokens[1];
                entry.path = tokens.size() >= 3 ? tokens[2] : "";
            } else {
                entry.name = tokens[0];
                entry.base_address = tokens.size() >= 2 ? tokens[1] : "";
                entry.path = tokens.size() >= 3 ? tokens[2] : "";
            }
            modules.push_back(entry);
        }
    }
    return modules;
}

class ModulesTabImpl : public ComponentBase {
public:
    explicit ModulesTabImpl(std::shared_ptr<TuiState> state)
        : state_(std::move(state)) {}

    Element Render() override {
        auto modules = state_->get_modules();

        std::vector<const ModuleEntry*> filtered;
        for (auto& m : modules) {
            if (filter_text_.empty() ||
                m.name.find(filter_text_) != std::string::npos ||
                m.path.find(filter_text_) != std::string::npos) {
                filtered.push_back(&m);
            }
        }

        // Filter line with manual cursor
        Element filter_el;
        if (filter_active_) {
            filter_el = hbox({
                text(filter_text_) | color(Color::White),
                text("\u2588") | blink | color(Color::Cyan), // █ cursor
            });
        } else {
            filter_el = text(filter_text_) | color(Color::GrayLight);
        }

        auto filter_line = hbox({
            text(" /") | color(Color::Cyan),
            filter_el | flex,
            text(" " + std::to_string(filtered.size())) | color(Color::GrayDark),
            text(" "),
        });

        Elements rows;

        if (filtered.empty() && modules.empty()) {
            rows.push_back(text("  no modules loaded") | color(Color::GrayDark));
        } else if (filtered.empty()) {
            rows.push_back(text("  no match") | color(Color::GrayDark));
        }

        for (int i = 0; i < (int)filtered.size(); i++) {
            auto* m = filtered[i];
            auto marker = (i == selected_)
                ? text(" \u25B8 ") | color(Color::Cyan)  // ▸
                : text("   ");

            std::string addr = m->base_address;
            if (addr.size() > 12) addr = addr.substr(0, 12) + "..";

            auto row = hbox({
                marker,
                text(m->name) | color(Color::White) | flex,
                text(" "),
                text(addr) | color(Color::Cyan) | dim,
            });

            if (i == selected_) {
                row = row | bgcolor(Color::Palette256(236));
            }
            rows.push_back(row);
        }

        auto list = vbox(std::move(rows)) | vscroll_indicator | yframe | flex;

        return vbox({
            filter_line,
            list | flex,
        }) | flex;
    }

    bool OnEvent(Event event) override {
        // Filter mode: all input goes to filter text
        if (filter_active_) {
            if (event == Event::Escape) {
                filter_active_ = false;
                filter_text_.clear();
                return true;
            }
            if (event == Event::Return) {
                filter_active_ = false;
                return true;
            }
            if (event == Event::Backspace) {
                if (!filter_text_.empty()) filter_text_.pop_back();
                return true;
            }
            if (event.is_character()) {
                filter_text_ += event.character();
                selected_ = 0;
                return true;
            }
            return false;
        }

        // Navigation mode
        auto modules = state_->get_modules();
        int count = 0;
        for (auto& m : modules) {
            if (filter_text_.empty() ||
                m.name.find(filter_text_) != std::string::npos ||
                m.path.find(filter_text_) != std::string::npos) {
                count++;
            }
        }

        if (event == Event::Character('/')) {
            filter_active_ = true;
            return true;
        }
        if (event == Event::Character('r')) {
            refresh_modules();
            return true;
        }
        if (event == Event::Character('e') && count > 0 && selected_ < count) {
            show_exports(selected_);
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
    void refresh_modules() {
        CommandAdapter::execute_async("exec Module.list()", state_,
            [this](const std::string& result) {
                state_->set_modules(parse_modules_output(result));
                selected_ = 0;
            });
    }

    void show_exports(int index) {
        auto modules = state_->get_modules();
        int count = 0;
        for (auto& m : modules) {
            if (filter_text_.empty() ||
                m.name.find(filter_text_) != std::string::npos ||
                m.path.find(filter_text_) != std::string::npos) {
                if (count == index) {
                    std::string cmd = "exec Module.exports(\"" + m.name + "\")";
                    CommandAdapter::execute_async(cmd, state_,
                        [this](const std::string& result) {
                            state_->append_console_output(result);
                        });
                    return;
                }
                count++;
            }
        }
    }

    std::shared_ptr<TuiState> state_;
    std::string filter_text_;
    bool filter_active_ = false;
    int selected_ = 0;
};

Component CreateModulesTab(std::shared_ptr<TuiState> state) {
    return Make<ModulesTabImpl>(std::move(state));
}
