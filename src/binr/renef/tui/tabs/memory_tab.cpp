#include "memory_tab.h"
#include "../command_adapter.h"
#include "memscan_tui.h"
#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
#include <sstream>
#include <iomanip>

using namespace ftxui;

class MemoryTabImpl : public ComponentBase {
public:
    explicit MemoryTabImpl(std::shared_ptr<TuiState> state)
        : state_(std::move(state)) {}

    Element Render() override {
        auto results = state_->get_scan_results();
        auto hex_dump = state_->get_hex_dump();

        // Scan input line
        Element scan_el;
        if (scan_active_) {
            scan_el = hbox({
                text(scan_pattern_) | color(Color::White),
                text("\u2588") | blink | color(Color::Cyan),
            });
        } else {
            scan_el = text(scan_pattern_.empty() ? "48 89 e5 ..." : scan_pattern_)
                | color(scan_pattern_.empty() ? Color::GrayDark : Color::GrayLight);
        }

        auto scan_line = hbox({
            text(" ms ") | bold | color(Color::Cyan),
            scan_el | flex,
            text(" Enter") | color(Color::GrayDark),
            text(":search ") | color(Color::GrayDark),
        });

        // Results
        Elements result_rows;
        if (results.empty() && !has_scanned_) {
            result_rows.push_back(
                text("  s:scan  j/k:nav  Enter:dump  Esc:console") | color(Color::GrayDark));
        } else if (results.empty()) {
            result_rows.push_back(text("  no matches") | color(Color::GrayDark));
        }

        for (int i = 0; i < (int)results.size(); i++) {
            auto& r = results[i];
            std::stringstream addr_ss;
            addr_ss << "0x" << std::hex << std::setfill('0') << std::setw(12) << r.address;

            auto marker = (i == selected_)
                ? text(" \u25B8 ") | color(Color::Cyan)
                : text("   ");

            auto row = hbox({
                marker,
                text(addr_ss.str()) | color(Color::Cyan) | size(WIDTH, EQUAL, 16),
                text(" "),
                text(r.library.empty() ? "<anon>" : r.library)
                    | color(Color::White) | size(WIDTH, EQUAL, 16),
                text(" "),
                text(r.hex) | color(Color::Yellow) | flex,
            });

            if (i == selected_) {
                row = row | bgcolor(Color::Palette256(236));
            }
            result_rows.push_back(row);
        }

        auto results_box = vbox(std::move(result_rows))
            | vscroll_indicator | yframe | flex;

        // Hex dump section
        Elements hex_rows;
        if (!hex_dump.empty()) {
            std::istringstream stream(hex_dump);
            std::string line;
            while (std::getline(stream, line)) {
                size_t colon = line.find(':');
                if (colon != std::string::npos) {
                    auto addr_part = text(line.substr(0, colon + 1)) | color(Color::Cyan);
                    auto rest = text(line.substr(colon + 1)) | color(Color::GrayLight);
                    hex_rows.push_back(hbox({text(" "), addr_part, rest}));
                } else {
                    hex_rows.push_back(text(" " + line) | color(Color::GrayLight));
                }
            }
        }

        // Compose
        Elements content;
        content.push_back(scan_line);
        content.push_back(separator() | color(Color::GrayDark));
        content.push_back(results_box | flex);

        if (!hex_rows.empty()) {
            content.push_back(separator() | color(Color::GrayDark));
            for (auto& row : hex_rows) {
                content.push_back(std::move(row));
            }
        }

        return vbox(std::move(content)) | flex;
    }

    bool OnEvent(Event event) override {
        // Scan input mode
        if (scan_active_) {
            if (event == Event::Escape) {
                scan_active_ = false;
                return true;
            }
            if (event == Event::Return) {
                scan_active_ = false;
                if (!scan_pattern_.empty()) do_scan();
                return true;
            }
            if (event == Event::Backspace) {
                if (!scan_pattern_.empty()) scan_pattern_.pop_back();
                return true;
            }
            if (event.is_character()) {
                scan_pattern_ += event.character();
                return true;
            }
            return false;
        }

        // Navigation mode
        auto results = state_->get_scan_results();
        int count = (int)results.size();

        if (event == Event::Character('s') || event == Event::Character('/')) {
            scan_active_ = true;
            return true;
        }
        if (event == Event::Return && count > 0 && selected_ < count) {
            do_dump(results[selected_]);
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
        // Escape not handled here → bubbles up to tui_app for focus toggle
        return false;
    }

    bool Focusable() const override { return true; }

private:
    void do_scan() {
        has_scanned_ = true;
        std::string pattern = scan_pattern_;
        CommandAdapter::execute_async("msj " + pattern, state_,
            [this](const std::string& result) {
                auto parsed = parse_memscan_json(result);
                state_->set_scan_results(std::move(parsed));
                selected_ = 0;
            });
    }

    void do_dump(const MemScanResult& result) {
        std::stringstream ss;
        ss << "md 0x" << std::hex << result.address << " 256";
        CommandAdapter::execute_async(ss.str(), state_,
            [this](const std::string& output) {
                state_->set_hex_dump(output);
            });
    }

    std::shared_ptr<TuiState> state_;
    std::string scan_pattern_;
    bool scan_active_ = false;
    bool has_scanned_ = false;
    int selected_ = 0;
};

Component CreateMemoryTab(std::shared_ptr<TuiState> state) {
    return Make<MemoryTabImpl>(std::move(state));
}
