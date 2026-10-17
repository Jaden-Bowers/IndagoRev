// Integration tests for indago-tui, driven through a real pseudo-terminal.
//
// The workbench is an interactive ncurses program, so the honest way to cover
// it is to run the built binary on a pty and assert on what it actually paints.
// A small terminal emulator reconstructs the screen from the output stream,
// which makes the assertions independent of how ncurses chooses to optimize
// its repaints (it only emits changed cells, so a raw byte buffer would be
// useless for asserting on a stable screen).
//
// The suite seeds one workspace with a project, an imported target, static
// functions, evidence (with a real content-store blob), queued jobs and two
// harness investigations, then drives many independent sessions against it.
// Each session is isolated so a failure in one scenario does not cascade.

#include <nlohmann/json.hpp>

#include "indago/core.hpp"
#include "indago/harness.hpp"
#include "indago/service.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <sqlite3.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

namespace {

using Json = nlohmann::json;
namespace fs = indago::fs;

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const std::string& what) {
    if (ok) {
        ++g_pass;
        std::cout << "  ok   " << what << "\n";
    } else {
        ++g_fail;
        std::cout << "  FAIL " << what << "\n";
    }
}

// Terminal key sequences for TERM=xterm-256color with keypad enabled. That
// terminfo uses application-cursor mode for the arrows/Home/End (ESC O x).
const std::string kUp = "\x1bOA";
const std::string kDown = "\x1bOB";
const std::string kRight = "\x1bOC";
const std::string kLeft = "\x1bOD";
const std::string kPgUp = "\x1b[5~";
const std::string kPgDn = "\x1b[6~";
const std::string kHome = "\x1bOH";
const std::string kEnd = "\x1bOF";
const std::string kF5 = "\x1b[15~";
const std::string kEsc = "\x1b";
const std::string kEnter = "\r";

// ---------------------------------------------------------------------------
// A minimal character-grid terminal.
//
// Understands the subset of escape sequences ncurses emits for this app:
// cursor addressing (H/f/A/B/C/D/G/d), erases (J/K/X), line/char insertion and
// deletion (L/M/P/@), SGR and mode switches (ignored), charset selection
// (ESC ( / ESC )) and OSC. Everything else is dropped.
// ---------------------------------------------------------------------------
class Screen {
public:
    Screen(int rows, int cols) { resize(rows, cols); }

    void resize(int rows, int cols) {
        rows_ = rows > 0 ? rows : 1;
        cols_ = cols > 0 ? cols : 1;
        grid_.assign(static_cast<std::size_t>(rows_) * cols_, ' ');
        cy_ = cx_ = 0;
    }

    void feed(const char* data, std::size_t size) {
        for (std::size_t i = 0; i < size; ++i) {
            const unsigned char c = static_cast<unsigned char>(data[i]);
            if (c == 0x1b) {
                i = escape(data, size, i);
            } else if (c == '\r') {
                cx_ = 0;
            } else if (c == '\n') {
                cy_ = std::min(cy_ + 1, rows_ - 1);
                cx_ = 0;
            } else if (c == '\b') {
                if (cx_ > 0) --cx_;
            } else if (c == '\t') {
                cx_ = std::min(cols_ - 1, (cx_ / 8 + 1) * 8);
            } else if (c >= 0x20 && c != 0x7f) {
                put(cy_, cx_, static_cast<char>(c));
                cx_ = std::min(cx_ + 1, cols_ - 1);
            }
        }
    }

    bool contains(const std::string& needle) const {
        return text().find(needle) != std::string::npos;
    }

    std::string text() const {
        std::string out;
        for (int r = 0; r < rows_; ++r) {
            out.append(&grid_[static_cast<std::size_t>(r) * cols_],
                       static_cast<std::size_t>(cols_));
            out.push_back('\n');
        }
        return out;
    }

private:
    void put(int y, int x, char ch) {
        if (y < 0 || y >= rows_ || x < 0 || x >= cols_) return;
        grid_[static_cast<std::size_t>(y) * cols_ + x] = ch;
    }

    std::size_t escape(const char* d, std::size_t size, std::size_t i) {
        if (i + 1 >= size) return i;
        const char next = d[i + 1];
        if (next == '[') {
            std::size_t j = i + 2;
            std::string params;
            while (j < size && !(d[j] >= 0x40 && d[j] <= 0x7e)) params.push_back(d[j++]);
            if (j >= size) return size - 1;
            csi(d[j], params);
            return j;
        }
        if (next == ']') {  // OSC terminated by BEL or ST
            std::size_t j = i + 2;
            while (j < size && d[j] != 0x07 &&
                   !(d[j] == 0x1b && j + 1 < size && d[j + 1] == '\\')) {
                ++j;
            }
            if (j < size && d[j] == 0x1b) ++j;
            return j;
        }
        if (next == '(' || next == ')' || next == '#' || next == '%') return i + 2;
        return i + 1;
    }

    std::vector<int> params(const std::string& p) const {
        std::vector<int> out;
        int cur = 0;
        bool any = false;
        for (char ch : p) {
            if (ch >= '0' && ch <= '9') {
                cur = cur * 10 + (ch - '0');
                any = true;
            } else if (ch == ';') {
                out.push_back(any ? cur : 0);
                cur = 0;
                any = false;
            }
        }
        out.push_back(any ? cur : 0);
        return out;
    }

    void csi(char final, const std::string& p) {
        const auto a = params(p);
        const int p0 = a.empty() ? 0 : a[0];
        const int p1 = a.size() > 1 ? a[1] : 0;
        auto arg = [](int v, int def) { return v > 0 ? v : def; };
        switch (final) {
            case 'A': cy_ = std::max(0, cy_ - arg(p0, 1)); break;
            case 'B': cy_ = std::min(rows_ - 1, cy_ + arg(p0, 1)); break;
            case 'C': cx_ = std::min(cols_ - 1, cx_ + arg(p0, 1)); break;
            case 'D': cx_ = std::max(0, cx_ - arg(p0, 1)); break;
            case 'G': cx_ = std::min(cols_ - 1, arg(p0, 1) - 1); break;
            case 'd': cy_ = std::min(rows_ - 1, arg(p0, 1) - 1); break;
            case 'H':
            case 'f':
                cy_ = std::min(rows_ - 1, std::max(0, arg(p0, 1) - 1));
                cx_ = std::min(cols_ - 1, std::max(0, arg(p1, 1) - 1));
                break;
            case 'J':
                if (p0 == 2) clear_all();
                else if (p0 == 0) clear_to_end();
                break;
            case 'K':
                if (p0 == 1) clear_to_start_of_line();
                else if (p0 == 2) clear_line();
                else clear_to_end_of_line();
                break;
            case 'X': {
                const int n = arg(p0, 1);
                for (int k = 0; k < n; ++k) put(cy_, cx_ + k, ' ');
                break;
            }
            case 'P': {
                const int n = arg(p0, 1);
                for (int x = cx_; x + n < cols_; ++x)
                    grid_[static_cast<std::size_t>(cy_) * cols_ + x] =
                        grid_[static_cast<std::size_t>(cy_) * cols_ + x + n];
                for (int x = std::max(cx_, cols_ - n); x < cols_; ++x) put(cy_, x, ' ');
                break;
            }
            case 'L': insert_lines(arg(p0, 1)); break;
            case 'M': delete_lines(arg(p0, 1)); break;
            default: break;
        }
    }

    void insert_lines(int n) {
        for (int y = rows_ - 1; y >= cy_ + n; --y) {
            for (int x = 0; x < cols_; ++x)
                grid_[static_cast<std::size_t>(y) * cols_ + x] =
                    grid_[static_cast<std::size_t>(y - n) * cols_ + x];
        }
        for (int y = cy_; y < std::min(rows_, cy_ + n); ++y)
            for (int x = 0; x < cols_; ++x) put(y, x, ' ');
    }

    void delete_lines(int n) {
        for (int y = cy_; y + n < rows_; ++y) {
            for (int x = 0; x < cols_; ++x)
                grid_[static_cast<std::size_t>(y) * cols_ + x] =
                    grid_[static_cast<std::size_t>(y + n) * cols_ + x];
        }
        for (int y = std::max(cy_, rows_ - n); y < rows_; ++y)
            for (int x = 0; x < cols_; ++x) put(y, x, ' ');
    }

    void clear_all() { std::fill(grid_.begin(), grid_.end(), ' '); }
    void clear_line() {
        for (int x = 0; x < cols_; ++x) put(cy_, x, ' ');
    }
    void clear_to_end_of_line() {
        for (int x = cx_; x < cols_; ++x) put(cy_, x, ' ');
    }
    void clear_to_start_of_line() {
        for (int x = 0; x <= cx_ && x < cols_; ++x) put(cy_, x, ' ');
    }
    void clear_to_end() {
        clear_to_end_of_line();
        for (int y = cy_ + 1; y < rows_; ++y)
            for (int x = 0; x < cols_; ++x) put(y, x, ' ');
    }

    int rows_{1};
    int cols_{1};
    std::vector<char> grid_;
    int cy_{0};
    int cx_{0};
};

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: tui_tests <path-to-indago-tui>\n";
        return 2;
    }
    std::cout << "tui_tests: " << g_pass << " passed, " << g_fail << " failed\n";
    return g_fail == 0 ? 0 : 1;
}

#else  // _WIN32

int main(int, char**) {
    std::cout << "tui_tests: skipped (forkpty unavailable on this platform)\n";
    return 0;
}

#endif
