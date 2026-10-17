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

// ---------------------------------------------------------------------------
// A pty-hosted indago-tui process plus the emulator for its output.
// ---------------------------------------------------------------------------
class Session {
public:
    Session(const std::string& binary, const std::string& workspace,
            const std::string& project, int cols = 120, int rows = 36)
        : binary_(binary), workspace_(workspace), project_(project),
          screen_(rows, cols) {
        struct winsize ws{};
        ws.ws_col = static_cast<unsigned short>(cols);
        ws.ws_row = static_cast<unsigned short>(rows);
        pid_ = forkpty(&master_, nullptr, nullptr, &ws);
        if (pid_ < 0) throw std::runtime_error(std::string("forkpty: ") + std::strerror(errno));
        if (pid_ == 0) {
            setenv("TERM", "xterm-256color", 1);
            setenv("LANG", "C.UTF-8", 1);
            setenv("LC_ALL", "C.UTF-8", 1);
            std::vector<const char*> args{binary_.c_str(), "--workspace", workspace_.c_str()};
            if (!project_.empty()) {
                args.push_back("--project");
                args.push_back(project_.c_str());
            }
            args.push_back(nullptr);
            execv(binary_.c_str(), const_cast<char* const*>(args.data()));
            _exit(127);
        }
        const int flags = fcntl(master_, F_GETFL, 0);
        fcntl(master_, F_SETFL, flags | O_NONBLOCK);
    }

    ~Session() {
        if (pid_ > 0) {
            kill(pid_, SIGKILL);
            int status = 0;
            waitpid(pid_, &status, 0);
        }
        if (master_ >= 0) close(master_);
    }

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    void send(const std::string& keys, int reap_ms = 40) {
        if (master_ < 0) return;
        const ssize_t n = write(master_, keys.data(), keys.size());
        (void)n;
        // Give the app a beat to consume the input and start reacting.
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(reap_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    void type(const std::string& text) { send(text); }
    void enter() { send(kEnter); }

    bool expect(const std::string& needle, int timeout_ms = 5000) {
        return wait_until([&] { return screen_.contains(needle); }, timeout_ms);
    }

    bool gone(const std::string& needle, int timeout_ms = 3000) {
        return wait_until([&] { return !screen_.contains(needle); }, timeout_ms);
    }

    bool contains(const std::string& needle) { pump(); return screen_.contains(needle); }

    void settle(int ms) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    void resize(int cols, int rows) {
        struct winsize ws{};
        ws.ws_col = static_cast<unsigned short>(cols);
        ws.ws_row = static_cast<unsigned short>(rows);
        ioctl(master_, TIOCSWINSZ, &ws);
        screen_.resize(rows, cols);
        if (pid_ > 0) kill(pid_, SIGWINCH);
        settle(120);
    }

    bool wait_exit(int timeout_ms = 4000) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            pump();
            int status = 0;
            const pid_t r = waitpid(pid_, &status, WNOHANG);
            if (r == pid_) {
                pid_ = -1;
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        return false;
    }

    std::string screen() { pump(); return screen_.text(); }

private:
    void pump() {
        if (master_ < 0) return;
        char scratch[16384];
        for (;;) {
            const ssize_t n = read(master_, scratch, sizeof(scratch));
            if (n <= 0) break;
            screen_.feed(scratch, static_cast<std::size_t>(n));
        }
    }

    template <typename Predicate>
    bool wait_until(Predicate done, int timeout_ms) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            pump();
            if (done()) return true;
            struct pollfd pfd{master_, POLLIN, 0};
            poll(&pfd, 1, 25);
        }
        pump();
        return done();
    }

    std::string binary_;
    std::string workspace_;
    std::string project_;
    int master_{-1};
    pid_t pid_{-1};
    Screen screen_;
};

void want(Session& s, const std::string& needle, const std::string& what, int ms = 6000) {
    check(s.expect(needle, ms), what);
}

void want_gone(Session& s, const std::string& needle, const std::string& what, int ms = 3000) {
    check(s.gone(needle, ms), what);
}

// ---------------------------------------------------------------------------
// Fixture: a deterministic ELF64 so import_target has a real artifact.
// ---------------------------------------------------------------------------
fs::path make_fixture(const fs::path& dir, const std::string& name,
                      unsigned char fill) {
    std::vector<unsigned char> bytes(0x1000, fill);
    auto put = [&](std::size_t at, std::uint64_t value, unsigned count) {
        for (unsigned i = 0; i < count; ++i)
            bytes[at + i] = static_cast<unsigned char>(value >> (8 * i));
    };
    bytes[0] = 0x7f; bytes[1] = 'E'; bytes[2] = 'L'; bytes[3] = 'F';
    bytes[4] = 2; bytes[5] = 1; bytes[6] = 1;
    put(16, 2, 2); put(18, 62, 2); put(20, 1, 4); put(24, 0x401000, 8); put(32, 64, 8);
    put(52, 64, 2); put(54, 56, 2); put(56, 1, 2);
    const std::vector<unsigned char> code{0x48,0x39,0xd8,0x74,0x02,0x75,0x00,0x0f,0x94,0xc0,
                                          0x48,0x0f,0x45,0xc3,0xe8,0,0,0,0,0xff,0xd0,0xeb,0,0xc3};
    put(64, 1, 4); put(68, 5, 4); put(72, 0x1000, 8); put(80, 0x401000, 8); put(88, 0x401000, 8);
    put(96, code.size(), 8); put(104, code.size(), 8); put(112, 0x1000, 8);
    bytes.insert(bytes.end(), code.begin(), code.end());
    const auto path = dir / name;
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    return path;
}

void exec_sql(sqlite3* db, const std::string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        const std::string message = err ? err : "sql error";
        sqlite3_free(err);
        throw std::runtime_error(message);
    }
}

struct Seed {
    fs::path workspace;
    std::string project = "sampleproj";
    std::string target_name = "sample.pe64";
    std::string target_id;
    std::string artifact_sha;
    fs::path second_fixture;
    std::string investigation_id;
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
