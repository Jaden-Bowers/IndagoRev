#include "ui.hpp"

#include <algorithm>
#include <clocale>
#include <cstring>

namespace tui {

namespace {
int pair_header{1};
int pair_accent{2};
int pair_ok{3};
int pair_error{4};
int pair_warn{5};
}  // namespace

bool ui_init() {
    std::setlocale(LC_ALL, "");
    if (initscr() == nullptr) return false;
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    set_escdelay(50);
    if (has_colors()) {
        start_color();
        if (use_default_colors() == OK) {
            init_pair(pair_header, COLOR_WHITE, COLOR_BLUE);
            init_pair(pair_accent, COLOR_CYAN, -1);
            init_pair(pair_ok, COLOR_GREEN, -1);
            init_pair(pair_error, COLOR_RED, -1);
            init_pair(pair_warn, COLOR_YELLOW, -1);
        } else {
            init_pair(pair_header, COLOR_WHITE, COLOR_BLUE);
            init_pair(pair_accent, COLOR_CYAN, COLOR_BLACK);
            init_pair(pair_ok, COLOR_GREEN, COLOR_BLACK);
            init_pair(pair_error, COLOR_RED, COLOR_BLACK);
            init_pair(pair_warn, COLOR_YELLOW, COLOR_BLACK);
        }
    }
    return true;
}

void ui_end() { endwin(); }

void set_attr(Attr attr) {
    attroff(A_BOLD | A_REVERSE | A_DIM | A_BLINK | A_UNDERLINE);
    switch (attr) {
        case Attr::Normal:
            attrset(A_NORMAL);
            break;
        case Attr::Title:
            if (has_colors()) attrset(COLOR_PAIR(pair_accent));
            attron(A_BOLD);
            break;
        case Attr::Header:
            if (has_colors()) attrset(COLOR_PAIR(pair_header));
            attron(A_BOLD);
            break;
        case Attr::Select:
            attrset(A_REVERSE | A_BOLD);
            break;
        case Attr::Dim:
            attrset(A_DIM);
            break;
        case Attr::Error:
            if (has_colors()) attrset(COLOR_PAIR(pair_error));
            attron(A_BOLD);
            break;
        case Attr::Ok:
            if (has_colors()) attrset(COLOR_PAIR(pair_ok));
            break;
        case Attr::Accent:
            if (has_colors()) attrset(COLOR_PAIR(pair_warn));
            attron(A_BOLD);
            break;
    }
}

void draw_fill(WINDOW* w, int y, int x, int width, char ch, Attr attr) {
    set_attr(attr);
    for (int i = 0; i < width; ++i) {
        if (w == stdscr) {
            if (mvaddch(y, x + i, ch) != OK) return;
        } else {
            if (mvwaddch(w, y, x + i, ch) != OK) return;
        }
    }
}

void draw_clipped(WINDOW* w, int y, int x, const std::string& text, int width,
                  std::size_t coloff) {
    if (width <= 0 || x + width < 0) return;
    const std::size_t begin = std::min<std::size_t>(coloff, text.size());
    const std::size_t count = std::min<std::size_t>(
        static_cast<std::size_t>(width), text.size() - begin);
    if (w == stdscr) {
        if (count) mvaddnstr(y, x, text.data() + begin, static_cast<int>(count));
    } else {
        if (count) mvwaddnstr(w, y, x, text.data() + begin, static_cast<int>(count));
    }
}

void draw_banner(const std::string& left, const std::string& center,
                 const std::string& right) {
    int lines = 0, cols = 0;
    getmaxyx(stdscr, lines, cols);
    (void)lines;
    draw_fill(stdscr, 0, 0, cols, ' ', Attr::Header);
    draw_clipped(stdscr, 0, 1, left, cols - 2);
    if (!center.empty()) {
        const auto rest = static_cast<int>(left.size()) + 2;
        draw_clipped(stdscr, 0, rest, center, cols - rest - 2);
    }
    if (!right.empty()) draw_clipped(stdscr, 0, cols - static_cast<int>(right.size()) - 1, right, cols - 1);
}

void draw_title(const std::string& text, const std::string& note) {
    int lines = 0, cols = 0;
    getmaxyx(stdscr, lines, cols);
    (void)lines;
    set_attr(Attr::Normal);
    mvhline(1, 0, ' ', cols);
    set_attr(Attr::Title);
    const int title_w = std::max(1, cols / 2);
    draw_clipped(stdscr, 1, 0, text, title_w);
    if (!note.empty()) {
        set_attr(Attr::Dim);
        int x = cols - static_cast<int>(note.size()) - 1;
        if (x < title_w) x = title_w;
        if (x > cols - 1) x = cols - 1;
        if (x > 0) draw_clipped(stdscr, 1, x, note, cols - x - 1);
    }
    set_attr(Attr::Normal);
}

void draw_help(const std::string& text) {
    int lines = 0, cols = 0;
    getmaxyx(stdscr, lines, cols);
    set_attr(Attr::Dim);
    draw_fill(stdscr, lines - 1, 0, cols, ' ', Attr::Dim);
    draw_clipped(stdscr, lines - 1, 1, text, cols - 2);
}

void draw_status(const std::string& text, bool error) {
    int lines = 0, cols = 0;
    getmaxyx(stdscr, lines, cols);
    set_attr(error ? Attr::Error : Attr::Normal);
    draw_fill(stdscr, lines - 2, 0, cols, ' ', error ? Attr::Error : Attr::Normal);
    draw_clipped(stdscr, lines - 2, 1, text, cols - 2);
}

void draw_list(const std::vector<std::string>& items, int& sel, int& top,
               int first_row, int height, const std::string& empty_note) {
    int lines = 0, cols = 0;
    getmaxyx(stdscr, lines, cols);
    (void)lines;
    const int total = static_cast<int>(items.size());
    if (top < 0) top = 0;
    if (top > total - 1) top = total > 0 ? total - 1 : 0;
    if (sel < 0) sel = 0;
    if (sel > total - 1) sel = total > 0 ? total - 1 : 0;
    if (sel < top) top = sel;
    if (sel >= top + height) top = sel - height + 1;
    set_attr(Attr::Normal);
    int y = first_row;
    for (int i = top; i < total && y < first_row + height; ++i, ++y) {
        draw_fill(stdscr, y, 0, cols, ' ', i == sel ? Attr::Select : Attr::Normal);
        draw_clipped(stdscr, y, 1, items[static_cast<std::size_t>(i)], cols - 2);
    }
    for (; y < first_row + height; ++y) draw_fill(stdscr, y, 0, cols, ' ', Attr::Normal);
    if (total == 0) {
        set_attr(Attr::Dim);
        draw_clipped(stdscr, first_row + 1, 1, empty_note, cols - 2);
    }
    set_attr(Attr::Normal);
}

void draw_textview(const std::vector<std::string>& lines, int& row, int& col,
                   int first_row, int height, int width) {
    int sc_lines = 0, cols = 0;
    getmaxyx(stdscr, sc_lines, cols);
    if (width <= 0) width = cols;
    if (row < 0) row = 0;
    if (col < 0) col = 0;
    const std::size_t total = lines.size();
    if (row > static_cast<int>(total) - 1) row = total > 0 ? static_cast<int>(total) - 1 : 0;
    set_attr(Attr::Normal);
    int y = first_row;
    for (int i = 0; i < height && y < first_row + height; ++i, ++y) {
        draw_fill(stdscr, y, 0, cols, ' ', Attr::Normal);
        const std::size_t index = static_cast<std::size_t>(row + i);
        if (index < total) draw_clipped(stdscr, y, 0, lines[index], cols, static_cast<std::size_t>(col));
    }
    set_attr(Attr::Normal);
    (void)sc_lines;
}

std::optional<std::string> prompt_line(const std::string& label,
                                       const std::string& initial) {
    int lines = 0, cols = 0;
    getmaxyx(stdscr, lines, cols);
    const int box_w = std::min<int>(cols - 4, 96);
    const int box_h = 5;
    const int box_x = (cols - box_w) / 2;
    const int box_y = lines / 2 - box_h / 2;
    constexpr std::size_t kMaxInput = 1024;
    std::string value = initial;
    while (true) {
        const int w = std::max(1, box_w - 4);
        set_attr(Attr::Title);
        for (int r = 0; r < box_h; ++r) {
            draw_fill(stdscr, box_y + r, box_x, box_w, ' ', Attr::Normal);
            if (r == 0) {
                mvaddch(box_y, box_x, ACS_ULCORNER);
                mvaddch(box_y, box_x + box_w - 1, ACS_URCORNER);
            } else if (r == box_h - 1) {
                mvaddch(box_y + r, box_x, ACS_LLCORNER);
                mvaddch(box_y + r, box_x + box_w - 1, ACS_LRCORNER);
            } else {
                mvaddch(box_y + r, box_x, ACS_VLINE);
                mvaddch(box_y + r, box_x + box_w - 1, ACS_VLINE);
            }
        }
        mvhline(box_y, box_x + 1, ACS_HLINE, box_w - 2);
        mvhline(box_y + box_h - 1, box_x + 1, ACS_HLINE, box_w - 2);
        set_attr(Attr::Normal);
        draw_clipped(stdscr, box_y + 1, box_x + 2, label, box_w - 4);
        set_attr(Attr::Select);
        const int n = static_cast<int>(value.size());
        if (n <= w) {
            draw_clipped(stdscr, box_y + 2, box_x + 2, value, w);
        } else {
            mvaddch(box_y + 2, box_x + 2, '<');
            draw_clipped(stdscr, box_y + 2, box_x + 3,
                        value.substr(static_cast<std::size_t>(n - (w - 1))),
                        w - 1);
        }
        set_attr(Attr::Dim);
        draw_clipped(stdscr, box_y + 3, box_x + 2, "[Enter] ok  [Esc] cancel", box_w - 4);
        set_attr(Attr::Normal);
        const int cursor_x = box_x + 2 + std::min(n, w);
        if (cursor_x >= box_x + box_w - 2) move(box_y + 2, box_x + box_w - 2);
        else move(box_y + 2, cursor_x);
        curs_set(1);
        refresh();
        const int ch = getch();
        curs_set(0);
        if (ch == KEY_ENTER || ch == '\n' || ch == '\r') return value;
        if (ch == 27) return std::nullopt;
        if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (!value.empty()) value.pop_back();
        } else if (ch >= 32 && ch <= 126 && value.size() < kMaxInput) {
            value.push_back(static_cast<char>(ch));
        }
    }
}

bool confirm_yesno(const std::string& label) {
    int lines = 0, cols = 0;
    getmaxyx(stdscr, lines, cols);
    const int box_w = std::min<int>(cols - 4, 72);
    const int box_h = 5;
    const int box_x = (cols - box_w) / 2;
    const int box_y = lines / 2 - box_h / 2;
    bool yes = false;
    while (true) {
        set_attr(Attr::Normal);
        for (int r = 0; r < box_h; ++r) {
            draw_fill(stdscr, box_y + r, box_x, box_w, ' ', Attr::Normal);
            if (r == 0) {
                mvaddch(box_y, box_x, ACS_ULCORNER);
                mvaddch(box_y, box_x + box_w - 1, ACS_URCORNER);
            } else if (r == box_h - 1) {
                mvaddch(box_y + r, box_x, ACS_LLCORNER);
                mvaddch(box_y + r, box_x + box_w - 1, ACS_LRCORNER);
            } else {
                mvaddch(box_y + r, box_x, ACS_VLINE);
                mvaddch(box_y + r, box_x + box_w - 1, ACS_VLINE);
            }
        }
        mvhline(box_y, box_x + 1, ACS_HLINE, box_w - 2);
        mvhline(box_y + box_h - 1, box_x + 1, ACS_HLINE, box_w - 2);
        draw_clipped(stdscr, box_y + 1, box_x + 2, label, box_w - 4);
        const std::string yes_text = yes ? "[Y]" : "[y]";
        const std::string no_text = yes ? "[n]" : "[N]";
        set_attr(yes ? Attr::Accent : Attr::Normal);
        draw_clipped(stdscr, box_y + 2, box_x + 2, yes_text, 6);
        set_attr(yes ? Attr::Normal : Attr::Accent);
        draw_clipped(stdscr, box_y + 2, box_x + 9, no_text, 6);
        set_attr(Attr::Dim);
        draw_clipped(stdscr, box_y + 3, box_x + 2, "[Enter] confirm  [Esc] back", box_w - 4);
        set_attr(Attr::Normal);
        refresh();
        const int ch = getch();
        if (ch == KEY_LEFT || ch == KEY_RIGHT || ch == 9) yes = !yes;
        else if (ch == 'y' || ch == 'Y') yes = true;
        else if (ch == 'n' || ch == 'N') yes = false;
        else if (ch == KEY_ENTER || ch == '\n' || ch == '\r') return yes;
        else if (ch == 27) return false;
    }
}

}  // namespace tui