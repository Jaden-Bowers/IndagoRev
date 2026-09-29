#pragma once

#include <ncurses.h>

#include <optional>
#include <string>
#include <vector>

namespace tui {

enum class Attr {
    Normal,
    Title,
    Header,
    Select,
    Dim,
    Error,
    Ok,
    Accent,
};

bool ui_init();
void ui_end();
void set_attr(Attr attr);
void draw_fill(WINDOW* w, int y, int x, int width, char ch, Attr attr);
void draw_clipped(WINDOW* w, int y, int x, const std::string& text, int width,
                  std::size_t coloff = 0);
void draw_banner(const std::string& left, const std::string& center,
                 const std::string& right);
void draw_title(const std::string& text, const std::string& note);
void draw_help(const std::string& text);
void draw_status(const std::string& text, bool error);

void draw_list(const std::vector<std::string>& items, int& sel, int& top,
               int first_row, int height, const std::string& empty_note);
void draw_textview(const std::vector<std::string>& lines, int& row, int& col,
                   int first_row, int height, int width);

std::optional<std::string> prompt_line(const std::string& label,
                                       const std::string& initial);
bool confirm_yesno(const std::string& label);

}  // namespace tui