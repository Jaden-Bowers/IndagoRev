#pragma once

#include <ncurses.h>

#include <optional>
#include <string>
#include <vector>

namespace tui {

// Visual styles resolved to curses attributes and color pairs by set_attr().
// Colors fall back to monochrome attributes when the terminal has no color.
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

// Initializes curses (locale, cbreak, noecho, keypad, cursor, escape delay,
// color pairs). Returns false if the terminal cannot be initialized.
bool ui_init();

// Restores the terminal to its pre-curses state.
void ui_end();

// Applies the attributes and colors for one style to the global screen state.
void set_attr(Attr attr);

// Fills a run of `width` cells with `ch` on window `w`, stopping early if the
// cursor write runs off the window.
void draw_fill(WINDOW* w, int y, int x, int width, char ch, Attr attr);

// Writes `text` at (y, x) clipped to `width` columns, skipping the first
// `coloff` bytes so horizontally panned detail views can reuse it.
void draw_clipped(WINDOW* w, int y, int x, const std::string& text, int width,
                  std::size_t coloff = 0);

// Draws the top banner row: `left` at the start, `center` after it, and `right`
// aligned to the right edge.
void draw_banner(const std::string& left, const std::string& center,
                 const std::string& right);

// Draws the page title row with an optional dim right-aligned note.
void draw_title(const std::string& text, const std::string& note);

// Draws the help line on the second-to-last row.
void draw_help(const std::string& text);

// Draws the status line on the last row, using the error style when `error`.
void draw_status(const std::string& text, bool error);

// Draws a scrollable list of `items` starting at `first_row` for `height` rows,
// highlighting `sel` and maintaining `top` so the selection stays visible.
// Shows `empty_note` when the list is empty.
void draw_list(const std::vector<std::string>& items, int& sel, int& top,
               int first_row, int height, const std::string& empty_note);

// Draws `lines` as a scrolling, horizontally pannable text view. `row` and
// `col` are clamped to the content bounds.
void draw_textview(const std::vector<std::string>& lines, int& row, int& col,
                   int first_row, int height, int width);

// Shows a modal single-line input box with `label` and an initial value.
// Returns the edited value on Enter, or nullopt when the user presses Escape.
std::optional<std::string> prompt_line(const std::string& label,
                                       const std::string& initial);

// Shows a modal yes/no dialog. The choice is toggled with y/n or the arrow keys
// and confirmed with Enter; Escape cancels and returns false.
bool confirm_yesno(const std::string& label);

}  // namespace tui
