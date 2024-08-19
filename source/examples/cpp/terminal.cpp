using namespace std;

#include "terminal.hpp"

namespace example {
    terminal::terminal() {
        // Initialize ncurses
        ::initscr();
        ::cbreak();  // Disable line buffering
        ::noecho();  // Don't echo input
        ::mousemask(0, NULL); // Disable mouse events
        ::keypad(stdscr, TRUE); // Enable special key handling
        ::timeout(16); // timeout getch() after 16 milliseconds

        this->render();
    }

    terminal::~terminal() {
        ::endwin();
    }

    void terminal::register_command(string command, function<void(const vector<string>&)> lambda) {
        this->commands_.insert({command, lambda});
    }

    void terminal::write_line() {
        this->line_buffer_.emplace_back(string());
        this->render();
    }

    void terminal::write_line(string line) {
        const int COLS = this->cols_;

        // spit lines on newline
        istringstream lineStream(line);

        // split lines on newline
        while (getline(lineStream, line, '\n')) {
            // and line-wrap
            while (line.size() > COLS) {
                this->line_buffer_.emplace_back(line.substr(0, COLS));
                line = line.substr(COLS);
            }
            if (!line.empty())
                this->line_buffer_.emplace_back(std::move(line));
        }
        this->render();
    }

    void terminal::update() {
        string command;
        bool dirty = false;
        for (int inputChar = getch(); inputChar != ERR; inputChar = getch()) {

            switch(inputChar) {
            case '\n':
            case KEY_ENTER:
                command = string(this->input_buffer_.data(), this->input_buffer_.size());
                this->input_buffer_.clear();
                this->render();
                this->handle_command(command);
                break;
            case KEY_BACKSPACE:
                if (!this->input_buffer_.empty()) {
                    this->input_buffer_.pop_back();
                    dirty = true;
                }
                break;
            default:
                // is printable ascii
                if (inputChar >= 32 && inputChar <= 126) {
                    this->input_buffer_.push_back(inputChar);
                    dirty = true;
                }
                break;
            }
        }

        if (dirty) {
            this->render();
        }
    }

    // private methods

    void terminal::render() {
        const int SCROLLBACK = this->rows_ - 2;
        const int ROWS = this->rows_;
        const int COLS = this->cols_;

        while (this->line_buffer_.size() > SCROLLBACK) {
            this->line_buffer_.pop_front();
        }

        ::move(0, 0);
        // lines
        for (const auto& line : this->line_buffer_) {
            const int len = std::min(COLS, static_cast<int>(line.size()));
            ::printw("%.*s", len, line.data());
            if (len < COLS) {
                ::clrtoeol();
                ::move(getcury(stdscr) + 1, 0);
            }
        }
        // empty
        for (int i = static_cast<int>(this->line_buffer_.size()); i < SCROLLBACK; i++) {
            ::clrtoeol();
            ::move(getcury(stdscr) + 1, 0);
        }

        // border
        for (int i = 0; i < COLS; i++) {
            ::addch('=');
        }

        // input line
        const int len = std::max(0, std::min(static_cast<int>(this->input_buffer_.size()), COLS - 2));
        ::move(ROWS - 1, 0);
        ::clrtoeol();
        ::printw("> %.*s", len, this->input_buffer_.data());

        // draw
        ::refresh();
    }

    void terminal::handle_command(string input) {
        if (input.empty()) {
            return;
        }

        vector<string> args;
        istringstream iss(input);
        string token;

        while (iss >> quoted(token)) {
            args.push_back(token);
        }

        string command = *args.begin();
        args.erase(args.begin());

        this->write_line(string("> ") + input);
        if (const auto it = this->commands_.find(command); it != this->commands_.end()) {
            try {
                it->second(args);
            }    catch (const std::runtime_error& err) {
                this->write_line(string("error: ") + err.what());
            }
        } else {
            this->write_line(string("Invalid command: ") + command);
        }
    }
}
