using namespace std;

namespace example {

    class terminal {
    public:
        terminal();
        ~terminal();

        void register_command(string command, function<void(const vector<string>&)> lambda);

        void write_line();
        void write_line(string line);
        void update();
    private:
        void render();
        void handle_command(string input);

        deque<string> line_buffer_;
        vector<char> input_buffer_;
        map<string, function<void(const vector<string>&)>> commands_;

        const volatile int& rows_ = LINES;
        const volatile int& cols_ = COLS;
    };
    inline terminal TERM{};
}