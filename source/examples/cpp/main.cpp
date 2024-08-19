#include "terminal.hpp"
#include "hello_world.hpp"
#include "commands.hpp"

using namespace std;
using namespace gosling;
using namespace hw;

int main() try {

    ::gosling_library_init(out(LIBRARY), throw_on_error());
    TERM.write_line("Welcome to example_chat_cpp!");
    TERM.write_line("Type help for a list of commands");
    TERM.register_command("init-context", hw::init_context);
    TERM.register_command("start-identity", hw::start_identity);
    TERM.register_command("stop-identity", hw::stop_identity);
    TERM.register_command("request-endpoint", hw::request_endpoint);
    TERM.register_command("start-endpoint", hw::start_endpoint);
    TERM.register_command("stop-endpoint", hw::stop_endpoint);
    TERM.register_command("connect-endpoint", hw::connect_endpoint);
    TERM.register_command("drop-peer", hw::drop_peer);
    TERM.register_command("list-peers", hw::list_peers);
    TERM.register_command("chat", hw::chat);
    TERM.register_command("help", hw::help);
    TERM.register_command("exit", hw::exit);

    while (!EXIT_REQUESTED) {
        if (GOSLING_CONTEXT) {
            ::gosling_context_poll_events(GOSLING_CONTEXT.get(), throw_on_error());
        }
        TERM.update();

        for(auto it = ENDPOINT_CONNECTIONS.begin(); it != ENDPOINT_CONNECTIONS.end();) {
            const auto& peer_id = it->first;
            auto& read_buffer = it->second.read_buffer;
            auto& socket = it->second.socket;

            boost::system::error_code ec;
            std::size_t bytes_read = boost::asio::read_until(socket, boost::asio::dynamic_buffer(read_buffer), '\n', ec);

            if (ec && ec != boost::asio::error::would_block) {
                ostringstream ss;
                ss << "error reading from " << peer_id << ": " << ec;
                TERM.write_line(ss.str());
                it = ENDPOINT_CONNECTIONS.erase(it);
                continue;
            }

            ostringstream ss;
            if (!ec && bytes_read > 0) {
                ss << "chat from " << peer_id << ":";
                TERM.write_line(ss.str());
                ss.str("");
                ss << "< " << read_buffer;
                TERM.write_line(ss.str());
                read_buffer.clear();
            }
            ++it;
        }
    }

    return 0;
} catch (const std::exception& ex) {
    TERM.write_line(ex.what());
}
