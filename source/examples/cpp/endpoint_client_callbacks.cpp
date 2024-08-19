using namespace std;
using namespace gosling;

#include "terminal.hpp"
#include "hello_world.hpp"

namespace hw {
    void register_endpoint_client_callbacks(gosling_context* context) {
        // callback for when the endpoint client handshake completes successfully
        ::gosling_context_set_endpoint_client_handshake_completed_callback(context,
            [](gosling_context* context,
               gosling_handshake_handle_t handle,
               const gosling_v3_onion_service_id* endpoint_service_id,
               const char* channel_name,
               size_t channel_name_length,
               tcp_stream_t stream) -> void {
                try {
                    // find our handshake data
                    auto it = ENDPOINT_CLIENT_HANDSHAKES.find(handle);
                    assert(it != ENDPOINT_CLIENT_HANDSHAKES.end());

                    const string peer_service_id = to_string(it->second.identity_server_service_id.get());
                    // handshake over erase
                    ENDPOINT_CLIENT_HANDSHAKES.erase(it);

                    auto conn = ENDPOINT_CONNECTIONS.insert({peer_service_id, peer_connection{}});
                    assert(conn.second);
                    conn.first->second.socket.assign(boost::asio::ip::tcp::v4(), stream);
                    conn.first->second.socket.non_blocking(true);

                    TERM.write_line("  endpoint client handshake succeeded!");
                    TERM.write_line(string("  may now chat to connected endpoint server: ") + peer_service_id);
                } catch (const std::exception& ex) {
                    TERM.write_line("endpoint_client_handshake_completed callback threw exception");
                    TERM.write_line(ex.what());
                }
            }, throw_on_error());

        // callback for when the endpoint client handshake fails
        ::gosling_context_set_endpoint_client_handshake_failed_callback(context,
            [](gosling_context* context,
               gosling_handshake_handle_t handle,
               const gosling_error* error) -> void {
                try {
                    // find our handshake data
                    auto it = ENDPOINT_CLIENT_HANDSHAKES.find(handle);
                    assert(it != ENDPOINT_CLIENT_HANDSHAKES.end());
                    // handshake over erase
                    ENDPOINT_CLIENT_HANDSHAKES.erase(it);

                    TERM.write_line("  endpoint client handshake failed!");

                    ostringstream ss;
                    ss << "error: " << error;
                    TERM.write_line(ss.str());
                } catch (...) {
                    TERM.write_line("endpoint_client_handshake_failed callback threw exception");
                }
            }, throw_on_error());
    }
}
