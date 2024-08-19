using namespace std;
using namespace gosling;

#include "terminal.hpp"
#include "globals.hpp"

namespace example {
    void register_endpoint_server_callbacks(gosling_context* context) {
        // callback for signalling to the server that a client has connected and an endpoint
        // handshake is starting
        ::gosling_context_set_endpoint_server_handshake_started_callback(context,
            [](gosling_context*,
               gosling_handshake_handle_t handle) -> void {
                try {
                    TERM.write_line("  endpoint handshake starting");

                    // initialise state data for this handshake
                    endpoint_server_handshake data;
                    ENDPOINT_SERVER_HANDSHAKES.insert({handle, std::move(data)});
                } catch (...) {
                    TERM.write_line("endpoint_server_handshake_started callback threw exception");
                }
            }, throw_on_error());

        // callback for testing if a requested channel is allowed for the given user
        ::gosling_context_set_endpoint_server_channel_supported_callback(context,
            [](gosling_context*,
               gosling_handshake_handle_t handle,
               const gosling_v3_onion_service_id* client_service_id,
               const char* channel_name,
               size_t channel_name_length) -> bool {
                try {
                    // find our handshake data
                    auto it = ENDPOINT_SERVER_HANDSHAKES.find(handle);
                    assert(it != ENDPOINT_SERVER_HANDSHAKES.end());

                    ::gosling_v3_onion_service_id_clone(out(it->second.client_service_id), client_service_id, throw_on_error());
                    it->second.channel_name = string_view(channel_name, channel_name_length);

                    // an endpoint may support multiple different channels
                    // in this example we assume channel_name must be CHANNEL_NAME but one could
                    // have logic here based on the connecting user

                    // ensure the client is asking for a supported channel
                    return it->second.channel_name == CHANNEL_NAME;
                } catch (...) {
                    TERM.write_line("endpoint_server_channel_supported callback threw exception");
                    return false;
                }
            }, throw_on_error());

        // callback for when the endoint server handshake completes successfully
        ::gosling_context_set_endpoint_server_handshake_completed_callback(context,
            [](gosling_context* context,
               gosling_handshake_handle_t handle,
               const gosling_v3_onion_service_id* endpoint_service_id,
               const gosling_v3_onion_service_id* client_service_id,
               const char* channel_name,
               size_t channel_name_length,
               tcp_stream_t stream) -> void {
                try {
                    // find our handshake data
                    auto it = ENDPOINT_SERVER_HANDSHAKES.find(handle);
                    assert(it != ENDPOINT_SERVER_HANDSHAKES.end());
                    // handshake over erase
                    ENDPOINT_SERVER_HANDSHAKES.erase(it);

                    // save off connection info
                    const auto peer_service_id = to_string(client_service_id);
                    auto conn = ENDPOINT_CONNECTIONS.insert({peer_service_id, peer_connection{}});
                    assert(conn.second);
                    conn.first->second.socket.assign(boost::asio::ip::tcp::v4(), stream);
                    conn.first->second.socket.non_blocking(true);

                    TERM.write_line("  endpoint server endpoint handshake succeeded!");
                    TERM.write_line(string("  may now chat to connected client: ") + to_string(client_service_id));
                } catch (std::exception& ex) {
                    TERM.write_line("endpoint_server_handshake_completed callback threw exception");
                    TERM.write_line(ex.what());
                }
            }, throw_on_error());

        // callback for when the endpoint server handshake fails
        ::gosling_context_set_endpoint_server_handshake_failed_callback(context,
            [](gosling_context* context,
               gosling_handshake_handle_t handle,
               const gosling_error* error) -> void {
                try {
                    // find our handshake data
                    auto it = ENDPOINT_SERVER_HANDSHAKES.find(handle);
                    assert(it != ENDPOINT_SERVER_HANDSHAKES.end());
                    // handshake over erase
                    ENDPOINT_SERVER_HANDSHAKES.erase(it);

                    TERM.write_line("  server endpoint handshake failed!");

                    ostringstream ss;
                    ss << "error: " << error;
                    TERM.write_line(ss.str());
                } catch (...) {
                    TERM.write_line("endpoint_server_handshake_failed callback threw exception");
                }
            }, throw_on_error());
    }
}
