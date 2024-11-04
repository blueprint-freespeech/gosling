using namespace std;
using namespace gosling;

#include "terminal.hpp"
#include "globals.hpp"

namespace example {
    void register_identity_client_callbacks(gosling_context* context) {
        // return the required size of identity callback challenge response
        ::gosling_context_set_identity_client_challenge_response_size_callback(context,
            [](void*,
               gosling_context*,
               gosling_handshake_handle_t handle,
               const uint8_t* challenge_buffer,
               size_t challenge_buffer_size) -> size_t {
                try {
                    // find our handshake data
                    auto it = IDENTITY_CLIENT_HANDSHAKES.find(handle);
                    assert(it != IDENTITY_CLIENT_HANDSHAKES.end());

                    // expect an empty challenge doc
                    auto challenge = json::from_bson(challenge_buffer, challenge_buffer + challenge_buffer_size);
                    assert(challenge == json::object());
                    it->second.challenge = challenge;

                    // build an empty document challenge response
                    auto challenge_response = json::object();
                    it->second.challenge_response_bson = json::to_bson(challenge_response);
                    return it->second.challenge_response_bson.size();
                } catch (...) {
                    TERM.write_line("identity_client_challenge_response_size callback threw exception");
                    return 0;
                }
            }, nullptr, throw_on_error());

        // provide the client with a challenge response
        ::gosling_context_set_identity_client_build_challenge_response_callback(context,
            [](void*,
               gosling_context*,
               gosling_handshake_handle_t handle,
               const uint8_t* challenge_buffer,
               size_t challenge_buffer_size,
               uint8_t* out_challenge_response_buffer,
               size_t challenge_response_buffer_size) -> void {
                try {
                    // find our handshake data
                    auto it = IDENTITY_CLIENT_HANDSHAKES.find(handle);
                    assert(it != IDENTITY_CLIENT_HANDSHAKES.end());

                    auto& challenge_response_buffer = it->second.challenge_response_bson;
                    assert(challenge_response_buffer.size() == challenge_response_buffer_size);

                    // copy empty bson document to provided buffer
                    std::copy(challenge_response_buffer.begin(), challenge_response_buffer.end(), out_challenge_response_buffer);
                } catch (...) {
                    TERM.write_line("identity_client_build_challenge_response callback threw exception");
                }
            }, nullptr, throw_on_error());

        // callback for signalling to identity client handshake succeeded
        ::gosling_context_set_identity_client_handshake_completed_callback(context,
            [](void*,
               gosling_context*,
               gosling_handshake_handle_t handle,
               const gosling_v3_onion_service_id* identity_server,
               const gosling_v3_onion_service_id* endpoint_server,
               const char* endpoint_name,
               size_t endpoint_name_length,
               const gosling_x25519_private_key* endpoint_auth_key) -> void {
                try {
                    // find our handshake data
                    auto it = IDENTITY_CLIENT_HANDSHAKES.find(handle);
                    assert(it != IDENTITY_CLIENT_HANDSHAKES.end());
                    // handshake over erase
                    IDENTITY_CLIENT_HANDSHAKES.erase(it);

                    ostringstream ss;
                    ss << "  client identity handshake succeeded\n";
                    ss << "  now authorised to connect to " << identity_server << "'s endpoint";

                    TERM.write_line(ss.str());

                    // save off client credentials for connecting to endpoint server
                    endpoint_client_credentials client_credentials;
                    ::gosling_v3_onion_service_id_clone(out(client_credentials.endpoint_service_id), endpoint_server, throw_on_error());
                    ::gosling_x25519_private_key_clone(out(client_credentials.client_auth_private), endpoint_auth_key, throw_on_error());

                    ENDPOINT_CLIENT_CREDENTIALS.insert({to_string(identity_server), std::move(client_credentials)});
                } catch (...) {
                    TERM.write_line("identity_client_handshake_completed callback threw exception");
                }
            }, nullptr, throw_on_error());
        // callback for signalling to identity client the handshake failed
        ::gosling_context_set_identity_client_handshake_failed_callback(context,
            [](void*,
               gosling_context*,
               gosling_handshake_handle_t handle,
               const gosling_error* error) -> void {
                try {
                    // find our handshake data
                    auto it = IDENTITY_CLIENT_HANDSHAKES.find(handle);
                    assert(it != IDENTITY_CLIENT_HANDSHAKES.end());
                    // handshake over erase
                    IDENTITY_CLIENT_HANDSHAKES.erase(it);

                    TERM.write_line("client identity handshake failed!");

                    ostringstream ss;
                    ss << "error: " << error;
                    TERM.write_line(ss.str());
                } catch (...) {
                    TERM.write_line("identity_client_handshake_failed callback threw exception");
                }
            }, nullptr, throw_on_error());
    }
}
