using namespace std;
using namespace gosling;

#include "terminal.hpp"
#include "globals.hpp"

namespace example {
    void register_identity_server_callbacks(gosling_context* context) {

        // it takes some time before an onion service is published to the tor netork
        // and is accessible by clients, this callback fires at the earliest time
        // the identity onion service is available
        ::gosling_context_set_identity_server_published_callback(context,
            [](gosling_context*) -> void {
                try {
                    // tor notifies publish multiple times
                    if (IDENTITY_SERVER_PUBLISHED) {
                        return;
                    }
                    TERM.write_line("  identity server published");

                    IDENTITY_SERVER_PUBLISHED = true;
                } catch (...) {
                    TERM.write_line("identity_server_published callback threw exception");
                }
            }, throw_on_error());

    // callback fires when a client attempts to make a connection
    ::gosling_context_set_identity_server_handshake_started_callback(context,
        [](gosling_context*,
           gosling_handshake_handle_t handle) -> void {
            try {
                TERM.write_line("  identity handshake starting");

                identity_server_handshake data;
                IDENTITY_SERVER_HANDSHAKES.insert({handle, std::move(data)});
            } catch (...) {
                TERM.write_line("identity_server_handshake_started callback threw exception");
            }
        }, throw_on_error());

    // callback for checking to see if a connecting client is allowed (ie that
    // they have not been banned, rate-limited, etc)
    ::gosling_context_set_identity_server_client_allowed_callback(context,
        [](gosling_context*, gosling_handshake_handle_t handle, const gosling_v3_onion_service_id* client_service_id) -> bool {
            try {
                // find our handshake data
                auto it = IDENTITY_SERVER_HANDSHAKES.find(handle);
                assert(it != IDENTITY_SERVER_HANDSHAKES.end());

                // save off connecting client's service id
                ::gosling_v3_onion_service_id_clone(out(it->second.client_service_id), client_service_id, throw_on_error());

                ostringstream ss;
                ss << "  " << client_service_id << " requesting endpoint";
                TERM.write_line(ss.str());

                // one could maintain a list of blocked clients and always reject their request
                return true;
            } catch (...) {
                TERM.write_line("identity_server_client_allowed callback threw exception");
                return false;
            }
        }, throw_on_error());

    // callback for checking to see if a requested endpoint is supported
    ::gosling_context_set_identity_server_endpoint_supported_callback(context,
        [](gosling_context*,
           gosling_handshake_handle_t handle,
           const char* endpoint_name,
           size_t endpoint_name_length) -> bool {
            try {
                // find our handshake data
                auto it = IDENTITY_SERVER_HANDSHAKES.find(handle);
                assert(it != IDENTITY_SERVER_HANDSHAKES.end());

                // save off connect client's requested endpoint name
                it->second.endpoint_name = string_view(endpoint_name, endpoint_name_length);

                // ensure client is asking for a supported endpoint
                // this way one endpoint server can manage multiple different endpoint
                // services
                return it->second.endpoint_name == ENDPOINT_NAME;
            } catch (...) {
                TERM.write_line("identity_server_endpoint_supported callback threw exception");
                return false;
            }
        }, throw_on_error());

    // callback for getting the required size of a challenge object
    ::gosling_context_set_identity_server_challenge_size_callback(context,
        [](gosling_context*,
           gosling_handshake_handle_t handle) -> size_t {
            try {
                // find our handshake data
                auto it = IDENTITY_SERVER_HANDSHAKES.find(handle);
                assert(it != IDENTITY_SERVER_HANDSHAKES.end());

                // gosling allows a customisable challenge + response using
                // bson documents; for now just send an empty document
                const auto challenge_json = json::object();
                const auto challenge_bson = json::to_bson(challenge_json);
                it->second.challenge_bson = challenge_bson;

                return challenge_bson.size();
            } catch (const std::exception& ex) {
                TERM.write_line("identity_server_challenge_size callback threw exception");
                TERM.write_line(string("ex.what(): ") + ex.what());
                return 0;
            }
        }, throw_on_error());

    // callback for the identity server to populate the challenge object to send to client
    ::gosling_context_set_identity_server_build_challenge_callback(context,
        [](gosling_context*,
           gosling_handshake_handle_t handle,
           uint8_t* out_challenge_buffer,
           size_t challenge_buffer_size) -> void {
            try {
                // find our handshake data
                auto it = IDENTITY_SERVER_HANDSHAKES.find(handle);
                assert(it != IDENTITY_SERVER_HANDSHAKES.end());

                // copy challenge to the provided buffer
                const auto& challenge_bson = it->second.challenge_bson;
                assert(challenge_bson.size() == challenge_buffer_size);
                std::copy(challenge_bson.begin(), challenge_bson.end(), out_challenge_buffer);
            } catch (...) {
                TERM.write_line("identity_server_build_challenge callback threw exception");
            }
        }, throw_on_error());

    // callback for the identity server to verify the client's challenge response
    ::gosling_context_set_identity_server_verify_challenge_response_callback(context,
        [](gosling_context*,
           gosling_handshake_handle_t handle,
           const uint8_t* challenge_response_buffer,
           size_t challenge_response_buffer_size) -> bool {
            try {
                // find our handshake data
                auto it = IDENTITY_SERVER_HANDSHAKES.find(handle);
                assert(it != IDENTITY_SERVER_HANDSHAKES.end());

                // parse our received bson challenge response buffer
                it->second.challenge_response = json::from_bson(challenge_response_buffer, challenge_response_buffer + challenge_response_buffer_size);

                // for now, we expect an empty bson document in response, but again
                // this can be customised for the application
                return it->second.challenge_response == json::object();
            } catch (...) {
                TERM.write_line("identity_server_verify_challenge_response threw exception");
                return false;
            }
        }, throw_on_error());

    // callback for signaling to identity server handshake has succeeded
    ::gosling_context_set_identity_server_handshake_completed_callback(context,
        [](gosling_context*,
           gosling_handshake_handle_t handle,
           const gosling_ed25519_private_key* endpoint_private_key,
           const char* endpoint_name,
           size_t endpoint_name_length,
           const gosling_v3_onion_service_id* client_service_id,
           const gosling_x25519_public_key* client_auth_public_key) -> void {
            try {
                // find our handshake data
                auto it = IDENTITY_SERVER_HANDSHAKES.find(handle);
                assert(it != IDENTITY_SERVER_HANDSHAKES.end());
                // and remove it since the handshake is complete
                IDENTITY_SERVER_HANDSHAKES.erase(it);

                TERM.write_line("  server identity handshake succeeded");

                // save off config needed to start endpoint server
                endpoint_server_config server_config;
                ::gosling_ed25519_private_key_clone(out(server_config.server_private_key), endpoint_private_key, throw_on_error());
                ::gosling_v3_onion_service_id_clone(out(server_config.client_service_id), client_service_id, throw_on_error());
                ::gosling_x25519_public_key_clone(out(server_config.client_auth_public), client_auth_public_key, throw_on_error());

                ENDPOINT_SERVER_CONFIGS.insert({to_string(client_service_id), std::move(server_config)});
            } catch (...) {
                TERM.write_line("identity_server_handshake_completed callback threw exception");
            }
        }, throw_on_error());

    // callback for signalling to identity server that a handshake has been rejected
    ::gosling_context_set_identity_server_handshake_rejected_callback(context,
        [](gosling_context*,
           gosling_handshake_handle_t handle,
           bool client_allowed,
           bool client_requested_endpoint_valid,
           bool client_proof_signature_valid,
           bool client_auth_signature_valid,
           bool challenge_response_valid) -> void {
            try {
                // find our handshake data
                auto it = IDENTITY_SERVER_HANDSHAKES.find(handle);
                assert(it != IDENTITY_SERVER_HANDSHAKES.end());
                // and remove it since the handshake is complete
                IDENTITY_SERVER_HANDSHAKES.erase(it);

                TERM.write_line("  identity server handshake rejected:");
                TERM.write_line(string("   client_allowed:                  ") + (client_allowed ? "true" : "false"));
                TERM.write_line(string("   client_requested_endpoint_valid: ") + (client_requested_endpoint_valid ? "true" : "false"));
                TERM.write_line(string("   client_proof_signature_valid:    ") + (client_proof_signature_valid ? "true" : "false"));
                TERM.write_line(string("   client_auth_signature_valid:     ") + (client_auth_signature_valid ? "true" : "false"));
                TERM.write_line(string("   challenge_response_valid:        ") + (challenge_response_valid ? "true" : "false"));

            } catch (...) {
                TERM.write_line("identity_server_handshake_rejected callback threw exception");
            }
        }, throw_on_error());

    // callback for signalling to identity server handshake failure
    ::gosling_context_set_identity_server_handshake_failed_callback(context,
        [](gosling_context*,
           gosling_handshake_handle_t handle,
           const gosling_error* error) -> void {
            try {
                // find our handshake data
                auto it = IDENTITY_SERVER_HANDSHAKES.find(handle);
                assert(it != IDENTITY_SERVER_HANDSHAKES.end());
                // and remove it since the handshake is complete
                IDENTITY_SERVER_HANDSHAKES.erase(it);

                ostringstream ss;

                TERM.write_line("  identity server handshake failed!");
                ss << "error: " << error;
                TERM.write_line(ss.str());
            } catch (...) {
                TERM.write_line("identity_server_handshake_failed callback threw exception");
            }
        }, throw_on_error());
    }
}
