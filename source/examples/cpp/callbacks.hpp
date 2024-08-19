#pragma once

namespace example {
    void register_identity_server_callbacks(gosling_context* context);
    void register_identity_client_callbacks(gosling_context* context);
    void register_endpoint_server_callbacks(gosling_context* context);
    void register_endpoint_client_callbacks(gosling_context* context);

    inline void register_callbacks(gosling_context* context) {
        // register callback for tor bootstrap updates
        ::gosling_context_set_tor_bootstrap_status_received_callback(context,
            [](gosling_context*,
               uint32_t progress,
               const char* tag,
               size_t tag_length,
               const char* summary,
               size_t summary_length) -> void {
                try {
                    ostringstream ss;
                    ss << "  bootstrap progress: " << progress << "% - " << summary;
                    TERM.write_line(ss.str());

                    if (progress == 100) {
                        BOOTSTRAP_COMPLETE = true;
                        TERM.write_line("  bootstrap complete!");
                    }
                } catch (...) {
                    TERM.write_line("tor_bootstrap_status_received callback threw exception");
                }
            }, throw_on_error());

        register_identity_server_callbacks(context);
        register_identity_client_callbacks(context);
        register_endpoint_server_callbacks(context);
        register_endpoint_client_callbacks(context);
    }
}