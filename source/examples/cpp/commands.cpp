using namespace std;
using namespace gosling;

#include "terminal.hpp"
#include "globals.hpp"
#include "callbacks.hpp"



namespace example {
    void help(const vector<string>& args) {
        if (args.empty() || args.front() == "help") {
            TERM.write_line("Available commands:");
            TERM.write_line("  help COMMAND             Print help for COMMAND");
            TERM.write_line("  init-context             Initialise the gosling context");
            TERM.write_line("  start-identity           Start the identity onion-service");
            TERM.write_line("  stop-identity            Stop the identity onion-service");
            TERM.write_line("  request-endpoint         Connect to identity onion-service and request an endpoint");
            TERM.write_line("  start-endpoint           Start an endpoint onion-service");
            TERM.write_line("  stop-endpoint            Stop an endpoint onion-service");
            TERM.write_line("  connect-endpoint         Connect to a peer's endpoint onion-service");
            TERM.write_line("  drop-peer                Drop a connection to a peer");
            TERM.write_line("  list-peers               List all of the currently connected peers");
            TERM.write_line("  chat                     Send a message to a connected peer");
            TERM.write_line("  exit                     Quits the program");
        }
        else {
            const auto& command = args.front();
            if (command == "init-context") {
                TERM.write_line("usage: init TOR_WORKING_DIRECTORY");
                TERM.write_line("Initialise a gosling context and bootstrap tor");
                TERM.write_line();
                TERM.write_line("  TOR_WORKING_DIRECTORY    The directory where the tor daemon will store");
                TERM.write_line("                           persistent state");
            } else if (command == "start-identity") {
                TERM.write_line("usage: start-identity");
                TERM.write_line("Start the identity onion-service so that clients can make first contact");
            } else if (command == "stop-identity") {
                TERM.write_line("usage: stop-identity");
                TERM.write_line("Stop the identity onion-service so you appear offline to unauthorized clients");
            } else if (command == "request-endpoint") {
                TERM.write_line("usage: request-endpoint SERVER_ID");
                TERM.write_line("Connect to remote identity server and request an endpoint");
            } else if (command == "start-endpoint") {
                TERM.write_line("usage: start-endpoint SERVICE_ID");
                TERM.write_line("Start an endpoint onion-service so that its client may connect");
                TERM.write_line();
                TERM.write_line("  SERVICE_ID               The client's onion-service id whose endpoint");
                TERM.write_line("                           we want to start");
            } else if (command == "stop-endpoint") {
                TERM.write_line("usage: stop-endpoint SERVICE_ID");
                TERM.write_line("Stop an endpoint onion-service so that its associated client may");
                TERM.write_line("no longer connect");
                TERM.write_line();
                TERM.write_line("  SERVICE_ID               The client's onion-service id whose endpoint");
                TERM.write_line("                           we want to stop");
            } else if (command == "connect-endpoint") {
                TERM.write_line("usage: connect-endpoint SERVER_ID");
                TERM.write_line("Connect to a peer's endpoint onion-service");
                TERM.write_line();
                TERM.write_line("  SERVER_ID                The server's identity service id");
            } else if (command == "drop-peer") {
                TERM.write_line("usage: drop-peer SERVICE_ID");
                TERM.write_line("Drop an existing peer connection");
                TERM.write_line();
                TERM.write_line("  SERVICE_ID               The remote peer's identity service id");
            } else if (command == "list-peers") {
                TERM.write_line("usage: list-peers");
                TERM.write_line("Print list of connected peers we can chat with");
            } else if (command == "chat") {
                TERM.write_line("usage: chat SERVICE_ID MESSAGE...");
                TERM.write_line("Send a message to a connected peer");
                TERM.write_line();
                TERM.write_line("  SERVICE_ID               The remote peer's identity service id");
                TERM.write_line("  MESSAGE...               A message to send to the remote peer");
            } else if (command == "exit") {
                TERM.write_line("usage: exit");
                TERM.write_line("Quits the program");
            } else {
                TERM.write_line("Unknown command");
            }
        }
    }

    // initialise a new gosling context, launch tor and bootstrap
    void init_context(const vector<string>& args) {
        if (args.size() != 1) {
            help({"init-context"});
            return;
        }

        if (GOSLING_CONTEXT) {
            TERM.write_line("error: context already initialised");
            return;
        }

        const auto& tor_working_directory = args.front();

        // initialise a tor provider for our gosling context
        unique_ptr<gosling_tor_provider_config> tor_provider_config;
        ::gosling_tor_provider_config_new_bundled_legacy_client_config(out(tor_provider_config), nullptr, 0, tor_working_directory.data(), tor_working_directory.size(), throw_on_error());

        unique_ptr<gosling_tor_provider> tor_provider;
        ::gosling_tor_provider_from_tor_provider_config(out(tor_provider), tor_provider_config.get(), throw_on_error());

        TERM.write_line("generating new identity key");

        // generate a private key for our identity
        unique_ptr<gosling_ed25519_private_key> identity_private_key;
        ::gosling_ed25519_private_key_generate(out(identity_private_key), throw_on_error());

        // get onion service id
        unique_ptr<gosling_v3_onion_service_id> identity_service_id;
        ::gosling_v3_onion_service_id_from_ed25519_private_key(out(identity_service_id), identity_private_key.get(), throw_on_error());

        IDENTITY_SERVICE_ID = std::move(identity_service_id);

        ostringstream ss;
        ss << "  identity onion service id: " << IDENTITY_SERVICE_ID.get();
        TERM.write_line(ss.str());

        // init context
        TERM.write_line("creating context");
        unique_ptr<gosling_context> context;
        ::gosling_context_init(out(context), tor_provider.release(), 1120, 401, identity_private_key.get(), throw_on_error());

        // gosling's functionality depends on a number of callbacks, so register them
        TERM.write_line("registering callbacks");
        register_callbacks(context.get());

        // connect to the tor network
        TERM.write_line("beginning bootstrap");
        ::gosling_context_bootstrap_tor(context.get(), throw_on_error());

        // save off our context
        GOSLING_CONTEXT = std::move(context);
    }

    // start the identity server
    void start_identity(const vector<string>& args) {
        if (args.size() != 0) {
            help({"start-identity"});
            return;
        }

        if (!GOSLING_CONTEXT) {
            TERM.write_line("error: context not yet initialised");
            return;
        }

        TERM.write_line("starting identity server");
        ::gosling_context_start_identity_server(GOSLING_CONTEXT.get(), throw_on_error());
    }

    // stop the identity server
    void stop_identity(const vector<string>& args) {
        if (args.size() != 0) {
            help({"stop-identity"});
        }

        if (!GOSLING_CONTEXT) {
            TERM.write_line("error: context not yet initialised");
            return;
        }

        ::gosling_context_stop_identity_server(GOSLING_CONTEXT.get(), throw_on_error());
        IDENTITY_SERVER_PUBLISHED = false;
        TERM.write_line("stopped identity server");
    }

    // request an endpoint from a remote identity server
    void request_endpoint(const vector<string>& args) {
        if (args.size() != 1) {
            help({"request-endpoint"});
            return;
        }

        if (!GOSLING_CONTEXT) {
            TERM.write_line("error: context not yet initialised");
            return;
        }

        const auto& onion_service_id = args[0];
        unique_ptr<gosling_v3_onion_service_id> remote_identity_service_id;
        ::gosling_v3_onion_service_id_from_string(out(remote_identity_service_id), onion_service_id.data(), onion_service_id.size(), throw_on_error());

        ostringstream ss;
        ss << "requesting endpoint from " << onion_service_id;
        TERM.write_line(ss.str());

        string endoint_name = ENDPOINT_NAME;

        // start the handshake
        const auto handle = ::gosling_context_begin_identity_handshake(GOSLING_CONTEXT.get(),remote_identity_service_id.get(), endoint_name.data(), endoint_name.size(), throw_on_error());

        // create entry for client handshake
        identity_client_handshake data;
        data.server_service_id = std::move(remote_identity_service_id);
        data.endpoint_name = std::move(endoint_name);
        IDENTITY_CLIENT_HANDSHAKES.insert({handle, std::move(data)});
    }

    void start_endpoint(const vector<string>& args) {
        if (args.size() != 1) {
            help({"start-endpoint"});
            return;
        }

        if (!GOSLING_CONTEXT) {
            TERM.write_line("error: context not yet initialised");
            return;
        }

        const auto& client_service_id = args[0];
        if (auto it = ENDPOINT_SERVER_CONFIGS.find(client_service_id); it != ENDPOINT_SERVER_CONFIGS.end()) {
            auto& config = it->second;

            ostringstream ss;
            ss << "starting endpoint for " << client_service_id;
            ::gosling_context_start_endpoint_server(GOSLING_CONTEXT.get(), config.server_private_key.get(), ENDPOINT_NAME.data(), ENDPOINT_NAME.size(), config.client_service_id.get(), config.client_auth_public.get(), throw_on_error());
            TERM.write_line(ss.str());
        } else {
            TERM.write_line(string("error: config for ") + client_service_id + " not found");
        }
    }

    void stop_endpoint(const vector<string>& args) {
        if (args.size() != 1) {
            help({"stop-endpoint"});
            return;
        }

        if (!GOSLING_CONTEXT) {
            TERM.write_line("error: context not yet initialised");
            return;
        }

        const auto& client_service_id = args[0];
        if (auto it = ENDPOINT_SERVER_CONFIGS.find(client_service_id);
            it != ENDPOINT_SERVER_CONFIGS.end()) {
            auto& config = it->second;

            ostringstream ss;
            ss << "stopping endpoint for " << client_service_id;
            ::gosling_context_stop_endpoint_server(GOSLING_CONTEXT.get(), config.server_private_key.get(), throw_on_error());
            TERM.write_line(ss.str());
        } else {
            TERM.write_line(string("error: config for ") + client_service_id + " not found");
        }
    }

    void connect_endpoint(const vector<string>& args) {
        if (args.size() != 1) {
            help({"connect-endpoint"});
            return;
        }

        if (!GOSLING_CONTEXT) {
            TERM.write_line("error: context not yet initialised");
            return;
        }

        const auto& server_service_id_string = args[0];
        unique_ptr<gosling_v3_onion_service_id> identity_service_id;
        ::gosling_v3_onion_service_id_from_string(out(identity_service_id), server_service_id_string.data(), server_service_id_string.size(), throw_on_error());

        if (auto it = ENDPOINT_CLIENT_CREDENTIALS.find(server_service_id_string);
            it != ENDPOINT_CLIENT_CREDENTIALS.end()) {
            auto& credentials = it->second;

            ostringstream ss;
            ss << "connecting to endpoint " << server_service_id_string;
            TERM.write_line(ss.str());
            // begin connecting
            const auto handle = ::gosling_context_begin_endpoint_handshake(GOSLING_CONTEXT.get(), credentials.endpoint_service_id.get(), credentials.client_auth_private.get(), CHANNEL_NAME.data(), CHANNEL_NAME.size(), throw_on_error());

            // create entry for client handshake
            endpoint_client_handshake data;
            data.identity_server_service_id = std::move(identity_service_id);
            ::gosling_v3_onion_service_id_clone(out(data.endpoint_server_service_id), credentials.endpoint_service_id.get(), throw_on_error());

            ENDPOINT_CLIENT_HANDSHAKES.insert({handle, std::move(data)});
        } else {
            TERM.write_line(string("error: credentials for ") + server_service_id_string + " not found");
        }
    }

    void drop_peer(const vector<string>& args) {
        if (args.size() != 1) {
            help({"drop-peer"});
            return;
        }

        if (!GOSLING_CONTEXT) {
            TERM.write_line("error: context not yet initialised");
            return;
        }

        const auto& peer = args[0];

        ostringstream ss;
        if (auto it = ENDPOINT_CONNECTIONS.find(args[0]);
            it != ENDPOINT_CONNECTIONS.end()) {
            ENDPOINT_CONNECTIONS.erase(it);
            ss << "removed " << peer;
            TERM.write_line(ss.str());
        } else {
            ss << "no such peer: " << peer;
            TERM.write_line(ss.str());
        }
    }

    void list_peers(const vector<string>& args) {
        if (!args.empty()) {
            help({"list-peers"});
            return;
        }

        if (!GOSLING_CONTEXT) {
            TERM.write_line("error: context not yet initialised");
            return;
        }


        if (ENDPOINT_CONNECTIONS.empty()) {
            TERM.write_line("no peers connected");
        } else {
            ostringstream ss;
            ss << "available peers:\n";

            for (const auto& pair : ENDPOINT_CONNECTIONS) {
                ss << "  " << pair.first << '\n';
            }
            TERM.write_line(ss.str());
        }
    }

    void chat(const vector<string>& args) {
        if (args.size() < 2) {
            help({"chat"});
            return;
        }

        if (!GOSLING_CONTEXT) {
            TERM.write_line("error: context not yet initialised");
            return;
        }

        const auto& recipient = args[0];
        ostringstream ss;
        ss << args[1];
        for (auto i = 2; i < args.size(); i++) {
            ss << " " << args[i];
        }
        ss << "\n";
        const auto msg = ss.str();

        auto it = ENDPOINT_CONNECTIONS.find(recipient);
        if (it == ENDPOINT_CONNECTIONS.end()) {
            TERM.write_line(string("no connection found for ") + recipient);
            return;
        }

        boost::asio::write(it->second.socket, boost::asio::buffer(msg.data(), msg.size()));
    }

    void exit(const vector<string>&) {
        EXIT_REQUESTED = true;
    }
}