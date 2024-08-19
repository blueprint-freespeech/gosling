#pragma once

namespace example {

    // Some state flags
    inline bool EXIT_REQUESTED{false};
    inline bool BOOTSTRAP_COMPLETE{false};
    inline bool IDENTITY_SERVER_PUBLISHED{false};

    // Global data
    inline unique_ptr<gosling_library> LIBRARY{};
    inline unique_ptr<gosling_context> GOSLING_CONTEXT{};
    inline unique_ptr<gosling_v3_onion_service_id> IDENTITY_SERVICE_ID{};
    inline boost::asio::io_service IO_SERVICE{};

    //
    // Handshake Constants
    //
    inline const string ENDPOINT_NAME{"example-endpoint"};
    inline const string CHANNEL_NAME{"example-channel"};

    //
    // In-Progress Handshake Data
    //

    // data available to an identity server during handshake
    struct identity_server_handshake  {
        // the service id of the connecting client
        unique_ptr<gosling_v3_onion_service_id> client_service_id;
        // the endpoint name the client is requesting
        string endpoint_name;
        // the challenge document we sent the client
        vector<uint8_t> challenge_bson;
        // the response document we received back from the client
        json challenge_response;
    };

    // data available to an identity client during handshake
    struct identity_client_handshake {
        // the service id of the identity server we are connecting to
        unique_ptr<gosling_v3_onion_service_id> server_service_id;
        // the endpoint name we have requested
        string endpoint_name;
        // received challenge document
        json challenge;
        // challenge response bson
        vector<uint8_t> challenge_response_bson;
    };

    // data available to an endpoint server during handshake
    struct endpoint_server_handshake {
        // the service id of the connecting client
        unique_ptr<gosling_v3_onion_service_id> client_service_id;
        // channel name the client is requesting
        string channel_name;
    };

    // data available to an endpoint clielnt during handshake
    struct endpoint_client_handshake {
        // the service id of the identity server associated with the endpoint server we are connecting to
        unique_ptr<gosling_v3_onion_service_id> identity_server_service_id;
        // the service id of the endpoint server we are connecting to
        unique_ptr<gosling_v3_onion_service_id> endpoint_server_service_id;
    };

    // in-process identity server handshakes
    inline map<gosling_handshake_handle_t, identity_server_handshake> IDENTITY_SERVER_HANDSHAKES{};

    // in-process identity client handshakes
    inline map<gosling_handshake_handle_t, identity_client_handshake> IDENTITY_CLIENT_HANDSHAKES{};

    // in-process endpoint server handshakes
    inline map<gosling_handshake_handle_t, endpoint_server_handshake> ENDPOINT_SERVER_HANDSHAKES{};

    // in-process endpoint client handshakes
    inline map<gosling_handshake_handle_t, endpoint_client_handshake>
        ENDPOINT_CLIENT_HANDSHAKES{};

    //
    // Resolved Handshake Data
    //

    // credentials needed to connect to an endpoint server
    struct endpoint_client_credentials {
        unique_ptr<gosling_v3_onion_service_id> endpoint_service_id;
        unique_ptr<gosling_x25519_private_key> client_auth_private;
    };

    // credentials needed to host an endpoint server
    struct endpoint_server_config {
        unique_ptr<gosling_ed25519_private_key> server_private_key;
        unique_ptr<gosling_v3_onion_service_id> client_service_id;
        unique_ptr<gosling_x25519_public_key> client_auth_public;
    };

    // server identity onion service id to endpoint credentials
    inline map<string, endpoint_client_credentials> ENDPOINT_CLIENT_CREDENTIALS{};
    // client identity onion service id to credentials
    inline map<string, endpoint_server_config> ENDPOINT_SERVER_CONFIGS{};

    //
    // Connected Peers
    //

    // socket and buffer for async reads
    struct peer_connection {
        string read_buffer;
        boost::asio::ip::tcp::socket socket = boost::asio::ip::tcp::socket(IO_SERVICE);
    };
    // peer identity service id to tcp stream
    inline map<string, peer_connection> ENDPOINT_CONNECTIONS{};

}