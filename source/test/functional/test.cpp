using namespace std;
using namespace gosling;

// platform specific wrappers for tcp stream stuffs
#if defined(GOSLING_PLATFORM_WINDOWS)
typedef SOCKET gosling_tcp_socket_t;
#elif (defined(GOSLING_PLATFORM_MACOS) || defined(GOSLING_PLATFORM_LINUX))
typedef int gosling_tcp_socket_t;
#endif

// simple bson document: { msg : "hello world" }
constexpr static uint8_t challenge_bson[] = {
    // document length 26 == 0x0000001a
    0x1a, 0x00, 0x00, 0x00,
    // string msg
    0x02, 'm', 's', 'g', 0x00,
    // strlen("hello world\x00") 12 = 0x0000000c
    0x0c, 0x00, 0x00, 0x00,
    // "hello world"
    'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0x00,
    // document null-terminator
    0x00};

// empty bson document
constexpr static uint8_t challenge_response_bson[] = {
    // document length 5 == 0x00000005
    0x05, 0x00, 0x00, 0x00,
    // document null-terminator
    0x00};

const std::string endpointName("endpoint_name");
const std::string channelName("channel_name");

static void create_client_identity_handshake(unique_ptr<gosling_context> &ctx) {

  const auto challenge_response_size_callback =
      [](gosling_context *context, size_t handshake_handle,
         const uint8_t *challenge_buffer,
         size_t challenge_buffer_size) -> size_t {
    REQUIRE(context != nullptr);
    cout << "--- challenge_response_size_callback: { context: "
         << static_cast<void *>(context)
         << ", handshake_handle: " << handshake_handle << " }" << endl;
    return sizeof(challenge_response_bson);
  };

  REQUIRE_NOTHROW(
      ::gosling_context_set_identity_client_challenge_response_size_callback(
          ctx.get(), challenge_response_size_callback, throw_on_error()));

  const auto build_challenge_response_callback =
      [](gosling_context *context, size_t handshake_handle,
         const uint8_t *challenge_buffer, size_t challenge_buffer_size,
         uint8_t *out_challenge_response_buffer,
         size_t challenge_response_buffer_size) -> void {
    REQUIRE(context != nullptr);
    cout << "--- build_challenge_response_callback: { context: "
         << static_cast<void *>(context)
         << ", handshake_handle: " << handshake_handle << " }" << endl;

    REQUIRE(challenge_buffer_size == sizeof(challenge_bson));
    REQUIRE(std::equal(challenge_buffer,
                       challenge_buffer + challenge_buffer_size,
                       challenge_bson));
    REQUIRE(challenge_response_buffer_size == sizeof(challenge_response_bson));

    std::copy(challenge_response_bson,
              challenge_response_bson + sizeof(challenge_response_bson),
              out_challenge_response_buffer);
  };

  REQUIRE_NOTHROW(
      ::gosling_context_set_identity_client_build_challenge_response_callback(
          ctx.get(), build_challenge_response_callback, throw_on_error()));
}

static void create_server_identity_handshake(unique_ptr<gosling_context> &ctx) {

  const auto client_allowed_callback =
      [](gosling_context *context, size_t handshake_handle,
         const gosling_v3_onion_service_id *client_service_id) -> bool {
    REQUIRE(context != nullptr);
    cout << "--- client allowed callback: { context: " << context
         << ", handshake_handle: " << handshake_handle << " }" << endl;

    return true;
  };

  REQUIRE_NOTHROW(::gosling_context_set_identity_server_client_allowed_callback(
      ctx.get(), client_allowed_callback, throw_on_error()));

  const auto endpoint_supported_callback =
      [](gosling_context *context, size_t handshake_handle,
         const char *endpoint_name, size_t endpoint_name_length) -> bool {
    REQUIRE(context != nullptr);
    cout << "--- endpoint_supported_callback: { context: " << context
         << ", handshake_handle: " << handshake_handle << " }" << endl;

    if (string(endpoint_name, endpoint_name_length) == endpointName) {
      return true;
    }

    return false;
  };

  REQUIRE_NOTHROW(
      ::gosling_context_set_identity_server_endpoint_supported_callback(
          ctx.get(), endpoint_supported_callback, throw_on_error()));

  const auto challenge_size_callback = [](gosling_context *context,
                                          size_t handshake_handle) -> size_t {
    REQUIRE(context != nullptr);
    cout << "--- challenge_size_callback: { context: " << context
         << ", handshake_handle: " << handshake_handle << " }" << endl;
    return sizeof(challenge_bson);
  };

  REQUIRE_NOTHROW(::gosling_context_set_identity_server_challenge_size_callback(
      ctx.get(), challenge_size_callback, throw_on_error()));

  const auto build_challenge_callback =
      [](gosling_context *context, size_t handshake_handle,
         uint8_t *out_challenge_buffer, size_t challenge_buffer_size) -> void {
    REQUIRE(context != nullptr);
    cout << "--- build_challenge_callback: { context: " << context
         << ", handshake_handle: " << handshake_handle << " }" << endl;

    REQUIRE(out_challenge_buffer != nullptr);
    REQUIRE(challenge_buffer_size == sizeof(challenge_bson));

    std::copy(challenge_bson, challenge_bson + sizeof(challenge_bson),
              out_challenge_buffer);
  };

  REQUIRE_NOTHROW(
      ::gosling_context_set_identity_server_build_challenge_callback(
          ctx.get(), build_challenge_callback, throw_on_error()));

  const auto verify_challenge_response_callback =
      [](gosling_context *context, size_t handshake_handle,
         const uint8_t *challenge_response_buffer,
         size_t challenge_response_buffer_size) -> bool {
    REQUIRE(context != nullptr);
    cout << "--- verify_challenge_response_callback: { context: " << context
         << ", handshake_handle: " << handshake_handle << " }" << endl;

    REQUIRE(challenge_response_buffer != nullptr);

    if (challenge_response_buffer_size != sizeof(challenge_response_bson)) {
      return false;
    }

    if (!std::equal(challenge_response_buffer,
                    challenge_response_buffer + challenge_response_buffer_size,
                    challenge_response_bson)) {
      return false;
    }

    return true;
  };

  REQUIRE_NOTHROW(
      ::gosling_context_set_identity_server_verify_challenge_response_callback(
          ctx.get(), verify_challenge_response_callback, throw_on_error()));
}

static void create_server_endpoint_handshake(unique_ptr<gosling_context> &ctx) {
  const auto channel_supported_callback =
      [](gosling_context *context, size_t handshake_handle,
         const gosling_v3_onion_service_id *client_service_id,
         const char *channel_name, size_t channel_name_length) -> bool {
    REQUIRE(context != nullptr);
    REQUIRE(client_service_id != nullptr);
    cout << "--- channel_supported_callback: { context: " << context
         << ", handshake_handle: " << handshake_handle
         << ", client_service_id: " << client_service_id << ", channel_name: '"
         << channel_name << "' }" << endl;

    if (string(channel_name, channel_name_length) == channelName) {
      return true;
    }

    return false;
  };

  REQUIRE_NOTHROW(
      ::gosling_context_set_endpoint_server_channel_supported_callback(
          ctx.get(), channel_supported_callback, throw_on_error()));
}

enum gosling_tor_provider_type {
  mock_tor_provider,
  legacy_tor_provider,
};

// we template this function to ensure the static symbols defined here are
// different, since we can repeatedly call this function with different
// gosling_tor_providers, and we want each invocation to start fresh
template <gosling_tor_provider_type TP>
void gosling_cpp_demo_impl(
    unique_ptr<gosling_tor_provider> &&alice_tor_provider,
    unique_ptr<gosling_tor_provider> &&pat_tor_provider) {

  // and ensure at runtime we haven't accidentally called this function twice
  static bool never_been_called = true;
  REQUIRE(never_been_called);
  never_been_called = false;

  // generate private keys
  unique_ptr<gosling_ed25519_private_key> alice_private_key;
  REQUIRE_NOTHROW(::gosling_ed25519_private_key_generate(out(alice_private_key),
                                                         throw_on_error()));

  cout << "alice key: " << alice_private_key.get() << endl;

  unique_ptr<gosling_ed25519_private_key> pat_private_key;
  REQUIRE_NOTHROW(::gosling_ed25519_private_key_generate(out(pat_private_key),
                                                         throw_on_error()));

  cout << "pat key: " << pat_private_key.get() << endl;

  // calculate service ids
  unique_ptr<gosling_v3_onion_service_id> alice_identity;
  REQUIRE_NOTHROW(::gosling_v3_onion_service_id_from_ed25519_private_key(
      out(alice_identity), alice_private_key.get(), throw_on_error()));

  cout << "alice service id: " << alice_identity.get() << endl;

  unique_ptr<gosling_v3_onion_service_id> pat_identity;
  REQUIRE_NOTHROW(::gosling_v3_onion_service_id_from_ed25519_private_key(
      out(pat_identity), pat_private_key.get(), throw_on_error()));

  cout << "pat service id: " << pat_identity.get() << endl;

  // init contexts
  unique_ptr<gosling_context> alice_context;
  REQUIRE_NOTHROW(
      ::gosling_context_init(out(alice_context),           // out_context
                             alice_tor_provider.release(), // tor_provider
                             420,                          // identity port
                             420,                          // endpoint port
                             alice_private_key.get(), // identity private key
                             throw_on_error()));

  // server callbacks
  create_server_identity_handshake(alice_context);
  create_server_endpoint_handshake(alice_context);

  unique_ptr<gosling_context> pat_context;
  REQUIRE_NOTHROW(
      ::gosling_context_init(out(pat_context),           // out_context
                             pat_tor_provider.release(), // tor_provider
                             420,                        // identity port
                             420,                        // endpoint port
                             alice_private_key.get(),    // identity private key
                             throw_on_error()));

  // client callbacks
  create_client_identity_handshake(pat_context);

  // bootstrap alice
  static bool alice_bootstrap_complete = false;

  REQUIRE_NOTHROW(::gosling_context_set_tor_bootstrap_completed_callback(
      alice_context.get(),
      [](gosling_context *context) -> void {
        alice_bootstrap_complete = true;
        cout << "--- alice bootstrapped" << endl;
      },
      throw_on_error()));

  cout << "--- begin alice bootstrap" << endl;
  REQUIRE_NOTHROW(
      ::gosling_context_bootstrap_tor(alice_context.get(), throw_on_error()));

  while (!alice_bootstrap_complete) {
    REQUIRE_NOTHROW(
        ::gosling_context_poll_events(alice_context.get(), throw_on_error()));
  }

  // init alice's identity server
  static bool alice_identity_server_ready = false;
  REQUIRE_NOTHROW(::gosling_context_set_identity_server_published_callback(
      alice_context.get(),
      [](gosling_context *context) -> void {
        alice_identity_server_ready = true;
        cout << "--- alice identity server published" << endl;
      },
      throw_on_error()));

  cout << "--- start alice identity server" << endl;
  REQUIRE_NOTHROW(::gosling_context_start_identity_server(alice_context.get(),
                                                          throw_on_error()));

  while (!alice_identity_server_ready) {
    REQUIRE_NOTHROW(
        ::gosling_context_poll_events(alice_context.get(), throw_on_error()));
  }

  // bootstrap pat
  static bool pat_bootstrap_complete = false;
  REQUIRE_NOTHROW(::gosling_context_set_tor_bootstrap_completed_callback(
      pat_context.get(),
      [](gosling_context *context) -> void {
        pat_bootstrap_complete = true;
        cout << "--- pat bootstrapped" << endl;
      },
      throw_on_error()));
  cout << "--- begin pat bootstrap" << endl;
  REQUIRE_NOTHROW(
      ::gosling_context_bootstrap_tor(pat_context.get(), throw_on_error()));

  while (!pat_bootstrap_complete) {
    REQUIRE_NOTHROW(
        ::gosling_context_poll_events(alice_context.get(), throw_on_error()));
    REQUIRE_NOTHROW(
        ::gosling_context_poll_events(pat_context.get(), throw_on_error()));
  }

  // pat requests an endpoint from alice
  static bool pat_endpoint_request_complete = false;
  static unique_ptr<gosling_v3_onion_service_id> alice_endpoint_service_id;
  static unique_ptr<gosling_x25519_private_key> pat_onion_auth_private_key;

  REQUIRE_NOTHROW(
      ::gosling_context_set_identity_client_handshake_completed_callback(
          pat_context.get(),
          [](gosling_context *context, size_t handshake_handle,
             const gosling_v3_onion_service_id *identity_service_id,
             const gosling_v3_onion_service_id *endpoint_service_id,
             const char *endpoint_name, size_t endpoint_name_length,
             const gosling_x25519_private_key *client_auth_private_key)
              -> void {
            REQUIRE(string(endpoint_name, endpoint_name_length) ==
                    endpointName);

            REQUIRE_NOTHROW(::gosling_v3_onion_service_id_clone(
                out(alice_endpoint_service_id), endpoint_service_id,
                throw_on_error()));
            REQUIRE_NOTHROW(::gosling_x25519_private_key_clone(
                out(pat_onion_auth_private_key), client_auth_private_key,
                throw_on_error()));

            pat_endpoint_request_complete = true;
            cout << "--- pat identity handshake completed" << endl;
          },
          throw_on_error()));

  REQUIRE_NOTHROW(
      ::gosling_context_set_identity_client_handshake_failed_callback(
          pat_context.get(),
          [](gosling_context *context, size_t handshake_handle,
             const gosling_error *error) -> void {
            cout << "--- pat identity handshake failed: "
                 << gosling_error_get_message(error) << endl;
            REQUIRE(false);
          },
          throw_on_error()));

  static bool alice_endpoint_request_complete = false;
  static unique_ptr<gosling_ed25519_private_key> alice_endpoint_private_key;
  static unique_ptr<gosling_v3_onion_service_id> pat_identity_service_id;
  static unique_ptr<gosling_x25519_public_key> pat_onion_auth_public_key;
  REQUIRE_NOTHROW(
      ::gosling_context_set_identity_server_handshake_completed_callback(
          alice_context.get(),
          [](gosling_context *context, size_t handshake_handle,
             const gosling_ed25519_private_key *endpoint_private_key,
             const char *endpoint_name, size_t endpoint_name_length,
             const gosling_v3_onion_service_id *client_service_id,
             const gosling_x25519_public_key *client_auth_public_key) -> void {
            REQUIRE(string(endpoint_name, endpoint_name_length) ==
                    endpointName);

            REQUIRE_NOTHROW(::gosling_ed25519_private_key_clone(
                out(alice_endpoint_private_key), endpoint_private_key,
                throw_on_error()));
            REQUIRE_NOTHROW(::gosling_v3_onion_service_id_clone(
                out(pat_identity_service_id), client_service_id,
                throw_on_error()));
            REQUIRE_NOTHROW(::gosling_x25519_public_key_clone(
                out(pat_onion_auth_public_key), client_auth_public_key,
                throw_on_error()));

            alice_endpoint_request_complete = true;
            cout << "--- alice identity handshake completed" << endl;
          },
          throw_on_error()));
  REQUIRE_NOTHROW(
      ::gosling_context_set_identity_server_handshake_failed_callback(
          alice_context.get(),
          [](gosling_context *context, size_t handshake_handle,
             const gosling_error *error) -> void {
            cout << "--- alice identity handshake failed: "
                 << gosling_error_get_message(error) << endl;
            REQUIRE(false);
          },
          throw_on_error()));

  bool pat_begin_identity_handshake_succeeded = false;
  for (auto k = 1; k <= 3; k++) {
    cout << "--- pat begin identity handshake attempt " << k << endl;

    try {
      ::gosling_context_begin_identity_handshake(
          pat_context.get(), alice_identity.get(), endpointName.data(),
          endpointName.size(), throw_on_error());
      pat_begin_identity_handshake_succeeded = true;
      break;
    } catch (...) {
    }
  }
  REQUIRE(pat_begin_identity_handshake_succeeded);

  while (!alice_endpoint_request_complete) {
    REQUIRE_NOTHROW(
        ::gosling_context_poll_events(alice_context.get(), throw_on_error()));
    REQUIRE_NOTHROW(
        ::gosling_context_poll_events(pat_context.get(), throw_on_error()));
  }

  // alice stand's up endpoint server
  static bool alice_endpoint_published = false;
  REQUIRE_NOTHROW(::gosling_context_set_endpoint_server_published_callback(
      alice_context.get(),
      [](gosling_context *context,
         const gosling_v3_onion_service_id *endpoint_service_id,
         const char *endpoint_name, size_t endpoint_name_length) -> void {
        REQUIRE(string(endpoint_name, endpoint_name_length) == endpointName);
        alice_endpoint_published = true;
        cout << "--- alice endpoint server published" << endl;
      },
      throw_on_error()));

  cout << "--- alice endpoint server start" << endl;
  REQUIRE_NOTHROW(::gosling_context_start_endpoint_server(
      alice_context.get(), alice_endpoint_private_key.get(),
      endpointName.data(), endpointName.size(), pat_identity_service_id.get(),
      pat_onion_auth_public_key.get(), throw_on_error()));

  while (!alice_endpoint_published || !pat_endpoint_request_complete) {
    REQUIRE_NOTHROW(
        ::gosling_context_poll_events(pat_context.get(), throw_on_error()));
    REQUIRE_NOTHROW(
        ::gosling_context_poll_events(alice_context.get(), throw_on_error()));
  }

  // pat connects to alice's endpoint
  static bool pat_channel_request_complete = false;
  static bool alice_channel_request_complete = false;
  static gosling_tcp_socket_t pat_stream = gosling_tcp_socket_t();
  static gosling_tcp_socket_t alice_stream = gosling_tcp_socket_t();

  static boost::asio::io_service io_service;
  static boost::asio::ip::tcp::socket pat_socket(io_service);
  static boost::asio::ip::tcp::socket alice_socket(io_service);

  REQUIRE_NOTHROW(
      ::gosling_context_set_endpoint_client_handshake_completed_callback(
          pat_context.get(),
          [](gosling_context *context, size_t handshake_handle,
             const gosling_v3_onion_service_id *endpoint_service_id,
             const char *channel_name, size_t channel_name_length,
             gosling_tcp_socket_t stream) -> void {
            REQUIRE(string(channel_name, channel_name_length) == channelName);

            cout << "--- pat endpoint handshake complete" << endl;
            pat_channel_request_complete = true;
            pat_socket.assign(boost::asio::ip::tcp::v4(), stream);
          },
          throw_on_error()));
  REQUIRE_NOTHROW(
      ::gosling_context_set_endpoint_client_handshake_failed_callback(
          pat_context.get(),
          [](gosling_context *context, size_t handshake_handle,
             const gosling_error *error) -> void {
            cout << "--- pat endpoint handshake failed: "
                 << gosling_error_get_message(error) << endl;
            REQUIRE(false);
          },
          throw_on_error()));

  REQUIRE_NOTHROW(
      ::gosling_context_set_endpoint_server_handshake_completed_callback(
          alice_context.get(),
          [](gosling_context *context, size_t handshake_handle,
             const gosling_v3_onion_service_id *endpoint_service_id,
             const gosling_v3_onion_service_id *client_service_id,
             const char *channel_name, size_t channel_name_length,
             gosling_tcp_socket_t stream) -> void {
            REQUIRE(string(channel_name, channel_name_length) == channelName);
            cout << "--- alice channel request complete" << endl;
            alice_channel_request_complete = true;
            alice_socket.assign(boost::asio::ip::tcp::v4(), stream);
          },
          throw_on_error()));
  REQUIRE_NOTHROW(
      ::gosling_context_set_endpoint_server_handshake_failed_callback(
          alice_context.get(),
          [](gosling_context *context, size_t handshake_handle,
             const gosling_error *error) -> void {
            cout << "--- alice endpoint handshake failed: "
                 << gosling_error_get_message(error) << endl;
            REQUIRE(false);
          },
          throw_on_error()));

  // pat opens chanel to alice's endpoint
  bool pat_begin_endpoint_handshake_succeeded = false;
  for (auto k = 1; k <= 3; k++) {
    cout << "--- pat begin endpoint channel request attempt " << k << endl;
    try {
      ::gosling_context_begin_endpoint_handshake(
          pat_context.get(), alice_endpoint_service_id.get(),
          pat_onion_auth_private_key.get(), channelName.data(),
          channelName.size(), throw_on_error());
      pat_begin_endpoint_handshake_succeeded = true;
      break;
    } catch (...) {
    }
  }
  REQUIRE(pat_begin_endpoint_handshake_succeeded);

  // wait for both channels to be open
  while (!pat_channel_request_complete || !alice_channel_request_complete) {
    REQUIRE_NOTHROW(
        ::gosling_context_poll_events(alice_context.get(), throw_on_error()));
    REQUIRE_NOTHROW(
        ::gosling_context_poll_events(pat_context.get(), throw_on_error()));
  }

  // pat sends Hello Alice to alice
  std::string pat_message = "Hello Alice!\n";
  std::string alice_read_buffer;

  cout << "--- pat writes message" << endl;

  boost::asio::write(
      pat_socket, boost::asio::buffer(pat_message.data(), pat_message.size()));

  cout << "--- alice waits for message" << endl;

  // alice reads
  boost::asio::read_until(alice_socket,
                          boost::asio::dynamic_buffer(alice_read_buffer), '\n');
  REQUIRE(pat_message == alice_read_buffer);

  // remove the trailing new-line byte
  alice_read_buffer.pop_back();

  cout << "--- alice received '" << alice_read_buffer << "'" << endl;

  if constexpr (TP != mock_tor_provider) {

    cout << "--- alice generates token" << endl;

    const auto circuit_token = ::gosling_context_generate_circuit_token(
        alice_context.get(), throw_on_error());

    // connect to example.com
    unique_ptr<gosling_target_address> domain_target_address;
    const std::string domain("www.example.com");

    REQUIRE_NOTHROW(::gosling_target_address_from_domain(
        out(domain_target_address), domain.c_str(), domain.size(), 80,
        throw_on_error()));

    cout << "--- alice connecting to '" << domain_target_address.get() << "'"
         << endl;

    gosling_tcp_socket_t example_socket = 0;
    REQUIRE_NOTHROW(::gosling_context_connect(
        alice_context.get(), &example_socket, domain_target_address.get(),
        circuit_token, throw_on_error()));
    REQUIRE(example_socket != 0);

    // google dns ipv4
    unique_ptr<gosling_ip_address> ipv4_ip_address;
    REQUIRE_NOTHROW(::gosling_ip_address_from_ipv4(out(ipv4_ip_address), 8, 8,
                                                   8, 8, throw_on_error()));

    unique_ptr<gosling_target_address> ipv4_target_address;
    REQUIRE_NOTHROW(::gosling_target_address_from_ip_address(
        out(ipv4_target_address), ipv4_ip_address.get(), 53, throw_on_error()));

    cout << "--- alice connecting to '" << ipv4_target_address.get() << "'"
         << endl;

    gosling_tcp_socket_t ipv4_socket = 0;
    REQUIRE_NOTHROW(::gosling_context_connect(alice_context.get(), &ipv4_socket,
                                              ipv4_target_address.get(),
                                              circuit_token, throw_on_error()));
    REQUIRE(ipv4_socket != 0);

    // google dns ipv6
    unique_ptr<gosling_ip_address> ipv6_ip_address;
    REQUIRE_NOTHROW(::gosling_ip_address_from_ipv6(out(ipv6_ip_address), 0x2001,
                                                   0x4860, 0x4860, 0, 0, 0, 0,
                                                   0x8888, throw_on_error()));

    unique_ptr<gosling_target_address> ipv6_target_address;
    REQUIRE_NOTHROW(::gosling_target_address_from_ip_address(
        out(ipv6_target_address), ipv6_ip_address.get(), 53, throw_on_error()));

    cout << "--- alice connecting to '" << ipv6_target_address.get() << "'"
         << endl;

    gosling_tcp_socket_t ipv6_socket = 0;
    REQUIRE_NOTHROW(::gosling_context_connect(alice_context.get(), &ipv6_socket,
                                              ipv6_target_address.get(),
                                              circuit_token, throw_on_error()));
    REQUIRE(ipv6_socket != 0);

    // riseup onion service
    unique_ptr<gosling_v3_onion_service_id> riseup_service_id;
    REQUIRE_NOTHROW(::gosling_v3_onion_service_id_from_string(
        out(riseup_service_id),
        "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd",
        V3_ONION_SERVICE_ID_STRING_LENGTH, throw_on_error()));

    unique_ptr<gosling_target_address> onion_service_address;
    REQUIRE_NOTHROW(::gosling_target_address_from_v3_onion_service_id(
        out(onion_service_address), riseup_service_id.get(), 80,
        throw_on_error()));

    cout << "--- alice connecting to '" << onion_service_address.get() << "'"
         << endl;

    gosling_tcp_socket_t onion_service_socket = 0;
    REQUIRE_NOTHROW(::gosling_context_connect(
        alice_context.get(), &onion_service_socket, onion_service_address.get(),
        circuit_token, throw_on_error()));
    REQUIRE(onion_service_socket != 0);
  }
}

#ifdef GOSLING_HAVE_MOCK_TOR_PROVIDER
void gosling_cpp_demo_mock_tor_provider() {

  cout << "#" << endl;
  cout << "# Starting gosling_cpp_demo_mock_tor_provider()" << endl;
  cout << "#" << endl;

  unique_ptr<gosling_tor_provider> alice_tor_provider;
  unique_ptr<gosling_tor_provider> pat_tor_provider;

  unique_ptr<gosling_tor_provider_config> mock_tor_provider_config;
  REQUIRE_NOTHROW(::gosling_tor_provider_config_new_mock_client_config(
      out(mock_tor_provider_config), throw_on_error()));

  REQUIRE_NOTHROW(::gosling_tor_provider_from_tor_provider_config(
      out(alice_tor_provider), // out tor_provider
      mock_tor_provider_config.get(), throw_on_error()));

  REQUIRE_NOTHROW(::gosling_tor_provider_from_tor_provider_config(
      out(pat_tor_provider), // out tor_provider
      mock_tor_provider_config.get(), throw_on_error()));

  gosling_cpp_demo_impl<mock_tor_provider>(std::move(alice_tor_provider),
                                           std::move(pat_tor_provider));
}

#endif // GOSLING_HAVE_MOCK_TOR_PROVIDER

#ifdef GOSLING_HAVE_LEGACY_TOR_PROVIDER
void gosling_cpp_demo_legacy_tor_provider() {

  cout << "#" << endl;
  cout << "# Starting gosling_cpp_demo_legacy_tor_provider()" << endl;
  cout << "#" << endl;

  const std::filesystem::path tmp = std::filesystem::temp_directory_path();
  cout << "tmp: " << tmp.string() << endl;

  // init alice tor provider
  const auto alice_working_dir = (tmp / "gosling_context_test_alice").string();
  cout << "alice working dir: " << alice_working_dir << endl;

  unique_ptr<gosling_tor_provider_config> alice_tor_provider_config;
  REQUIRE_NOTHROW(
      ::gosling_tor_provider_config_new_bundled_legacy_client_config(
          out(alice_tor_provider_config), nullptr, 0, alice_working_dir.data(),
          alice_working_dir.size(), throw_on_error()));

  unique_ptr<gosling_tor_provider> alice_tor_provider;
  REQUIRE_NOTHROW(::gosling_tor_provider_from_tor_provider_config(
      out(alice_tor_provider), // out tor_provider
      alice_tor_provider_config.get(), throw_on_error()));

  // init pat tor provider
  const auto pat_working_dir = (tmp / "gosling_context_test_pat").string();
  cout << "pat working dir: " << pat_working_dir << endl;

  unique_ptr<gosling_tor_provider_config> pat_tor_provider_config;
  REQUIRE_NOTHROW(
      ::gosling_tor_provider_config_new_bundled_legacy_client_config(
          out(pat_tor_provider_config), nullptr, 0, pat_working_dir.data(),
          pat_working_dir.size(), throw_on_error()));

  unique_ptr<gosling_tor_provider> pat_tor_provider;
  REQUIRE_NOTHROW(::gosling_tor_provider_from_tor_provider_config(
      out(pat_tor_provider), // out tor_provider
      pat_tor_provider_config.get(), throw_on_error()));

  gosling_cpp_demo_impl<legacy_tor_provider>(std::move(alice_tor_provider),
                                             std::move(pat_tor_provider));
}
#endif // GOSLING_HAVE_LEGACY_TOR_PROVIDER

TEST_CASE("gosling_cpp_demo") {
  // init gosling library statically so gosling objects with static lifetime
  // destruct in the right order
  static unique_ptr<gosling_library> library;
  REQUIRE_NOTHROW(::gosling_library_init(out(library), throw_on_error()));

#ifdef GOSLING_HAVE_MOCK_TOR_PROVIDER
  gosling_cpp_demo_mock_tor_provider();
#endif // GOSLING_HAVE_MOCK_TOR_PROVIDER

#ifdef GOSLING_HAVE_LEGACY_TOR_PROVIDER
  gosling_cpp_demo_legacy_tor_provider();
#endif // GOSLING_HAVE_LEGACY_TOR_PROVIDER
}
