from cgosling import *

def handle_error(err):
    if err:
        err_msg = gosling_error_get_message(err)
        print("error:", err_msg.decode('utf-8'))
        exit(1)

bootstrap_complete = False;

def bootstrap_status_callback(context, progress, tag, tag_length, summary, summary_length):
    print("python: bootstrap_status_callback", progress)
bootstrap_status_c_callback = GoslingTorBootstrapStatusReceivedCallback(bootstrap_status_callback)

def bootstrap_complete_callback(context):
    print("python: bootstrap_complete_callback")
    global bootstrap_complete
    bootstrap_complete = True
bootstrap_complete_c_callback = GoslingTorBootstrapCompletedCallback(bootstrap_complete_callback)

def main():
    # Your main code goes here
    print("Hello, this is the main function!")

    err = GoslingErrorPtr()
    library = GoslingLibraryPtr()

    print("initing cgosling library")
    gosling_library_init(pointer(library), pointer(err))
    handle_error(err)

    # init context
    print("create context")

    tor_provider = GoslingTorProviderPtr()
    tor_working_directory = "/tmp/python-test"
    tor_working_directory_c_str = create_string_buffer(tor_working_directory.encode('utf-8'))
    tor_working_directory_c_str_len = c_size_t(len(tor_working_directory))
    tor_provider_config = GoslingTorProviderConfigPtr()
    gosling_tor_provider_config_new_bundled_legacy_client_config(pointer(tor_provider_config), None, 0, tor_working_directory_c_str, tor_working_directory_c_str_len, pointer(err))
    handle_error(err)
    gosling_tor_provider_from_tor_provider_config(pointer(tor_provider), tor_provider_config, pointer(err))
    handle_error(err)

    identity_private_key = GoslingEd25519PrivateKeyPtr()
    gosling_ed25519_private_key_generate(pointer(identity_private_key), pointer(err))
    handle_error(err)

    identity_service_id = GoslingV3OnionServiceIdPtr()
    gosling_v3_onion_service_id_from_ed25519_private_key(pointer(identity_service_id), identity_private_key, pointer(err))
    handle_error(err)

    context = GoslingContextPtr()
    gosling_context_init(pointer(context), tor_provider, 1120, 401, identity_private_key, pointer(err))
    handle_error(err)

    gosling_context_set_tor_bootstrap_status_received_callback(context, bootstrap_status_c_callback, None, pointer(err))
    handle_error(err)

    gosling_context_set_tor_bootstrap_completed_callback(context, bootstrap_complete_c_callback, None, pointer(err))
    handle_error(err)

    print("begin bootstrap")

    gosling_context_bootstrap_tor(context, pointer(err))
    handle_error(err)

    while not bootstrap_complete:
        gosling_context_poll_events(context, pointer(err))
        handle_error(err)

# The following block ensures that the main function is only executed when the script is run directly
if __name__ == "__main__":
    main()