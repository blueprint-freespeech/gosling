# example_chat_cpp

This is the C++ implementation of the example chat application, using libcgosling and [ncurses](https://invisible-island.net/ncurses/announce.html) for the terminal interface. All gosling-related events are handled via a function-pointer callback registration system.

## Source walkthrough

- **`precomp.cpp/.hpp`**: The project's pre-compiled header.

- **`main.cpp`**: Entry point to the application; initialisation logic, terminal and gosling updates, and peer connection handling.

- **`globals.hpp`**: Declarations and definitions for application global types and data.

- **`terminal.cpp/.hpp`**: A simple ncurses-based terminal user-interface. Handles registration and execution of commands, displaying output, and handling user input.

- **`commands.cpp/.hpp`**: The declaration and definitions for all of the functions implementing the terminal commands.

- **`callbacks.hpp`**: Entry-point for registering all the various `gosling_callback_*` function pointers with the global `gosling_context`.

- **`identity_client_callbacks.cpp`**: Implementation of all of the callbacks required to complete an identity handshake as a client. This is the minimum set of callbacks required to complete an identity handshake initiated with the `gosling_context_begin_identity_handshake()` function.

- **`identity_server_callbacks.cpp`**: Implementation of all of the callbacks required to complete an identity handshake as a server.

- **`endpoint_client_callbacks.cpp`**: Implementation of all of the callbacks required to complete an endpoint handshake as a client. This is the minimum set of callbacks required to complete an endpoint handshake initiated with the `gosling_context_begin_endpoint_handshake()` function.

- **`endpoint_server_callbacks.cpp`**: Implementation of all of the callbacks required to complete an endpoint handshake as a server.
