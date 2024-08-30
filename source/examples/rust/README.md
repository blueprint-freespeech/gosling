# example_chat_rust

This is the Rust implementation of the example chat application, using Gosling and [crossterm](https://github.com/crossterm-rs/crossterm) for the terminal interface. All gosling events are handled via `ContextEvent` enums returned from the `Context::update()` method in `main.rs`.

## Source walkthrough

- **`main.rs`**: Entry point to the application; initialisation logic, terminal updates, gosling update+event handling, and peer connection handling.

- **`globals.rs`**: Definition of application globals.

- **`terminal.rs`**: A simple crossterm-based terminal user-interface. Handles signalling command requests, displaying output, and handling user input.

- **`commands.rs`**: The definitions for all of the functions implementing the terminal commands.
