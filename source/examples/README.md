# Example-Chat

This directory contains a few interoperable implementations of a toy example-chat application. Each implementation demonstrates usage of the Gosling library in a particular programming language. As much as possible, the projects' source-code is organised the same across projects. The final compiled applications should also each have approximately the same user-experience at runtime.

The following implementations are available:
- [example_chat_rs](rust/README.md) - direct usage of the Gosling crate in Rust
- [example_chat_cpp](cpp/README.md) - indrect usage of the Gosing crate using the libcgosling C library in C++

## Overview

The general user-flow for these applications is to connect to the Tor Network, start an identity onion-service, request endpoint onion-services from other peers (or wait for peers to request an endpoint from you), connect to these endpoints, and send+receive new-line delimited ASCII chat messages.

Each of these steps is done manually through various commands using a terminal interface.

For convenience, all of the peer-related commands are in terms of the peer's identity onion-service service-id, even when *actually* interacting with an endpoint onion-service. All of the endpoint onion-service identifiers and keys (ed25519 private keys, v3 onion-service service-id, x25519 client-auth keys) are referenced by the associated peers' identity server onion-service service-id for simplicity.

A 'real' application would also likely expose at most their peer's identity ids through the user-interface. So, a developer would also need to maintain a similar mapping between identity ids (or user-friendly handles) in the front-end and the various keys in the back-end.

## Commands

The `example_chat_cpp` application supports the following commands:

- **`init-context`**:  Launches a tor daemon (which must be present in `$PATH`), boostraps, and initialises the gosling context. After bootstrapping, the identity server can be started, endpoint requests can be made, endpoints can be started and connected to.

    This instance's identity server service-id is also displayed so that the user may share it and allow other peers to request an endpoint.

- **`start-identity`**: Starts the user's identity server. After starting, it will take some time before it is published and can be connected to. Once published, other peers may make a chat request via the **`request-endpoint`** command.

- **`stop-identity`**: Stops your own running identity server. Once stopped, remote peers will not be able to connect and make endpoint requests. Any running endpoint servers remaining running and any ongoing sessions with peers also stay connected.

- **`request-endpoint`**: Attempt to connect to a remote identity server and begin an identity handshake to request credentials for an endpoint server. On success, this peer will be able to connect to the remote peer using these credentials, once the remote peer starts their associated endpoint server.

- **`start-endpoint`**: Starts a peer's own endpoint server whose credentials have been provided to a remote peer. Starting the endpoint server is required for the remote peer to connect to you.

- **`stop-endpoint`**: Stops your own running endpoint server for a particular remote peer. Once stopped, remote peers will not be able to connect and chat, and any ongoing sessions to this particular peer will end.

- **`connect-endpoint`**: Connect to a remote peer's endpoint server whose credentials have been acquired through a previous call to **`request-endpoint`**. After connecting to a peer's endpoint, messages can be sent using the **`chat`** command.

- **`drop-peer`**: Ends a chat session with a remote peer. The session may have been initiated by either you or the remote peer.

- **`list-peers`**: Lists all of the currently connect peers which may be chatted with.

- **`chat`**: Send an ASCII message to a connected peer.
