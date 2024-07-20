# Honk-RPC

Implementation of the [Honk-RPC](https://gosling.technology/honk-rpc-spec.xhtml) remote procedure call protocol.

## Overview

The `honk-rpc` crate is a bare-bones implementation of the `Honk-RPC` protocol. This protocol is heavily inspired by [JSON-RPC](https://www.jsonrpc.org), but uses [BSON](https://bsonspec.org) as the underlying message format to enable more efficient transmission of large binary payloads.

Functionality is defined and implemented in namespace-scoped `ApiSet` objects. A Honk-RPC client/server pair and all the associated communications and request handling is encapsulated in a `Session` object.

For now, communications are presumed to take place over a Rust object implementing both `std::io::Read` and `std::io::Write`. In practice, this is presumed to be a `std::io::TcpStream`.

## ⚠ Unstable ⚠

The `honk-rpc` crate's API and the `Honk-RPC` protocol specification are considered unstable. The `honk-rpc` crate will likely be [changed](https://github.com/blueprint-freespeech/gosling/issues/110) in the future to operate purely on `bson` objects and lave the specifics of the transport layer up to consumers of the crate.
