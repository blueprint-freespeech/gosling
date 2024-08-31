# Usage Guide

#### Morgan <[morgan@torproject.org](mailto:morgan@torproject.org)>

---

**NOTE**: A high-level understanding of the Gosling protocol and participants is presumed. If you are new, you will most likely want to read the [Design Document](design-doc.xhtml) first.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119[^1].

## Overview

This is a guide for using the [`gosling`](../gosling/crates/gosling/index.html) Rust crate. Additional information about consuming Gosling through the `libcgosling` C-FFI can be found in the [libcgosling](#libcgosling) section. The toy applications in the [`/source/examples`](https://github.com/blueprint-freespeech/gosling/tree/main/source/examples) directory provide bare-bones examples for how to interact with both of these libraries.

The primary types in the `gosling` crate are the [`Context`](../gosling/crates/gosling/context/struct.Context.html) and the [`ContextEvent`](../gosling/crates/gosling/context/enum.ContextEvent.html).

A `Context` encapsulates everything about a peer in a Gosling-based peer-to-peer network. It manages the Tor Network connectivity, Gosling handshakes, and other implementation details.

Forward progress is handled via the [`Context::update()`](../gosling/crates/gosling/context/struct.Context.html#method.update) method. This method returns a list of `ContextEvent` objects to be handled by the application. If `Context::update()` is not called, then the internal state-machine will not progress.

The `ContextEvent` objects may be purely informative (e.g. tor logs), or may signal some action needed by the application (e.g. to progress a Gosling handshake).

The general life-cycle of a `Context` object is its initial creation, a request for bootstrap, and repeated calls to `Context::update()`. During this update cycle, the identity server or endpoint servers can be started and stopped, and connections to peers can be made.

## Connecting to the Tor Network

A `Context` uses a [`TorProvder`](../gosling/crates/tor_interface/tor_provider/trait.TorProvider.html) object to handle Tor Network connectivity. Currently, only a wrapper around the 'little-t' tor daemon is fully supported via the [`LegacyTorClient`](../gosling/crates/tor_interface/legacy_tor_client/struct.LegacyTorClient.html) type.

Arti support is under development.

### Legacy Tor Client

The `LegacyTorClient` has two modes of operation, which can be configured using a [`LegacyTorClientConfig`](../gosling/crates/tor_interface/legacy_tor_client/enum.LegacyTorClientConfig.html) enum. To construct a Gosling context, a `TorProvider` impl

#### Bundled Tor

A 'bundled' tor is a new instance of the tor daemon which is wholly owned and configured by its parent process (the Gosling-using application in this instance). As such, there are various configuration options available.

This is the typical way tor-using applications (e.g. Tor Browser, Ricochet-Refresh, cwtch, OnionShare, etc) access the tor network. These applications also build and package their own tor daemon executable, but that is beyond the scope of Gosling.

#### System Tor

A 'system' tor is a global instance which is used and shared by multiple applications, or even the entire system (e.g. in the Tails operating system).

## Identity+Endpoint Server and Client Usage

For a detailed description of the underlying Gosling protocol and stages of the identity and endpoint handshakes, please see the [Gosling Protocol specification](gosling-spec.xhtml)

### Hosting an identity server

All of the identity server functions have the form `Context::identity_server_*`.

A Gosling peer's identity server can be started and stopped using the [`Context::identity_server_start()`](../gosling/crates/gosling/context/struct.Context.html#method.identity_server_start) and [`Context::identity_server_stop()`](../gosling/crates/gosling/context/struct.Context.html#method.identity_server_stop) methods.

Once an identity server is running and published, the Gosling consumer will receive a [`ContextEvent::IdentityServerPublished`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.IdentityServerPublished) event. After this event is received, it is possible for remote peers to connect and begin the identity handshake to request endpoint credentials.

The general flow of an identity server handshake follows:

- Receive [`ContextEvent::IdentityServerHandshakeStarted`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.IdentityServerHandshakeStarted) - Signals that a peer has connected to identity server, but not yet started identity handshake. A `HandshakeHandle` is provided so the Gosling consumer can associate future events with each other.
- Receive [`ContextEvent::IdentityServerEndpointRequestReceived`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.IdentityServerEndpointRequestReceived) - Signals a connected peer has started the identity handshake. To progress this handshake, the Gosling consumer must invoke the [`Context::identity_server_handle_endpoint_request_received()`](../gosling/crates/gosling/context/struct.Context.html#method.identity_server_handle_endpoint_request_received) method.

    The purpose of this method is to indicate to the handshake machinery whether the connecting peer is permitted to to request an endpoint (based on their provided service-id), whether the endpoint the connecting peer is requesting is valid, and finally to construct and send an endpoint challenge.

    This endpoint challenge is an application-specific BSON document which is sent to the requesting client. It is up to the Gosling consumer to determine if/how this challenge is used, responded to, and verified.

- Receive [`ContextEvent::IdentityServerChallengeResponseReceived`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.IdentityServerChallengeResponseReceived) - Signals that a peer has received the server's endpoint challenge, and has crafted a response. To progress this handshake, the Gosling consumer must invoke the [`Context::identity_server_handle_challenge_response_received()`](../gosling/crates/gosling/context/struct.Context.html#method.identity_server_handle_challenge_response_received) method.

    The purpose of this method is to verify the identity client's crafted endpoint challenge-response object, and determine whether the handshake should continue successfully, or if the endpoint request should be rejected.

- Receive [`ContextEvent::IdentityServerHandshakeCompleted`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.IdentityServerHandshakeCompleted) - Signals that this identity handshake successfully completed and a configuration for an endpoint server has been negotiated and delivered to the connected peer. This event contains several members which must be saved in-order to start the endpoint-server for this peer.

    **OR**

- Receive [`ContextEvent::IdentityServerHandshakeRejected`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.IdentityServerHandshakeRejected) - Signals that the identity handshake successfully completed, but due to at least one of the provided reasons, the client's request was rejected.

It should also be noted that at any point in the handshake the server may receive a [`ContextEvent::IdentityServerHandshakeFailed`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.IdentityServerHandshakeFailed) containing reason for failure.

### Requesting an endpoint from an identity server

All of the identity client functions have the form `Context::identity_client_*`.

A Gosling peer can initiate an endpoint request with the [`Context::identity_client_begin_handshake()`](../gosling/crates/gosling/context/struct.Context.html#method.identity_client_begin_handshake) method.

The general flow of an identity client handshake follows:

- Receive [`ContextEvent::IdentityClientChallengeReceived`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.IdentityClientChallengeReceived) - Signals that the connected identity server has sent the client an endpoint challenge and the client must now construct and send an endpoint challenge-response. To progress this handshake, the Gosling consumer must invoke the [`Context::identity_client_handle_challenge_received()`](../gosling/crates/gosling/context/struct.Context.html#method.identity_client_handle_challenge_received) method.

    The purpose of this method is indicate to the handshake machinery what response to send in reply to the endpoint challenge.

    The endpoint challenge-response is an application-specific BSON document which is sent to and verified by the identity server. The identity server's verification method is also application-specific. If the server rejects the endpoint challenge-response the endpoint request will be rejected.

- Receive [`ContextEvent::IdentityClientHandshakeCompleted`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.IdentityClientHandshakeCompleted) - Signals that this identity handshake successfully completed and credentials for an endpoint server have been negotiated and delivered to this peer. This event contains several members which must be saved in-order to connect to the remote peer's endpoint server.

    **NOTE** The remote peer will still need to start their endpoint server before this peer can connect,

It should also be noted that at any point in the handshake the client may receive a [`ContextEvent::IdentityClientHandshakeFailed`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.IdentityClientHandshakeFailed) containing reason for failure.

At any point an identity client handshake can be aborted using the [`Context::identity_client_abort_handshake()`](../gosling/crates/gosling/context/struct.Context.html#method.identity_client_abort_handshake) method.

### Hosting an endpoint server

All of the endpoint server functions have the form `Context::endpoint_server_*`.

A Gosling peer's endpoint server can be started and stopped using the [`Context::endpoint_server_start()`](../gosling/crates/gosling/context/struct.Context.html#method.endpoint_server_start) and [`Context::endpoint_server_stop()`](../gosling/crates/gosling/context/struct.Context.html#method.endpoint_server_stop) methods.

<!--Once an endpoint server is running and published, the Gosling consumer will receive a [`ContextEvent::IdentityServerPublished`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.EndpointServerPublished) event. After this event is received, it is possible for remote peers to connect and begin the endpoint handshake to request a channel.-->

The general of an endpoint server handshake follows:

- Receive [`ContextEvent::EndpointServerHandshakeStarted`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.EndpointServerHandshakeStarted) - Signals that a peer has connected to endpoint server, but not yet started endpoint handshake. A `HandshakeHandle` is provided so the Gosling consumer can associate future events with each other.
- Receive [`ContextEvent::EndpointServerChannelRequestReceived`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.EndpointServerChannelRequestReceived) - Signals a connected peer has started the endpoint handshake. To progress this handshake, the Gosling consumer must invoke the [`Context::endpoint_server_handle_channel_request_received()`](../gosling/crates/gosling/context/struct.Context.html#method.endpoint_server_handle_channel_request_received) method.

    The purpose of this method is to indicate to the handshake machinery whether the connecting peer is permitted to connect to the provided channel.

- Receive [`ContextEvent::EndpointServerHandshakeCompleted`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.EndpointServerHandshakeCompleted) - Signals that this endpoint handshake successfully completed and a channel has been opened to the connected peer.  This event includes a `TcpStream` which the Gosling consumer may now use for application-specific communications with the connected peer.

    **OR**

- Receive [`ContextEvent::EndpointServerHandshakeRejected`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.EndpointServerHandshakeRejected) - Signals that the endpoint handshake successfully completed, but due to at least one of the provided reasons, the client's request was rejected.

It should also be noted that at any point in the handshake the server may receive a [`ContextEvent::EndpointServerHandshakeFailed`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.EndpointServerHandshakeRejected) containing reason for failure.

### Requesting a channel from an endpoint server

All of the endpoint client functions have the form `Context::endpoint_client_*`.

A Gosling peer can initiate a channel request with the [`Context::endpoint_client_begin_handshake()`](../gosling/crates/gosling/context/struct.Context.html#method.endpoint_client_begin_handshake) method.

The general flow of an endpoint client handshake follows:

- Receive [`ContextEvent::EndpointClientHandshakeCompleted`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.EndpointClientHandshakeCompleted) - Signals that this endpoint handshake successfully completed and a channel has been oepend to the connected peer. This event includes a `TcpStream` which the Gosling consumer may now use for application-specific communications with the connected peer.

It should also be noted that at any point in the handshake the client may receive a [`ContextEvent::EndpointClientHandshakeFailed`](../gosling/crates/gosling/context/enum.ContextEvent.html#variant.EndpointClientHandshakeFailed) containing reason for failure.

At any point an endpoint client handshake can be aborted using the [`Context::endpoint_client_abort_handshake()`](../gosling/crates/gosling/context/struct.Context.html#method.endpoint_client_abort_handshake) method.

## Cryptographic Types

The Gosling protocol and crate builds upon Tor and its various cryptographic types. These types are outlined and their purposes within Gosling are described here. The implementation for these types lives in the [`tor-interface`](../gosling/crates/tor_interface/index.html) crate.

Consumers of Gosling will need to handle safely using and storing these keys.

### ed25519 private key

This type of cryptographic key is required to publish an onion-service.

In the Gosling protocol, a peer's long-term identity is derived from a securely-generated, secret ed25519 private key. This key is used to publish a peer's identity server and as part of identity client authentication process.

A peer will also have an ed25519 private key for each of the remote peers which have successfully requested endpoint server credentials from it. These keys are used to publish endpoint servers for these peers to connect to.

Gosling also uses this type of key internally in the protocol to sign messages to prove ownership of this key, but consumers of the `gosling` crate do not need to worry about this.

Consumers of Gosling will use this type when starting identity or endpoint servers. They will also need to securely create an ed25519 private key when creating an intial identity for a peer using the [`Ed25519PrivateKey::generate()`](../gosling/crates/tor_interface/tor_crypto/struct.Ed25519PrivateKey.html#method.generate) method.

The associated `tor-interface` type is the [`Ed25519PrivateKey`](../gosling/crates/tor_interface/tor_crypto/struct.Ed25519PrivateKey.html).

#### ⚠ Warning ⚠

An ed25519 private key MUST never be shared or distributed. It is strongly RECOMMENDED that this type of key be encrypted when stored on disk.

If an adversary were to acquire another Gosling peer's ed25519 private key, then they would be able to impersonate that peer.

### ed25519 public key

This type of cryptographic key is the public-key counterpart to the ed25119 private key. This type is used internally in the Gosling handshakes for verifying cryptographic proofs signed with a counter-parts ed25519 private key.

Consumers of Gosling will not use this type.

The associated `tor-interface` type is the [`Ed25519PublicKey`](../gosling/crates/tor_interface/tor_crypto/struct.Ed25519PublicKey.html).

### v3 onion-service service-id

This type is fundamentally an alternate (and equivalent) representation of an ed25519 public key.

A v3 onion-service service-id is in some ways similar to a domain name, as it is the primary type needed by a Tor client to connect to a v3 onion-service.

In Gosling there are two types of v3 onion-service service-ids:

- identity server service-ids
- endpoint server service-ids

As described in the design document, a peer has a single identity server. This server's v3 onion-service service-id serves as a peer's long-term identity.

A peer also has (potentially) many associated endpoint server service-ids, one for each of the remote peers which it has requested endpoint credentials for. The endpoint server service-id is *one* of the credentials required to connect to an authorised endpoint server.

Consumers of Gosling will encounter this type when attempting to connect to an identity server or endpoint server, and after successfully completing an endpoint request.

The associated `tor-interface` type is the [`V3OnionServiceId`](../gosling/crates/tor_interface/tor_crypto/struct.V3OnionServiceId.html).

#### ⚠ Warning ⚠

An identity server's v3 onion-service service-id *has* to be shared in-order for the peer to complete endpoint requests.

Any adversary which knows a peer's identity server v3 onion-service id will be able to secretly collect the online/offline status metadata about that identity server. However, it should be noted that the identity server does not need to be online to connect to authorised peers, as they connect through secret endpoint servers.

An endpoint server's v3 onion-service service-id MUST NOT be shared.

If an adversary were to learn an endpoint server's v3 onion-service service-id, then they would also be able to secretly collect the online/offline status metadata about that endpoint server.

### x25519 private key

This type is used by Gosling as part of v3 onion-service client authorisation. In Gosling, endpoint server's v3 onion-service descriptors are encrypted using an x25519 public key, such that only the associated x25519 private key holder can read them. The x25519 private key holder is therefore the only party which can connect to their associated endpoint server.

Consumers of Gosling will encounter this type after successfully completing an endpoint request. It will need to be saved and used whenever the peer connects to the associated endpoint server.

Consumers of Gosling do not need to worry about creating x25519 private keys, as the Gosling `Context` takes care of that.

The associated `tor-interface` type is the [`X25519PrivateKey`](../gosling/crates/tor_interface/tor_crypto/struct.X25519PrivateKey.html).

#### ⚠ Warning ⚠

An x25519 private key MUST never be shared or distributed. It is strongly RECOMMENDED that this type of key be encrypted when stored on disk. It is also strongly RECOMMENDED that x25519 key-pairs not be re-used across unrelated v3 onion-services.

If an adversary were to acquire the x25519 private key used to encrypt the onion-service descriptors for a particular onion-service, then they would be able connect to that onion-service (presuming the adversary *also* had the associated onion-service service-id).

If a peer were to re-use an x25519 key-pair for client authorisation, then the multiple identities re-using said key-pair would be linked or associated if an adversary were to discover the key re-use.

### x25519 public key

This type of cryptographic key is the public-key counterpart to the x25119 private key. This type is used by Gosling as part of v3 onion-service client authorisation. In Gosling, an endpoint server needs the endpoint client's x25519 public key to encrypt the v3 onion-service descriptors. This x25519 public key is sent by the identity client when requesting an endpoint server.

Consumers of Gosling will encounter this type after successfully completing an endpoint request. It will need to be saved and used whenever the peer starts the associated endpoint server.

The associated `tor-interface` type is the [`X25519PublicKey`](../gosling/crates/tor_interface/tor_crypto/struct.X25519PublicKey.html).

#### ⚠ Warning ⚠

It is strongly RECOMMENDED that x25519 key-pairs not be re-used across unrelated v3 onion-services.

If a peer were to re-use an x25519 key-pair for client authorisation, then the multiple identities re-using said key-pair would be linked or associated if an adversary were to discover the key re-use.

## libcgosling

The `libcgosling` library wraps the `gosling` crate in a C-FFI. It can be built as either a static or shared library. All non-Rust (e.g. C/C++, Java, Python, etc) bindings to the `gosling` crate ultimately goes through `libcgosling`.

Most of the various (required) Rust types used in the `gosling` and `tor-interface` crates have equivalent C types. In general, a Rust type `Foo` maps to a C struct `gosling_foo_t`.

One major exception to this is the `ContextEvent` type. Rather than directly exposing `Context::update()` and returning a list of `gosling_context_event_t`s, `libcgosling` instead depends on a callback mechanism inspired by the GLFW library. The `libcgosling` consumer must register callbacks to handle events which are called during the execution of the `gosling_context_poll_events()` function.

[^1]: RFC 2119 [https://www.rfc-editor.org/rfc/rfc2119](https://www.rfc-editor.org/rfc/rfc2119)
