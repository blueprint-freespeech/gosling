# Gosling Protocol v0.0.1

The Gosling protocol allows for the creation of Tor onion-service based peer-to-peer (onion-to-onion) applications. Initial inspiration came from the Ricochet instant messenger's peer-to-peer onion service architecture. Improvements have been made and some privacy issues have been addressed and fixed.

It is assumed that the reader is familiar with onion routing[^1], Tor[^2], and onion services (aka hidden services)[^3]. For the purposes of this document, Ricochet and Ricochet Refresh are used interchangeably when referring to properties or guarantees common to both applications.

## Overview

The purpose of Gosling is to standardize a privacy-preserving architecture for peer-to-peer applications on the Tor network between **nodes**.

- **Node** - A peer in a service-specific Gosling peer-to-peer network.

Each node has three components: a **client**, an **introduction server**, and at least one **endpoint server**. A node can simultaneously have all three components running at the same time on a single computer, or each component could be split across multiple real computers on the tor network. A node is primarily identified by the onion-service id of its introduction server.

  - **Client**  - A **node's** component making an outgoing connection to another *node*
  - **Introduction Server** - A **node's** onion-service which listens for requests coming from **clients** who have never connected before that wish to become 'friends'. The **introduction server** and a **client** perform a handshake and exchange information required to reach the **node's** **endpoint server(s)**. An **introduction server** may serve multiple endpoint applications.
  - **Endpoint Server** - A **node's** onion-service(s) which listen for connections coming from **clients**. The route to this server is protected with onion service client authentication[^4], so only trusted Gosling **clients** are able to connect. A **node** may have multiple simultaneous **endpoint servers** (each with a different onion-service id), as tor only supports a finite number of authenticated clients per onion service.

  For some applications, it may make sense to provide each authenticated client their own onion service while for others, it may make more sense to batch clients together on a single onion service.

For the rest of this document we'll use instant messenger term **contact**.

- **Contact** - a Gosling **node** that has successfully completed the authentication handshake with another **node's** **introduction server** and is allowed to connect to said **node's** **endpoint server**.

### Background

The above architecture is informed by our experience with and the limitations of Ricochet's architecture.

Ricochet only uses a single onion service. The service id of this onion service is used as your Ricochet ID for connecting to and chatting with other Ricochet users.

This simple architecture has some drawbacks:

#### Poor visibility control to contacts

Though not supported by the Ricochet front-end, in theory if one wanted to appear 'offline' while still being able to chat to your friends, they could disable their onion service and only make outgoing connections their friends. However, this must be done for *all* friends at once.

**Gosling's Solution:** Gosling allows finer-grained visibility controls:

- If a **node** does not wish to receive new contact requests, they can simply not run their **introduction server**. Your existing allowed contacts are still be able to connect to the user's **endpoint server(s)** which are not publicly advertised.

- If a user wishes to appear offline to *all* **contacts**, they can disable their **endpoint server(s)**. A user may still selectively connect to their **contacts** by acting solely as a **client**.

#### Cyber-stalking

As a side-effect of Ricochet's usage of a single onion service and the poor visibility controls, anybody who knows
your Ricochet ID can secretly track a your online status. This is because the onion service is necessarily public to receive new friend requests.

All a malicious actor needs to do is attempt to open a connection to the target's Ricochet onion service.
Periodically pinging a Ricochet user's advertised service id will give a nearly perfect profile for when the are and are not using Ricochet.

This has some serious privacy implications. If a user uses Ricochet as they would any other IM application (always on in the background), this will give a perfect profile of the target's computer+internet usage.

**Gosling's Solution:** Because of the above described visibility controls, users can control when they are visible to to unauthorized users by selectively running their **introduction server**.

One could also imagine applications which forego using the **introduction server** entirely, and instead allow users to exchange client authorization keys and endpoint servers offline (via QR codes for example).

**Note:** A Gosling node may still be cyber-stalked by a *previously* authenticated user if the node is configured to group together multiple **clients** in a single **endpoint server** (rather than handing out a unique **endpoint server** to each client).

## Gosling Handshakes

**Nodes** communicate with each other using a BSON-based RPC protocol[^5]. As described above, each **node** has two server components: an **introduction server** and at least one **endpoint server**.

A **client** initially connects to an **introduction server** to complete the introduction handshake and exchange credentials to access a **node's** **endpoint server**.

After a **client** connects to and successfully authenticates with an **endpoint server**, we exit the Gosling handshake state machine and the underlying TCP stream is handed off to the endpoint application.

All types used in these RPC calls are BSON[^6] types.

Calling these functions out of order must result in an error being returned and the connection being closed.

### Introduction Server



#### Sequence Diagram

![introduction handshake](introduction_handshake.svg)

The **client** may optionally add the **introduction server's** onion service id to its own allow list to short-cut the contact request when the client and server roles are reversed.

#### Introduction Server RPC API

```c++
namespace gosling_introduction {
  // Begins an introduction handshake session.
  //
  // params:
  // - string version: the requested version of the Gosling protocol to use
  // - string client_identity: the client's v3 onion service id
  //
  // return: a document object with the following members on success, otherwise
  // an error is raised
  // - binary server_cookie: 32 byte cookie randomly generated by the server
  begin_handshake(string version,
                  string client_identity) -> document

  // Submits the client proof to the server for verification. If this function
  // is called before the handshake has begun, an error is raised.
  //
  // parameters:
  // - binary client_cookie: 32 byte cookie randomly generated by the client
  // - binary client_proof: 64 byte ed25519 proof signature
  //
  // return: an empty document on success, otherwise an error is raised.
  send_client_proof(binary client_cookie,
                    binary client_proof) -> document;


  // Request the challenge for the given endpoint service. If this function
  // is called before the client proof has ben verified, an error is raised.
  //
  // parameters:
  // - string endpoint: the application endpoint we wish to access
  //
  // return: a document object containing any data the client needs to
  // calculate the endpoint challenge response. The contents of this document
  // are deliberately unspecified and are application-specific. However, if
  // this document is empty it is assumed the requestor has already been
  // granted access previously and may send an empty challenge response.
  request_endpoint_challenge(string endpoint) -> document;

  // Send the challenge response for the previously requested endpoint. If
  // this function is called before the endpoint challenge has been requested,
  // an error is raised.
  //
  // parameters:
  // - document challenge_response: the calculated challenge response to the
  //   previous endpoint challenge request. The contents of this document are
  //   deliberately unspecified and are application-specific. If the endpoint
  //   challenge object was empty, this response object may also be empty.
  // - binary client_authentication_key: a 32-byte x25519 public key used to encrypt
  //   the onion service descriptor
  //
  // return: on success, a string containing the v3 onion service id of the
  // endpoint server (otherwise an error is raised); the endpoint's onion
  // service descriptor will be encrypted with the client's provided client
  // authentication key
  send_endpoint_challenge_response(document challenge_response,
                                   binary client_authentication_key) -> string;
}
```

### Endpoint Server

A **client** may connect an **endpoint server** multiple times by specifying different channel names. For example, a chat application may have concurrent 'messaging' and 'file transfer' channels.

#### Sequence Diagram

![endpoint handshake](endpoint_handshake.svg)

#### Endpoint Server RPC API

```c++
namespace gosling_endpoint {
  // Begins an endpoint handshake session.
  //
  // params:
  // - string version: the requested version of the Gosling protocol to use
  // - string client_identity: the client's v3 onion service id
  //
  // return: a document object with the following members on success, otherwise
  // an error is raised
  // - binary server_cookie: 32 byte cookie randomly generated by the server
  begin_handshake(string version,
                  string client_identity) -> document

  // Submits the client proof to the server for verification. If this function
  // is called before the handshake session has begun, an error raisd.
  //
  // parameters:
  // - binary client_cookie: 32 byte cookie randomly generated by the client
  // - binary client_proof: 64 byte e25519 proof signature
  //
  // return: an empty document on success, otherwise an error is raised
  send_client_proof(binary client_cookie,
                    binary client_proof) -> document;

  // Opens an endpoint session on this connection with the given channel
  // name. If the client already has an open endpoint session with the
  // given channel name, the existing session is terminated. If this function
  // is called before the client proof has been sent, then an error is raised.
  //
  // parameters:
  // - string endpoint: the endpoint service we wish to connect to
  // - string channel: the channel on that endpoint to connect to; if this
  //   client is already connected to the requested channel on this endpoint
  //   the old channel connection is  closed.
  //
  // return: an empty document on success, otherwise an error is raised
  open_endpoint(string endpoint, string channel) -> document;
}
```

### Proof Calculation and Verification

The proof signed by client is calculated as:

```
proof = SHA256(domain_separator +
               client_onion_id  +
               server_onion_id  +
               client_cookie    +
               server_cookie)
```

The **'+'** operator here indicates concatenation. The parameters are defined as:

- **domain_separator** : an ASCII string (without a null terminator); for the introduction handshake, this string is "gosling-introduction"; for the endpoint handshake, this string is "gosling-endpoint"
- **client_onion_id** : an ASCII string (without a null terminator); the base-32 encoded onion service id (without the ".onion" suffix) of the connecting client's introduction server
- **server_onion_id** : an ASCII string (without a null terminator); the base-32 encoded onion service id (without the ".onion" suffix) of the connected server (ie: when connected to the introduction server, the introduction server's onion service id is used; when connected to an endpoint server, that endpoint server's onion service id is used)
- **client_cookie** : cryptographically-randomly generated 32 byte client cookie
- **server_cookie** : cryptographically-randomly generated 32 byte server cookie

A **client** authenticates itself to a gosling server (both **introduction** or **endpoint**) by signing the above proof with the associated ed25519 private key of its own **introduction server**.

---
[^1]: see [Onion routing](https://en.wikipedia.org/wiki/Onion_routing)

[^2]: see [About Tor](https://support.torproject.org/about/)

[^3]: see [Onion Sevices](https://support.torproject.org/onionservices/)

[^4]: onion service client authentication: https://community.torproject.org/onion-services/advanced/client-auth/

[^5]: see [rpc.md](./rpc.md)

[^6]: see [BSON spec](https://bsonspec.org/spec.html)
