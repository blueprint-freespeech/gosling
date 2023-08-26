# Gosling Protocol v0.0.0.1

The Gosling protocol allows for the creation of Tor onion-service based peer-to-peer (onion-to-onion) applications. Initial inspiration came from the Ricochet instant messenger's peer-to-peer onion service architecture. Improvements have been made and some privacy issues have been addressed and fixed.

It is assumed that the reader is familiar with onion routing[^1], Tor[^2], and onion services (aka hidden services)[^3]. For the purposes of this document, Ricochet and Ricochet Refresh are used interchangeably when referring to properties or guarantees common to both applications.

## Overview

The purpose of Gosling is to standardize a privacy-preserving architecture for peer-to-peer applications on the Tor network between **nodes**.

- **Node** - A peer in a service-specific Gosling peer-to-peer network.

Each node has three components: a **client**, an **identity server**, and at least one **endpoint server**. A node can simultaneously have all three components running at the same time on a single computer, or each component could be split across multiple real computers on the tor network. A node is primarily identified by the onion-service id of its identity server.

  - **Client**  - A **node's** component making an outgoing connection to another **node**
  - **Identity Server** - A **node's** onion-service which listens for requests coming from **clients** who have never connected before that wish to become 'friends'. The **identity server** and a **client** perform a handshake and exchange information required to reach the **node's** **endpoint server(s)**.
  - **Endpoint Server** - A **node's** onion-service(s) which listen for connections coming from **clients**. The route to this server is protected with onion service client authorization[^4], so only trusted Gosling **clients** are able to connect. A **node** may have multiple simultaneous **endpoint servers** (each with a different onion-service id), as tor only supports a finite number of authorized clients per onion service.

For the rest of this document we'll also use instant messenger term **contact**.

  - **Contact** - a Gosling **node** that has successfully completed the authentication handshake with another **node's** **identity server** and is allowed to connect to said **node's** **endpoint server**.

The protocol supports a single **identity server** serving multiple endpoint applications. For example, an application ecosystem may want a single identifier for **nodes** which are part of both a peer-to-peer instant messaging and a file sharing network. This type of arrangement is supported by having each different application using a different endpoint name.

The protocol *technically* supports a single **endpoint server** serving multiple **clients** concurrently. The **identity server** could simply always return the same **endpoint server** service id after a successful introductory handshake. However, the reference implementation here does not implement this architecture for the following reasons:

 - There is currently no way to update a running tor onion-service's set of client authorization keys (used to encrypt onion-service's onion descriptor) without restarting the onion-service. This means we cannot add a new authorized **client** nor revoke the access of a previously authorized **client** to the **endpoint server** without severing all existing **endpoint server** sessions.
 - **Clients** would be able to determine the online/offline status of **endpoint servers** after their access has been revoked. This is because tor does not provide a way to have a 'hidden' onion-service (even when using client authorization). All of the existing authorized **clients** with access to a common **endpoint server** would need to be migrated to a new **endpoint server** if any of their access were to be revoked. This migration would also necessarily sever any existing **endpoint server** sessions. This issue is being tracked upstream in [torspec#119](https://gitlab.torproject.org/tpo/core/torspec/-/issues/119).
 - **Endpoint servers** make use of client authorization as an extra layer of security. An onion-service must upload an encrypted copy of its onion descriptor for each of its authorized clients to the tor-network. The maximum number of authorized clients an individual onion-service may have is not precisely defined or documented, but is estimated to be on the order of about a thousand clients. This is a practical limitation on the number of **clients** an individual **endpoint server** can have.

Due to the above considerations, the reference Gosling implementation will only ever assign one **client** per **endpoint server**.

### Background

The above architecture is informed by our experience with and the limitations of Ricochet's architecture.

Ricochet only uses a single onion service. The service id of this onion service is used as your Ricochet ID for connecting to and chatting with other Ricochet users.

This simple architecture has some drawbacks:

#### Poor visibility control to contacts

Though not supported by the Ricochet front-end, in theory if one wanted to appear 'offline' while still being able to chat to your friends, they could disable their onion service and only make outgoing connections their friends. However, this must be done for *all* friends at once.

**Gosling's Solution:** Gosling allows finer-grained visibility controls:

- If a **node** does not wish to receive new contact requests, they can simply not run their **identity server**. Your existing allowed contacts are still be able to connect to the user's **endpoint server(s)** which are not publicly advertised.

- If a user wishes to appear offline to *all* **contacts**, they can disable their **endpoint server(s)**. A user may still selectively connect to their **contacts** by acting solely as a **client**.

#### Cyber-stalking

As a side-effect of Ricochet's usage of a single onion service and the poor visibility controls, anybody who knows
your Ricochet ID can secretly track a your online status. This is because the onion service is necessarily public to receive new friend requests.

All a malicious actor needs to do is attempt to open a connection to the target's Ricochet onion service.
Periodically pinging a Ricochet user's advertised service id will give a nearly perfect profile for when the are and are not using Ricochet.

This has some serious privacy implications. If a user uses Ricochet as they would any other IM application (always on in the background), this will give a perfect profile of the target's computer+internet usage.

**Gosling's Solution:** Because of the above described visibility controls, users can control when they are visible to to unauthorized users by selectively running their **identity server**.

One could also imagine applications which forego using the **identity server** entirely, and instead allow users to exchange client authorization keys and endpoint servers offline (via QR codes for example).

**Note:** A Gosling node may still be cyber-stalked by a *previously* authenticated user if the node is configured to group together multiple **clients** in a single **endpoint server** (rather than handing out a unique **endpoint server** to each client).

## Gosling Handshakes

**Nodes** communicate with each other using a BSON-based RPC protocol[^5]. As described above, each **node** has two server components: an **identity server** and at least one **endpoint server**.

A **client** initially connects to an **identity server** to complete the identity handshake. The purpose of this handshake is to prove to the **identity server** that the connecting **client** controls all of the keys they claim to, and (if successful) to exchange credentials the **client** needs to access a **identity server's** associated **endpoint server**.

After a **client** connects to and successfully authenticates with an **endpoint server**, we exit the Gosling handshake state machine and the underlying TCP stream is handed off to the endpoint application.

All types used in these RPC calls are BSON[^6] types. Any type marked `binary` is specifically the 'Generic binary subtype' (`\x00`). Any type marked `document` is specifically a BSON document (an encoded set of key/value pairs).

Calling these functions out of order must result in an error being returned and the connection being closed.

### Identity Server

#### Sequence Diagram

![](images/identity_handshake.svg "Identity Handshake Sequence Diagram")

#### Identity Server RPC API

```c++
namespace gosling_identity {
  // Begins an identity handshake session.
  //
  // Parameters:
  // - string version : the requested version of the Gosling protocol to use
  // - string client_identity : the client's identity server v3 onion service id
  // - string endpoint : the application endpoint the client wants to access; this
  //   value must be encodable as ASCII.
  //
  // return : on success, a document object with the following members
  // - binary server_cookie : 32 byte cookie randomly generated by the server
  // - document endpoint_challenge : a document object containing any data the
  //   client needs to calculate the endpoint challenge response. The contents
  //   of this document are deliberately unspecified and are application-specific.
  //
  // An error is raised if an invalid version is provided.
  begin_handshake(string version,
                  string client_identity,
                  string endpoint) -> document

  // Submits the client proofs and the challenge response for server verification. If
  // this function is called before begin_handshake() an error is returned.
  //
  // Parameters:
  // - binary client_cookie : 32-byte cookie randomly generated by the client
  // - binary client_identity_proof_signature : 64-byte ed25519 signature of the
  //   client proof, signed with the ed25519 private key used to generate the
  //   client's v3 onion service id (see 'Client Identity Proof Calculation and
  //   Verification')
  // - binary client_authorization_key : 32-byte x25519 public key to be used to encrypt
  //   the endpoint onion service descriptor
  // - bool client_authorization_key_signbit : the signbit of the ed25519 public key to be
  //   derived from the provided x25519 public key; true => 1, false => 0
  // - binary client_authorization_signature : 64-byte ed25519 signature of the client's
  //   provided v3 onion service id, signed with the ed25519 private key derived
  //   from the private x25519 key associated with the provided public x25519
  //   'client_authorization_key' (see 'Client Authorization Signature Generation
  //   and Verification')
  // - document challenge_response : the calculated challenge response to the
  //   previous endpoint challenge request. The contents of this document are
  //   deliberately unspecified and are application-specific.
  //
  // return : on success, a string containing the v3 onion service id of the
  // endpoint server (otherwise an error is raised); the endpoint's onion
  // service descriptor will be encrypted with the provided client authorization key
  //
  // An error is raised if any of the associated checks or signature verifications fail
  send_response(binary client_cookie,
                binary client_identity_proof_signature,
                binary client_authorization_key,
                bool client_authorization_key_signbit,
                binary client_authorization_signature,
                document challenge_response) -> string;
}
```

### Endpoint Server

A **client** may connect an **endpoint server** multiple times by specifying different channel names. For example, a chat application may have concurrent 'messaging' and 'file transfer' channels.

#### Sequence Diagram

![](images/endpoint_handshake.svg "Endpoint handshake sequence diagram")

#### Endpoint Server RPC API

```c++
namespace gosling_endpoint {
  // Begins an identity handshake session.
  //
  // Parameters:
  // - string version : the requested version of the Gosling protocol to use
  // - string client_identity : the client's identity server v3 onion service id
  // - string channel : the application channel the client wants to open; this
  //   value must be encodable as ASCII.
  //
  // return : on success, a document object with the following members
  // - binary server_cookie: 32 byte cookie randomly generated by the server
  //
  // An error is raised if an invalid version is provided.
  begin_handshake(string version,
                  string client_identity,
                  string channel) -> document

  // Submits the client proof for server verification. If this function is called
  // before begin_handshake() an error is returned.
  //
  // Parameters:
  // - binary client_cookie : 32-byte cookie randomly generated by the client
  // - binary client_identity_proof_signature : 64-byte ed25519 signature of the
  //   client proof, signed with the ed25519 private key used to generate the
  //   client's v3 onion service id (see 'Client Identity Proof Calculation and
  //   Verification')
  //
  // return : on success, returns an empty document
  //
  // An error is raised if any of the associated checks or signature verifications fail
  send_response(binary client_cookie,
                binary client_identity_proof_signature) -> document;
}
```

### Client Identity Proof Calculation and Verification

The proof signed by client is calculated as:

```
proof = domain_separator  +
        request           +
        client_service_id +
        server_service_id +
        hex_client_cookie +
        hex_server_cookie
```

The `+` operator here indicates concatenation with a null byte in-between. For example, `"a" + "b" + "c"` would be encoded as the byte array `['a', \x00, 'b', \x00, 'c']`.

Each of the parameters  must be representable as an ASCII string and do *not* include an implicit null-terminator. The parameters are defined as:

- `domain_separator` : an ASCII string; for the identity handshake, this string is `gosling-identity`; for the endpoint handshake, this string is `gosling-endpoint`
- `request` : an ASCII string; for the identity handshake, this string is the requested endpoint; for the endpoint handshake, this string is the requested channel
- `client_service_id` : an ASCII string; the base-32 encoded onion service id (without the ".onion" suffix) of the connecting client's identity server
- `server_service_id` : an ASCII string; the base-32 encoded onion service id (without the ".onion" suffix) of the connected server (ie: when connected to the identity server, the identity server's onion service id is used; when connected to an endpoint server, that endpoint server's onion service id is used)
- `client_cookie` : an ASCII string; the cryptographically-randomly generated 32-byte client cookie encoded as lower-case hexadecimal (0-9a-f)
- `server_cookie` : an ASCII string; the cryptographically-randomly generated 32-byte server cookie encoded as lower-case hexadecimal (0-9a-f)

A **client** proves its identity to a gosling server (both **identity** or **endpoint**) by signing the above proof with the associated ed25519 private key of its own **identity server**. A gosling server must verify this signature using the **client's** public key derived from the provided v3 onion service id coinciding with the **client's** own **identity server**.

### Client Authorization Signature Generation and Verification

The client authorization signature is calculated by the **client** by signing the **client's** v3 onion service id with the ed25519 private key derived from the **client's** x25519 private key used to calculate their provided x25519 public key used for client authorization. The **identity server** verifies this signature with the ed25519 public key derived from the **client's** provided x25519 key (used for onion service client authorization).

![](images/client_auth_signature.svg "Client auth ed25519 signature verification derivation")

A **client** proves they control the x25519 private key associated with the provided x25519 public key (used for onion service client authorization) by generating the above signature and sending it to the **identity server**. A gosling **identity server** must verify the validity of the provided signature to guarantee the **client** controls the private x25519 key used to derive the provided public x25519 key.

## Acknowledgements

Creation of innovative free software needs support. We thank the NGI Assure Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 957073

[^1]: see [Onion routing](https://en.wikipedia.org/wiki/Onion_routing)

[^2]: see [About Tor](https://support.torproject.org/about/)

[^3]: see [Onion Sevices](https://community.torproject.org/onion-services/overview/)

[^4]: see: [Onion Service Client Authorization](https://community.torproject.org/onion-services/advanced/client-auth/)

[^5]: see [Honk-RPC Specification](honk-rpc-spec.xhtml)

[^6]: see [BSON spec](https://bsonspec.org/spec.html)
