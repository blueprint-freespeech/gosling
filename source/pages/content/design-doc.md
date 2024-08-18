# Gosling Design and Adversary Model

#### Richard Pospesel <[richard@blueprintforfreespeech.org](mailto:richard@blueprintforfreespeech.org)>

#### Morgan <[morgan@torproject.org](mailto:morgan@torproject.org)>

---

## Introduction

The purpose of Gosling is to allow authorised peers in a peer-to-peer network to connect to each other while minimising the leaked metadata available to unauthorised peers.

This document describes the design requirements and adversary model of the Gosling protocol and implementations. For the protocol details and particulars, please see the protocol specification[^1].

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119[^2].

It is assumed that the reader is familiar with Tor[^3], onion-routing[^4], onion-services (aka hidden services)[^5], and onion-service client-authorisation[^6].


## Design Requirements

1. **Authenticated long-term identity**

    Gosling peers MUST have a long-term identifier which is authenticated and cannot be impersonated.

2. **Peer anonymity**

    The public IP address of Gosling peers MUST NOT be accessible by other Gosling peers.

3. **Metadata resistance**

    The available metadata about Gosling sessions available to peers MUST be minimised.

4. **End-to-end encryption**

    All non-localhost communications MUST be end-to-end encrypted.

5. **Decentralisation**

    The Gosling protocol MUST NOT depend on any centralised authority for any of its functionality.

6. **Custom client authorisation**

    The Gosling protocol MUST be customisable to allow application-specific methods of determining whether an authenticated client is *allowed* to be a peer.

## Overview

Gosling peers have a long-term identity defined by an onion-service service-id. The onion-service associated with this service-id is used as an introduction point to acquire and authorise new peers. We refer to this onion-service as the identity server.

New potential peers connect to the the identity server and are REQUIRED to complete the identity handshake before attempting further communications. If no new peers are needed, the identity server MAY be shutdown.

The identity handshake serves three purposes:

1. **Peer authentication**: to verify the potential new peer initiating the handshake with the identity server has ownership of the private keys needed to derive its claimed onion-service service-id (i.e. to verify the peer is not attempting to impersonate another peer)
2. **Peer authorisation**: once authenticated, to determine if the peer is allowed to connect (e.g. by consulting a block-list, verifying knowledge of a shared secret, calculating of some cryptographic proof-of-work, solving a CAPTCHA, etc)
3. **Credential negotiation**: once authorised, jointly build the configuration needed by the peer to access a second onion-service known as the endpoint server where the actual application-specific communications occur (e.g. transferring or syncing files, sending chat messages, etc)

The peer authorisation process of the identity handshake is customisable to meet the needs of the application. The Gosling protocol MAY be configured to include OPTIONAL attachments on the identity handshake messages in order to implement additional custom authorisation logic. If the connecting peer and the hosting peer wish to swap roles in the future, during subsequent identity handshakes the authorisation portion of the identity handshake MAY be short-circuited if appropriate for the application.

After the identity handshake completes, the owner of the identity server MAY start an endpoint server for the newly-authorised peer to connect to. This endpoint server's service-id SHALL be secret and known only to this pair of peers, and its descriptor (information needed to connect to it) SHALL be protected using the connecting peer's agreed upon onion-service client-authorisation keypair. The endpoint server's credentials MUST NOT be shared between multiple peers.

After the identity handshake successfully completes, the host MAY start the endpoint server using the agreed-upon credentials, and the previously connecting peer MAY now attempt to connect to it. Connecting to the endpoint server REQUIREs completion of an endpoint handshake.

The endpoint handshake serves three purposes:

1. **Peer authentication**: to verify the peer initiating the handshake with the endpoint server has ownership of the private keys needed to derive its claimed onion-service service-id (i.e. to verify the peer is not attempting to impersonate another peer)
2. **Peer authorisation**: once authenticated, verify the peer's identity corresponds with the identity associated with this endpoint server
3. **TCP stream hand-off**: upon completion, the underlying tcp connection is returned to the application

The peer authorisation process of the endpoint handshake is not customisable.

## Adversary Model

The adversaries of Gosling-enabled applications have various possible goals, positions and capabilities.

### Positioning and Capabilities

 We have to assume a Gosling peer's own computer is free of malware which can read or write data sent between the Gosling-using application and the underlying Tor implementation or which can read or write the application's memory. Any attacks related to malicious 3rd-party applications running on the same machine as the Gosling-using application are considered explicitly out-of-scope.

 We assume our adversaries MAY be positioned in at least one of the following positions:

1. **Authorised Peers**

    An adversary MAY run a malicious but authorised Gosling peer.

    Such an adversary would have access to the data sent to and from their peers, as well as the online/offline status metadata of these peers.

2. **Unauthorised Peers**

    An adversary MAY attempt to connect to a Gosling peer's identity server and attempt to complete an identity handshake.

    Such an adversary would have access to the identity server's online/offline status. They would also be able send somehow malformed requests to the identity server.

2. **Tor middle relays or upstream routers**

    An adversary MAY run modified, malicious Tor relays in the Tor Network. Alternatively, they MAY control the upstream network infrastructure of Tor relays.

    Such an adversary can observe the encrypted traffic over the connections between Tor relays, and they can collect metadata around when such connections occur.

3. **Tor guard relays or upstream routers**

    An adversary MAY run modified, malicious Tor guard relays in the Tor Network. Alternatively, they MAY control the upstream network infrastructure of Tor guard relays.

    Such an adversary can observe the encrypted traffic sent from a Gosling peer through the Tor Network, and they can collect metadata around when such connections occur. This adversary also knows the real identity of a Gosling peer, but does not know with whom said peer is ultimately communicating with.

4. **Local network, ISP, or upstream routers**

    An adversary MAY control the network infrastructure between a Gosling peer and their Tor guard relay.

    Such an adversary can observe the encrypted traffic between a Gosling peer and its Tor guard relay, and they can collect metadata around when such connections occur. This adversary also knows the real identity of a Gosling peer, but does not know with whom said peer is ultimately communicating with. At this position, an adversary MAY block access to the Tor Network entirely and prevent a local Gosling peer from connecting.

### Goals and Mitigations

We assume our adversaries have at least one of the following goals. We presume that an authorised peer (i.e. a remote Gosling peer which has completed an identity handshake and is now permitted to connect our associated endpoint server) is more trusted than an unauthorised peer.

1. **Discovering peers' real identity**

    An adversary may want to de-anonymise a Gosling peer.

    **Mitigations**: Gosling is built on Tor onion-services. Tor onion-services ensure the anonymity of both the service itself, as well as those connecting to the service.

2. **Impersonating peers**

    An adversary may want to impersonate Gosling peer.

    **Mitigations**: The Gosling handshake REQUIRES connecting clients prove ownership of the their identity keys while Tor itself ensures that the onion-services clients connect to are not being impersonated.

3. **Building peer social graph**

    An adversary may want to identify which Gosling peers are or have been connected in the past.

    **Mitigations**: Gosling is *purely* peer-to-peer and provides no mechanism or capability to allow peers to learn about *their* peers relationships to other peers. Gosling also has no need for centralised authority that keeps track of such peer-to-peer relationships. The only party which is able to know who a peer is connected to is that peer itself.

4. **Correlating Gosling and non-Gosling activities**

    An adversary MAY want to determine if a Gosling peer is also a user of some other unrelated service.

    By default, Gosling's only possible metadata-leak to untrusted peers is the identity server's online/offline status. An adversary could therefore correlate a Gosling peer's online/offline status with the online/offline status of an account on some 3rd party service. If these two profiles have sufficent overlap, a case could be made that the Gosling peer and the 3rd party service account are the same user.

    **Mitigations**: To partially solve this problem, Gosling provides applications the ability to operate with various levels of privacy with an associated degradation in functionality.

    A Gosling peer's public identity server is OPTIONAL and only needs to be enabled if the user wants new and un-trusted peers to connect to them. When the identity server is disabled, only a previously authorised peer can build this aforementioned online/offline profile by connecting to their endpoint server.

    Additionally, Gosling peer's private endpoint servers are also OPTIONAL and only need to be enabled if the user wants their trusted peers to be able to connect to them. In this mode of operation, an application could still function by only allowing outgoing connections to other trusted peer's endpoint servers.

5. **Reading message contents**

    An adversary may want to know the contents of data transferred between Gosling peers.

    **Mitigations**: End-to-end encryption of messages is provided by the underlying Tor implementation.

6. **Censorship**

    An adversary may want to prevent a Gosling peer from accessing its peer-to-peer network.

    **Mitigations**: The only way to prevent Gosling peers from accessing each other is to block access to the Tor Network itself. Gosling can be configured to use pluggable-transports and bridges to access the Tor Network.



[^1]: Gosling Protocol [https://gosling.technology/gosling-spec.xhtml](gosling-spec.xhtml)

[^2]: RFC 2119 [https://www.rfc-editor.org/rfc/rfc2119](https://www.rfc-editor.org/rfc/rfc2119)

[^3]: onion-routing [https://en.wikipedia.org/wiki/Onion_routing](https://en.wikipedia.org/wiki/Onion_routing)

[^4]: Tor [https://support.torproject.org/about/](https://support.torproject.org/about/)

[^5]: onion-services [https://community.torproject.org/onion-services/overview/](https://community.torproject.org/onion-services/overview/)

[^6]: onion-service client-authorization [https://community.torproject.org/onion-services/advanced/client-auth/](https://community.torproject.org/onion-services/advanced/client-auth/)
