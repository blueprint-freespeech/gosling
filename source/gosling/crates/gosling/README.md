# Gosling

Gosling is a crate which encapsulates connecting to and authenticating with onion-service peers on the Tor Network. The authentication mechanism is based on and improves upon the peer authentication handshake found in [Ricochet-Refresh](https://ricochetrefresh.net).

Peer-to-peer applications can be built using Gosling with the following features by default:
- end-to-end encrypted
- anonymous
- authenticated
- metadata-resistant
- decentralised
- nat-punching

Through the use of pluggable-transports, applications can also bypass censorship.

The protocol itself is customisable to allow for additional application-specific authorisation.

The problem of peer-discovery is not solved by this crate.

For more details see [htps://gosling.technology](https://gosling.technology).
