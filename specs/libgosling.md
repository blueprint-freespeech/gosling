# Gosling

## Overview

Gosling is intended to be a building block for peer-to-peer applications using onion services. Each node in the network has an associated 'introducer' onion service and an 'authenticated' onion service.
- the introducer service serves as an introduction point for other nodes to become 'friends'; if the owner of the introduction point consents to a new client's request, they share a second authenticated onion service which from then on the client will connect to directly.
- the authenticated onion service is where the node's actual work is done; libgosling steps back, hands the socket off to the library's consumer and doesn't do much else

### Goals

- abstract away the task of setting up an onion service, authenticating users.
- to connect to a peer, library consumers need only call 'connect' for a given onion service
- nodes can run with multiple levels of visibility defined by following flags (allowing for 8 viable connectivity states):
    - **introduction service running** : unknown nodes may request access to node
    - **authenticated service running** : only known nodes may connect to node
    - **outgoing connections enabled** : node attempts to connect to known nodes
- prevent cyber-stalking by unauthenticated nodes
- ability to revoke access to previously connected nodes

### Non-Goals

- no support for non-bundled tor daemon (as this would end up breaking after switching to an integrated arti backend
- no further features beyond authentication; leave the rest up to the application

### Open Questions

- Is there a limit on how many authenticated users can a service have?
- How quick is it to add/remove authenticated users?
- How much work would it take to add support for adding/removing authenticated keys w/o restarting tor daemon?

## Architecture

### Tor Interface Library

- provides an interface between libgosling and the tor controller logic
- first implementation will be based on current tor daemon
- future implementation based on arti
- requirements:
    - creation of onion services
    - connecting to onion services
    - selecting pluggable transport
    - configuring bridges

#### Tor Daemon Implementation

##### tor process

- manages tor process launch, lifetime

##### tor controller

- communicates with the tor process via control port
- thin wrapper around the contorl port send commands, receive logs

##### SOCKS5 client

- layer for providing a socket-like interface through tor

##### Tor Interface

Responsible for:
- daemon init
- bootstrapping
    - network configuration
    - pluggable transports
    - bridges
- onion service
    - creation
    - client authentication ONION_CLIENT_AUTH_REMOVE/ADD
        - practical limit of 32 clients or so according to dgoulet
        - sizeof(onion service descriptor) / sizeof(client auth entry)
- opening pseudo-sockets
    - onion service TCP socket
    - unique identifier for different circuits to same endpoint
    - expose familiar socket API
- ed25519 crypto implementation

#### Arti implementation

##### Tor Interface

same as Tor Daemon's Implementation, but calling to arti APIs

### Gosling

#### Terms

- Node : a peer in the gosling network
- Client : a node initiating a connection to another node in the network
- Host : a node that another client has initiated connection with (over time, a gosling node can be simultaneously a host and a client)
- Introduction Service : the host's onion service which nodes share publicly for clients to connect to
- Authenticated Service : the onion service that clients connect to after authentication; where all the actual application communication goes through

#### Protocol

Enumerate the connections

- client -> introduction service
- client -> authenticated service
  clients can connect to the authenticated service concurrently over different channels (which may optionally use different circuits through the tor network)

##### Client -> Introduction Service

    - initial communique roughly same as ricochet's
    - initial message will be a general 'blob' for a particular application to decide whether to allow the user to connect?
        - maybe build in a general request -> challenge -> response before handing over authenticated



##### Client -> Authenticated Service

    - handshake, nodes verify each other's identity and then hand-off a socket
