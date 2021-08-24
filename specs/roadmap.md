## Roadmap/Deliverables

### Build System Upgrades

Ricochet-Refresh releases are currently built using the ricochet-build build system, a fork of the Tor Projects tor-browser-build projects which reproducibly builds Tor Browser. We intend to use Rust for these new libraries and components, so we will need to upgrade ricochet-build with the required tool-chains for each of our target platforms.

Development and iteration time for these build systems can be very time consuming (since compiling libraries and tool-chains can take awhile), so time estimates reflect this reality. We also anticipate there will be currently unknown challenges related to integrating Rust into Ricochet-Refresh which should be budgeted for here.

#### Deliverables

- Integrate rustc compiler and dependencies into ricochet-build project
- Create a simple 'hello world' Rust program to use as a test for our build system
- Working 'hello world' rust binaries for each of our target platforms:
    - 32-bit x86 Linux
    - 64-bit amd64 Linux
    - 32-bit x86 Windows
    - 64-bit amd64 Windows
    - 64-bit amd64 macOS

Total Estimated Time: 20-30 development days

### Tor Interface Library

A shared library with which to interface with the tor backend. The initial implementation will be a wrapper around the current C tor daemon. In the future, once it has the required feature set, this will be a wrapper around the Arti rust tor implementation.

This implementation will require the following components:

- tor daemon wrapper/manager : controls process lifetime of the tor daemon
- tor controller : provide a low level API for communicating with the tor daemon control port
- socks5 client : a socks5 client implementation for sending TCP network traffic over the tor daemon
- ed25519 encryption : various encryption primitives required for various tor operations

The final library will need to use these components to implement and expose the following feature-set:

- socket-like API for connecting to and communicating with network endpoints
- v3 onion service creation, with support for client authorization
- pluggable transport configuration for using bridges to circumvent censorship
- network configuration for users behind firewalls or proxies
- ed25519 apis with support for creation of ed25519 key pairs, signing,  signature verification, parsing and serialization (in expected tor formats)

#### Deliverables

- Completed Tor Interface Library with the above functionality implemented in Rust with C API using cbindgen
- C++ unit tests exercising and testing all of the library's APIs
- Rust functional test which:
    - launches the tor daemon
    - creates an authenticated onion service (using dynamically generated ed25519 key pair)
    - creates a simple 'echo' server listening only accessible by the onion service
    - open a socket to the onion service, and verify the echo server works
- Library an tests build and runs for Linux only
- Integrate libgosling build into our ricochet-build build system

Total Estimated Time: 40-60 development days

### Gosling Protocol Specification

The Gosling protocol will be loosely based on the existing v3 Ricochet-Refresh authentication protocol. The purpose of the Gosling protocol is to generalize and automate the process of connecting and authenticating with onion service based applications and services.

Nodes using Gosling will be able to communicate with each other other concurrent channels using different tor network circuits. Nodes can advertise their existence by sharing their ID which will be based off of a v3 onion service. This service serves as an introduction point, and nodes will have full control over whether they are active or not.

After a handshake with the introduction node which verifies each other's identity, the introduction point will share a second client authenticated v3 onion service which all future communications will go through. Nodes will be able to make multiple concurrent connections to this service using different tor circuits.

Having a second authenticated service solves the cyber-stalking problem currently faced by Ricochet-Refresh which effectively uses the same service for introductions and actual communication. Anyone who knows a Ricochet-Refresh id can determine when they are online by simply pinging the associated onion service.

With gosling, using a second authenticated onion service allows nodes to control who can determine when they are online. They can disable their public introduction node and only allow nodes which have been introduced to connect.

#### Deliverables

- Draft a specification outlining the high-level protocol communication flows, packet formats, etc.
- Share said specification on tor-dev mailing list for criticism and feedback
- Fix or rework any relevant problems discovered through this process

Total Estimated Time: 10-20 development days, 2-3 real-time months

### Libgosling Implementation

Implementing and testing the Gosling specification.

#### Deliverables

- Rust implementation of the Gosling protocol using the Tor Interface Library as a base
- C API wrappers for public Rust APIs
- C++ Unit tests exercising the C APIs
- Rust functional test which:
    - creates two gosling node instances
    - creates a simple 'echo' server backend using gosling for authentication
    - connect one node to the introduction point of another, and reject the request
        - ensure the requesting node does not gain access to the backend service
    - connect again, this time accepting
    - connect to the provided backend service through multiple channels (circuits) and ensure 'echo' service works as expected
- Tor Interface Library builds and runs on Windows and macOS
- Libgosling tests run and pass on Windows, macOS and Linux
- Integration of libgosling into our ricochet-build build system

Total Estimated Time: 40-60 development days

### Ricochet-Refresh Integration

The Ricochet-Refresh chat protocol is currently implemented in the libtego library (C++ implementation, C public API). We will replace the existing libtego implementation with a Rust library built on top of libgosling. The new library will aim to maintain C API compatibility with the existing libtego to ease integration into the Ricochet-Refresh frontend (though changes may need to be made). The new libtego should maintain the same feature-set as the existing implementation. There will necessarily be API and storage differences due to the additional requirements of authenticated onion services and the associated keys.

#### Deliverables

- Updated Ricochet-Refresh protocol specification documentation
- New Rust implementation of libtego built on top of libgosling
    - same feature-set as current libtego
    - API compatibility (where possible)
- C++ Unit tests exercising the libtego C APIs
- C++ functional tests which:
    - creates two ricochet-refresh users
    - exercises adding, removing, blocking contacts
    - exercises sending/receiving messages
    - exercises file-transfer
- Integrate updated libtego implementation into Ricochet-Refresh
- Beta release for Windows, macOS, and Linux using new implementation without backwards compatibility with previous versions

Total Estimated Time: 60-80 development days
