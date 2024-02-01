# Gosling

## A Blueprint for Free Speech Free Software Project

Gosling is a library that allows developers to create applications which provide anonymous, secure, and private peer-to-peer functionality using Tor onion services.

Gosling is:

- Open source
- Free to download, use, modify and contribute to
- Security conscious – it is written in Rust, a memory-safe language, and has already has been audited by an independent, external security service
- A work in progress – it is not done yet, but you can definitely explore and contribute to the code on our [GitHub  page](https://github.com/blueprint-freespeech/gosling)

### Why would a software developer want to use Gosling?

We lose so much of our personal privacy on the internet. Browsers and other software can often leave a long trail of electronic breadcrumbs behind most users. IT security is good for protecting some confidentiality and integrity of our data, but it does not usually fully protect our privacy. Anonymity provides the next level up of privacy.

Currently, it is difficult for a software developer to build anonymity and privacy preserving software. Plugging in Tor functionality requires time and skills that most developers do not have. It is easy to make mistakes, thus potentially creating a privacy or security risk for the end users.

Building Gosling is a way we can help reduce the burden on developers trying to create secure and anonymous peer-to-peer applications. By not having to delve too deeply into protocol design or the Tor specifications, software developers will find it easier to improve privacy and anonymity, and to do so with more security assurance.

Gosling is both a research project ("How do we modularise onion-service-providing code?") and a practical Internet building-block ("Let’s build a functional prototype, which we can test and verify that it works").

### The Technical Weeds

There are a class of libraries known as Tor Controllers which allow developers to programmatically control and manage the tor daemon. Some examples include [Stem](https://stem.torproject.org/), [Bine](https://github.com/cretz/bine), and [rust-tor-controller](https://github.com/Dhole/rust-tor-controller). These basically serve as a bridge to expose tor functionality to their respective programming languages. Gosling is  built on top of a [similar controller library](https://crates.io/crates/tor-interface), but abstracts away most of the tor details leaving only high-level functionality.

Server software (ssh, http, etc) already works well with tor. The tor daemon was originally created with these types of systems in mind. It is reasonable to setup the tor daemon through configuration files and the like when using these types of software. However, for client facing applications meant to be installed on users' devices, this complexity becomes a burden. Tor integration and cryptographic implementation details represent an additional overhead that gets in the way of and limits the number of developers who can safely build applications in this space without potentially harming their users.

Developers prefer to focus on the primary functionality of their application. In an ideal world, client applications would be able to use higher level APIs to communicate with each other. As an analogy, web developers can simply use XmlHttpRequests in JavaScript, without needing to first implement and fully understand the HTTP protocol. The security considerations and cryptographic complexities mean that there's good reason for helping general developers avoid getting involved in the low-level Tor communications. Much can go wrong, and the consequences can be very bad indeed for users who want to rely on anonymity.

Gosling provides an authentication and authorisation handshake which may be customised per protocol. For example, a chat protocol may include some additional information like an invite code, while other protocols may require some proof-of-work, or some additional verification via some other out-of-band channel like a QR code. For more information, please see our [specs](./gosling-spec.xhtml) and [example](https://github.com/blueprint-freespeech/gosling/tree/main/source/examples) projects!