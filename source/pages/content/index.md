# Gosling

## A Blueprint for Free Speech Free Software Project

Gosling is a library that allows developers to create applications which provide anonymous, secure, and private peer-to-peer functionality using Tor onion services.

Gosling is:

- Open source – free to download, use, modify and contribute to
- Security conscious – written in Rust, a memory-safe language, and has already has been audited by an independent, external security service
- A work in progress – it is not done yet, but you can definitely explore and contribute to the code on our [GitHub  page](https://github.com/blueprint-freespeech/gosling)

### Why would a software developer want to use Gosling?

We lose so much of our personal privacy on the internet. Browsers and other software can often leave a long trail of electronic breadcrumbs behind most users. IT security is good for protecting some confidentiality and integrity of our data, but it does not usually fully protect our privacy. Anonymity provides the next level up of privacy.

Currently, it is difficult for a software developer to build anonymity and privacy preserving software. Plugging in Tor functionality requires time and skills that most developers do not have. It is easy to make mistakes, thus potentially creating a privacy or security risk for the end users.

Building Gosling is a way we can help reduce the burden on developers trying to create secure and anonymous peer-to-peer applications. By not having to delve too deeply into protocol design or the Tor specifications, software developers will find it easier to improve privacy and anonymity, and to do so with more security assurance.

### Getting Started

For a deeper-dive into the problems Gosling is designed to solve and our threat-model, please see our [design document](./design-doc.xhtml).

For an overview of how to use the gosling Rust crate, please see the [usage guide](./usage-guide.xhtml).

To see Gosling used in a toy application, see our Rust and C++ examples in the [`/source/examples`](https://github.com/blueprint-freespeech/gosling/tree/main/source/examples) directory.

For specifics about the Gosling protocol, please see our [protocol specification](./gosling-spec.xhtml).
