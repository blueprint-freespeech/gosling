# News

---

## 2024-03-27 - Some Cargo Annoyances

So in the previous post I mentioned using patchelf to set the [SONAME](https://en.wikipedia.org/wiki/Soname) attribute on the libcgosling.so shared library to facilitate proper debian packaging. I further mentioned this was due to an upstream cargo issue. Well, it turns out a similar issue exists for macOS binaries. Rather than playing whack-a-mole and manually fixing every single eventual build target, I took a step back and re-thought my approach and what could be done that would be most maintainable long term.

The end-result is [this](https://github.com/blueprint-freespeech/gosling/commit/9ae019efd3c5e5565287b963d09868c4ffaf5891).

To summarise, rather than manually patching and generally futzing with build outputs, I am instead only building cgosling as a static lib, and then building a shared lib using each platforms C tooling. This way, we can lean on CMake to do the heavy lifting when it comes to platform-specific metadata, symbolic-links, naming, etc. Unfortunately there is no standard way using cmake to just build a shared library which exports all of a static libraries public symbols.

As a result, I've had to do some *interesting* engineering in the cgosling crate using proc macros. Without going into too much detail, we are now building two copies of the cgosling static library, one for direct consumption by downstream projects, and another `_impl` suffixed copy whose functions have also been renamed to include an `_impl` suffix. Then, using our existing code-generation pipeline, a cgosling shared library is written which defines public functions with the names found in the generated header, which simply pass-through all arguments to the `_impl` versions. *Hopefully* the compilers will optimise away this little overhead but if not I would be surprised if it is actually a big deal.

This work has allowed me to pretty rapidly and confidently implement both an [Homebrew Formula](https://github.com/blueprint-freespeech/gosling/commit/1435386ba6f826dd73096fa4dbaa4cc8f460af6e) for macOS (and Linux) and a [PKGBUILD](https://github.com/blueprint-freespeech/gosling/commit/b3e59159da503da2d37efd948843681667979ce3) script for msys2 Windows environments.

## 2024-02-28 - Debian Source Packages

This past week I've been diving into the wonderful world of debian packaging. Specifically, constructing a debian source package via CMake which can be used to build the cgosling library from source, and generate both binary and dev packages.

This exercise has been a bit difficult for a few reasons:

- I knew almost nothing about debian source packing at the start of this process.
- The current debian stable only has rustc version 1.63 in the apt repositories, which means I had to make some changes to remove the rustc 1.66 dependency.
- An upstream bug in cargo ([rust-lang/cargo#5045 - Support soname for cdylibs](https://github.com/rust-lang/cargo/issues/5045)) meant following the debian documentation results in deb packages with lintian errors.

This last issue proved to be the most time consuming. Essentially, the debian tools used to generate a binary package from a source package depend on the presence of the soname metadata field in the provided elf binaries to trigger a call to ldconfig on package installation. This ldconfig step essentially updates some data-store which tells the runtime linker what runtime libraries are available, as well as their versions. However, the rust toolchain does not set this metadata field for cdylib targets like it should. This resulted in libraries which the debian tools did not realise were libraries

To work around this, I have added a patchelf step which updates this soname field manually for Linux builds. I have also renamed the Linux shared-library target to include full semantic version at the end (libcgosling.so.0.2.1) and added symlinks to this library in the standard format (libcsogling.so and libcgosling.so.0) to play nicely in actual deployments.

As part of this, I have also moved the crate's semantic version definition out of its Cargo.toml file, and instead into the CMake part of the build-system. This way, we can generate all the various files (Cargo.toml, debian/control, debian/rules, etc) which need the semantic and major versions.

With commit [5ae906c](https://github.com/blueprint-freespeech/gosling/commit/7944370a122905b52640d87b5a8e17b2f3e5c53a), we are now able to build debian source packages, and end-users can build binary and dev packages. This is the first step in eventually getting cgosling into debian. Hopefully it will be all the easier by having a properly formatted (with no lintian errors!) source package to start from.

## 2024-02-01 - FOSDEM!

The Blueprint for Free Speech's Gosling and Ricochet Refresh team is going to Brussels to attend one of the world's largest free software events – [FOSDEM 2024](https://fosdem.org/2024/)

We'll be sharing our progress on Gosling and [Ricochet Refresh](https://ricochetrefresh.net), as well as exploring what the rest of the community is busy building.

Drop by if you can to FOSDEM  - it's free!

## 2023-07-04 - No news is good news!

Nothing to report here.