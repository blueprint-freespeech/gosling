# debian-source

This builds a debian source package from the cgosling crate which can be used to build the following packages:

- libcgosling0
- libcgosling0-dbgsym
- libcgosling-dev

Depends on the rustc, cargo, and cmake packages.

## Building binary packages

Extract the .dsc file, enter the source directory, and build the (unsigned) debian binary package (where `${CGOSLING_VERSION}` is the cgosling semantic version):

```bash
dpkg-source -x gosling_${CGOSLING_VERSION}-1.dsc
cd gosling-${CGOSLING_VERSION}
debuild -b -us -uc
```
