**WIP**

# Description

C Interface to private and native apple functions for generating encrypted machine fingerprints.

Following obfuscated functions will be encapsulated in assembly:
- Encrypting io platform data
- Generating validation data from platform data and identity service sessions
- Generating anisette data (X-Apple-I-MD) for gsa (TBD)

# Explanation of concepts and values

These are the names of the encrypted keys and their counterpart:

- Gq3489ugfi: Platform serial number
- Fyp98tpgj: IO Platform UUID
- abKPld1EcMni: MLB
- oycqAZloTNDm: ROM
- kbjfrfpoJU: Boot UUID

Encrypted values for those keys are generated in apple's closed-source XNU kernel bootstrap destructor (finalizer). 

# Support

## Compilation platforms
- Windows
- Linux

## Target architectures
- amd64
- x86 (TBD)
- arch64 (TBD)

## Requirements

- CMake (>= 3.2)
- Clang / ClangCL (>= 11)
- GCC (>= 11)

Build toolsets: Ninja, make, Visual Studio.

# References

https://github.com/beeper/pypush
