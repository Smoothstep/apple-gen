**WIP**

# Description

C Interface to private and native apple functions for generating encrypted machine fingerprints.

Following obfuscated functions will be encapsulated in assembly:
- Encrypting io platform data
- Generating validation data from platform data and identity service sessions
- Generating anisette data (X-Apple-I-MD) for gsa

# Explanation of concepts and values

These are the names of the encrypted keys and their counterpart:

Fyp98tpgj: IO Platform UUID
abKPld1EcMni: MLB
Gq3489ugfi: Serial number
oycqAZloTNDm: ROM
kbjfrfpoJU: Boot UUID

Encrypted values for those keys are generated in the closed-source XNU kernel bootstrap destructor (finalizer). 

# Support

## Compilation platforms
- Windows
- Linux

## Target architectures
- amd64
- x86 (TBD)
- arch64 (TBD)

Requires Clang, ClangCL or GCC.
Build with Ninja, make or Visual Studio.
