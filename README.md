# Fortanix Plugin Library

It is the common scenario that some of the customers requirements involve
executing a custom set of cryptographic operations that are tied to the
specific business logic. As an example, clients that are developing/using HD
wallets for cryptocurrencies applications make use of a standard algorithm
known as BIP32 to derive public keys. In order to bring an extra level of
flexibility to customers, SDKMS offers "plugins" to allow them to run custom
code securely inside enclaves and make use of their security objects.

Plugins are can be written and loaded by customers to SDKMS. Currently, the
LUA language is supported.

Given the tremendous success and flexibility that plugins provide, Fortanix is
releasing a plugin library so that as soon as customers start using SDKMS they
have access to a menu of different tested common case plugins.

Plugin Libraries are Git repositories that contain custom code (plugins) that
can be executed inside SDKMS to achieve certain functionality that is not part
of the core capabilities offered by SDKMS.

# Contributing

We gratefully accept bug reports and contributions from the community.
By participating in this community, you agree to abide by [Code of Conduct](./CODE_OF_CONDUCT.md).
All contributions are covered under the Developer's Certificate of Origin (DCO).

## Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
have the right to submit it under the open source license
indicated in the file; or

(b) The contribution is based upon previous work that, to the best
of my knowledge, is covered under an appropriate open source
license and I have the right under that license to submit that
work with modifications, whether created in whole or in part
by me, under the same open source license (unless I am
permitted to submit under a different license), as indicated
in the file; or

(c) The contribution was provided directly to me by some other
person who certified (a), (b) or (c) and I have not modified
it.

(d) I understand and agree that this project and the contribution
are public and that a record of the contribution (including all
personal information I submit with it, including my sign-off) is
maintained indefinitely and may be redistributed consistent with
this project or the open source license(s) involved.

# License

This project is primarily distributed under the terms of the Mozilla Public License (MPL) 2.0, see [LICENSE](./LICENSE) for details.

