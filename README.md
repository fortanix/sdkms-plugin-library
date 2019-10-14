# Fortanix Plugin Library
It is the common scenario that some of the customers requirements involve executing a custom set of cryptographic operations that are tied to the specific business logic. As an example, clients that are developing/using HD wallets for cryptocurrencies applications make use of a standard algorithm known as BIP32 to derive public keys. In order to bring an extra level of flexibility to customers, SDKMS offers "plugins" to allow them  to run custom code securely inside enclaves and make use of their security objects.

Plugins are can be written and loaded by customers to SDKMS. Currently, the LUA language is supported.

Given the tremendous success and flexibility that plugins provide, Fortanix is releasing a plugin library so that as soon as customers start using SDKMS they have access to a menu of different tested common case plugins.

Plugin Libraries are Git repositories that contain custom code (plugins) that can be executed inside SDKMS to achieve certain functionality that is not part of the core capabilities offered by SDKMS.
