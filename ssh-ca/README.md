# SSH CA

## Introduction

SSH certificates are a method for authenticating users and/or servers in the SSH protocol.
Instead of bare public keys (the usual method of SSH authentication) an authority
issues a certificate which can then be used to authenticate to an SSH server.
SSH certificates were originally added to OpenSSH in version 5.6 (released in 2010).

## Use Cases

Authenticate clients to servers or servers to clients using an trusted third party
hosted on DSM.

## Setup

### Creating CA key with DSM

The initial step is to create a key for the SSH CA. Generate an RSA
key with suitable parameters on DSM, and then download the public key.

Converting the public to the OpenSSH format requires a two-step process.
First, use OpenSSL to convert the RSA key to "RSAPublicKey" format:

`$ openssl rsa -pubin -RSAPublicKey_out -in sdkms_rsa.pub > sdkms_rsa_conv.pem`

Then use `ssh-keygen` to convert this to the SSH format

`$ ssh-keygen -m PEM -i -f sdkms_rsa_conv.pem > ssh_ca.pub`

### Creating CA key with OpenSSH

Alternatively, the key can be created on a trusted machine using OpenSSH
tools, then transferred to DSM:

`$ ssh-keygen -f ssh_ca`

This will create two files, `ssh_ca.pub` (public key in SSH format)
and `ssh_ca` (private key in PKCS #8 format).

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAI...
-----END RSA PRIVATE KEY-----
```

To import the SSH private key in DSM, copy the base64 encoded block
(but *not* the PEM headers starting with "-----") and paste it into
the Security Object import field. Make sure Sign and Verify operations
are enabled. Disable Export unless required.

### Server Configuration

Set up sshd configuration for accepting SSH certificates. In your `sshd_config` add

`TrustedUserCAKeys /path/to/ssh_ca.pub`

and restart `sshd`

### Issue Client Cert

Generate an RSA key pair that the user will use:

`ssh-keygen -f ~/.ssh/user_key`

This will again generate two keys, `user_key` (PKCS#8 private key) and
`user_key.pub` (the SSH format public key). The `user_key.pub` should look like

`ssh-rsa AAAAB3<more base64 data> username@hostname`

## Input/Output JSON

```
{
"cert_lifetime":<integer>,
"valid_principals":"<username>",
"cert_type":"user",
"ca_key":"<sobject name>",
"extensions":{<map of strings to strings>},
"critical_extensions":{<map of strings to strings>},
"pubkey":"<string>"
}
```

"`cert_lifetime`" specifies the lifetime of the certificate in seconds.

"`valid_principals`" specifies what username this certificate can be used for.

"`cert_type`" can be "user" or "server".

"`ca_key`" gives the name of the private key that was used when the RSA key was
imported into DSM earlier.

"`extensions`" specifies operations the certificate can be used for. Values
OpenSSH supports include "`permit-X11-forwarding`", "`permit-agent-forwarding`"
"`permit-port-forwarding`", "`permit-pty`", and "`permit-user-rc`". In theory,
extensions can take values, but all currently defined extensions use an empty
string. Unknown values will be ignored by the server.

"`critical_extensions`" specifies operations which if the server does not
understand the value, then the login attempt will be rejected. The values OpenSSH
supports are "`force-command`" and "`source-address`". "`force-command`" specifies a
single command which the certificate can be used for. "`source-address`" gives a
list of host/mask pairs, login is only allowed from an IP matching one of the
listed values.

"`pubkey`" gives the contents of the `user_key.pub` file with the leading "`ssh-rsa `" and
trailing "` username@hostname`" removed.

## Example Usage

```
{
"cert_lifetime":86400,
"valid_principals":"desired_username",
"cert_type":"user",
"ca_key":"SSH CA Key",
"extensions":{"permit-pty":""},
"critical_extensions":{"source-address":"10.2.0.0/16,127.0.0.1"},
"pubkey":"AAAAB3<more base64 data>"}
}
```

When the plugin is invoked it will return a string that looks like

`"ssh-rsa-cert-v01@openssh.com AAAAHHNza...."`

Copy the entire contents to `~/.ssh/user_key-cert.pub`

Now test the output using `ssh-keygen`:

```
$ ssh-keygen -L  -f user_key-cert.pub
user_key-cert.pub:
        Type: ssh-rsa-cert-v01@openssh.com user certificate
...
```

Now run

`$ ssh -i ~/.ssh/user_key server_host whoami`

The login should succeed with the command executed on the remote host.

If you use `-v` option when using a certificate you should see something like

```
debug1: Offering public key: RSA-CERT SHA256:Hcb9trzeAptUdTgqWj9VEncbkAGOpAglGnUrYGq4/Vo user_key
debug1: Server accepts key: pkalg ssh-rsa-cert-v01@openssh.com blen 1029
```

## References

[Annotation of src/usr.bin/ssh/PROTOCOL.certkeys, Revision HEAD](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD)