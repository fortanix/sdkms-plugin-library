# Tendermint One Time Signer

This plugin implements a one-time signer for Tendermint based blockchains.  As an overview, the Tendermint One Time Signer keeps track of certain state which it uses to determine whether to sign a message or not during the consensus process. The objective is to avoid double-signing, which can be harmful to the blockchain network.

The Tendermint One Time Signer implements the double sign prevention logic described here: https://docs.tendermint.com/master/spec/consensus/signing.html.

## Use cases

The plugin can be used to

- Sign blockchain consensus messages of types: Prevote (1), Precommit (2) and Proposal (32).

## Setup


 - Create a new group.

 - For the newly created group, update the key metadata policy to include the following custom attributes as **required**:

	   - Attribute name: height
	   - Attribute name: round
	   - Attribute name: type

 - Convert tendermint key to DER format. You can use the script provided below to do so.

 - Import the private key to DSM manually. Use type as **EC** and format as **Raw**.

 		- Add the following three attributes to the key:

       	- Attribute name: height, value: -1
	   		- Attribute name: round, value: -1
	   		- Attribute name: type, value: -1

 		- The name of the key should be `consensus-key`.


## Script to Convert Tendermint key to DER format

```
#!/bin/bash
# Usage: tendermint-ed25519.sh <input-tendermint> <output-private-p8der> <output-public-p8der>

gokey=$(jq -r .priv_key.value $1 | base64 -d| xxd -p -c 64)
echo 302e 0201 0030 0506 032b 6570 0422 0420 "${gokey:0:64}" | xxd -p -r > $2
echo 302a 3005 0603 2b65 7003 2100 "${gokey:64}" | xxd -p -r > $3
```

## Example Tendermint Key

```
{
  "last_step" : 0,
  "last_round" : "0",
  "address" : "B788DEDE4F50AD8BC9462DE76741CCAFF87D51E2",
  "pub_key" : {
    "value" : "h3hk+QE8c6QLTySp8TcfzclJw/BG79ziGB/pIA+DfPE=",
    "type" : "tendermint/PubKeyEd25519"
  },
  "last_height" : "0",
  "priv_key" : {
    "value" : "JPivl82x+LfVkp8i3ztoTjY6c6GJ4pBxQexErOCyhwqHeGT5ATxzpAtPJKnxNx/NyUnD8Ebv3OIYH+kgD4N88Q==",
    "type" : "tendermint/PrivKeyEd25519"
  }
}
```

## Sample Input

### Message Type: Prevote (1)

 **Input**

```
{
  "block_id": {
    "hash": "7CCAF6DA0CEA5D12A8A921F8224430038D9184FAE28626D94FB0F092A6DBB71D",
    "part_set_header": {
      "hash": "2F088CCA0ACC60CA2ADF7F9BC08EB4A45E1604E3CFC9AAA902DB33CD9887F51C",
      "total": 1
    }
  },
  "data": "bAgBEQEAAAAAAAAAIkgKIHzK9toM6l0SqKkh+CJEMAONkYT64oYm2U+w8JKm27cdEiQIARIgLwiMygrMYMoq33+bwI60pF4WBOPPyaqpAtszzZiH9RwqDAiRxuKTBhC9zIqhAzIHdGVzdGh1Yg==",
  "height": 1,
  "kid": "",
  "pol_round": -99,
  "req_type": 1,
  "round": 0,
  "step": 1
}
```

**Output**

```
{
  "status": 200,
  "signature": "rCsFAhVoyhe5dr0/xjOPYDCD62FtsrNa98QJsjRrbfwlmwHUpPM3L8CfB+wI6uSKxYU8gtp9g1bVm7EDAXxqDA=="
}
```

**Error**

```
{
  "message": "Double sign prevented.",
  "status": 500
}
```

### Message Type: Precommit (2)

**Input**

```
{
  "block_id": null,
  "data": "bAgBEQEAAAAAAAAAIkgKIHzK9toM6l0SqKkh+CJEMAONkYT64oYm2U+w8JKm27cdEiQIARIgLwiMygrMYMoq33+bwI60pF4WBOPPyaqpAtszzZiH9RwqDAiRxuKTBhC9zIqhAzIHdGVzdGh1Yg==",
  "height": 10,
  "kid": "",
  "pol_round": -99,
  "req_type": 2,
  "round": 0,
  "step": 1
}

```

**Output**

```
{
  "status": 200,
  "signature": "rCsFAhVoyhe5dr0/xjOPYDCD62FtsrNa98QJsjRrbfwlmwHUpPM3L8CfB+wI6uSKxYU8gtp9g1bVm7EDAXxqDA=="
}
```

**Error**
```
{
  "message": "Double sign prevented.",
  "status": 500
}
```

### Message Type: Proposal (32)

 **Input**

```
{
  "block_id": {
    "hash": "7CCAF6DA0CEA5D12A8A921F8224430038D9184FAE28626D94FB0F092A6DBB71D",
    "part_set_header": {
      "hash": "2F088CCA0ACC60CA2ADF7F9BC08EB4A45E1604E3CFC9AAA902DB33CD9887F51C",
      "total": 1
    }
  },
  "data": "dwggEQEAAAAAAAAAIP///////////wEqSAogfMr22gzqXRKoqSH4IkQwA42RhPrihibZT7Dwkqbbtx0SJAgBEiAvCIzKCsxgyirff5vAjrSkXhYE48/JqqkC2zPNmIf1HDIMCI/G4pMGEN3f17kDOgd0ZXN0aHVi",
  "height": 100,
  "kid": "",
  "pol_round": -99,
  "req_type": 32,
  "round": 0,
  "step": 0
}
```

**Output**

```
{
  "status": 200,
  "signature": "rCsFAhVoyhe5dr0/xjOPYDCD62FtsrNa98QJsjRrbfwlmwHUpPM3L8CfB+wI6uSKxYU8gtp9g1bVm7EDAXxqDA=="
}
```

**Error**
```
{
  "status": 500,
  "message": "Double sign prevented."
}
```
