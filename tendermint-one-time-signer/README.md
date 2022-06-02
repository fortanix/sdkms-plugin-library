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

## Input/Output JSON object format

### Message Type: Prevote (1)

 **Input**

```
{
 "type": 1, // `integer`
 "height": `integer`,
 "round": `integer`,
 "data": `base64`,
 "blockId_hash": `hex`,
 "blockId_parts_hash": `hex`,
 "blockId_parts_total": `integer`
}
```

**Output**

```
{
  "signature": `base64`
}
```

**Error**
```
{
  "message": `string`,
  "status": `integer`
}
```

### Message Type: Precommit (2)

 **Input**

```
{
 "type": 2, // `integer`
 "height": `integer`,
 "round": `integer`,
 "data": `base64`
 "blockId_hash": `hex`,
 "blockId_parts_hash": `hex`,
 "blockId_parts_total": `integer`
}
```

**Output**

```
{
  "signature": `base64`
}
```

**Error**

```
{
  "message": `string`,
  "status": `integer`
}
```

### Message Type: Proposal (32)

 **Input**

```
{
 "type": 32, // `integer`
 "height": `integer`,
 "round": `integer`,
 "data": `base64`,
 "blockId_hash": `hex`,
 "blockId_parts_hash": `hex`,
 "blockId_parts_total": `integer`
}
```

**Output**

```
{
  "signature": `base64`
}
```

**Error**
```
{
  "message": `string`,
  "status": `integer`
}
```

## Sample Input

### Message Type: Prevote (1)

 **Input**

```
{
   "type": 1,
   "round": 1,
   "height": 1,
   "blockId_hash":"C70B62CB6647F7F160B0C44F0A8E21F978CA986E0ACB51E125AE33AD717CBC0D",
   "blockId_parts_hash":"D12E6344822FA80ED9CFBCFA4DB3BB9B5D69655C702588E333D3BE86C9308B2C",
   "data":"bAgBEQEAAAAAAAAAIkgKIHzK9toM6l0SqKkh+CJEMAONkYT64oYm2U+w8JKm27cdEiQIARIgLwiMygrMYMoq33+bwI60pF4WBOPPyaqpAtszzZiH9RwqDAiRxuKTBhC9zIqhAzIHdGVzdGh1Yg==",
   "blockId_parts_total": 1
}
```

**Output**

```
{
  "signature": "SgGG8XxAavBhrDn600vPfCBuS/LDrJfh/ujBCw54l1T3M924IhPWNOnyPhPAEqVhXsXutcJe6rtt97VpQ7vVDg=="
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
   "type": 2,
   "round": 1,
   "height": 2,
   "blockId_hash":"C70B62CB6647F7F160B0C44F0A8E21F978CA986E0ACB51E125AE33AD717CBC0D",
   "blockId_parts_hash":"D12E6344822FA80ED9CFBCFA4DB3BB9B5D69655C702588E333D3BE86C9308B2C",
   "data":"bAgBEQEAAAAAAAAAIkgKIHzK9toM6l0SqKkh+CJEMAONkYT64oYm2U+w8JKm27cdEiQIARIgLwiMygrMYMoq33+bwI60pF4WBOPPyaqpAtszzZiH9RwqDAiRxuKTBhC9zIqhAzIHdGVzdGh1Yg==",
   "blockId_parts_total": 1
}
```

**Output**

```
{
  "signature": "SgGG8XxAavBhrDn600vPfCBuS/LDrJfh/ujBCw54l1T3M924IhPWNOnyPhPAEqVhXsXutcJe6rtt97VpQ7vVDg=="
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
   "type": 32,
   "round": 1,
   "height": 3,
   "blockId_hash":"C70B62CB6647F7F160B0C44F0A8E21F978CA986E0ACB51E125AE33AD717CBC0D",
   "blockId_parts_hash":"D12E6344822FA80ED9CFBCFA4DB3BB9B5D69655C702588E333D3BE86C9308B2C",
   "data":"bAgBEQEAAAAAAAAAIkgKIHzK9toM6l0SqKkh+CJEMAONkYT64oYm2U+w8JKm27cdEiQIARIgLwiMygrMYMoq33+bwI60pF4WBOPPyaqpAtszzZiH9RwqDAiRxuKTBhC9zIqhAzIHdGVzdGh1Yg==",
   "blockId_parts_total": 1
}
```

**Output**

```
{
  "signature": "SgGG8XxAavBhrDn600vPfCBuS/LDrJfh/ujBCw54l1T3M924IhPWNOnyPhPAEqVhXsXutcJe6rtt97VpQ7vVDg=="
}
```

**Error**
```
{
  "message": "Double sign prevented.",
  "status": 500
}
```
