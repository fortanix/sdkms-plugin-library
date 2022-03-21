#!/usr/bin/env node

const bitcoin = require('bitgo-utxo-lib');
const ethUtil = require('ethereumjs-util');
const _ = require('lodash');

const fs = require('fs');
const BigInt = require('bigi');

const N = BigInt.fromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

const input = JSON.parse(fs.readFileSync("/dev/stdin").toString());
const pubKey = bitcoin.HDNode.fromBase58(input.xpub).keyPair.__Q.getEncoded(false).slice(1);

const hex = Buffer.from(input.signature, "hex");
const sig = bitcoin.ECSignature.fromDER(hex);

// Reverse-engineer the recovery (v) by trying the two options to determine
// which one matches the known pubKey.
let recovery = _.find([ 27, 28 ], v => {
  let rbuf = sig.r.toBuffer();
  let sbuf = sig.s.toBuffer();
  return ethUtil.ecrecover(Buffer.from(input.msgHash, 'hex'), v, rbuf, sbuf).compare(pubKey) === 0;
}) - 27;

// If s is too large, normalize to the -s(modN) form.
if (parseInt(sig.s.toHex().substr(0,2), 16) > 127) {
  sig.s = BigInt.fromHex("00").subtract(sig.s).mod(N);
  recovery ^= 1;
}

let signature;

// For UTXO: just return toDER.
// For ETH: assemble ETH-style signature.
if (input.coin === 'eth') {
  let r = ethUtil.setLengthLeft(sig.r.toBuffer(), 32).toString('hex');
  let s = ethUtil.setLengthLeft(sig.s.toBuffer(), 32).toString('hex');
  let v = ethUtil.stripHexPrefix(ethUtil.intToHex(recovery + 27));
  signature = ethUtil.addHexPrefix(r.concat(s, v));

} else {
  signature = sig.toDER().toString('hex');
}

console.log(JSON.stringify({ signature }));
