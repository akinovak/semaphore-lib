"use strict";
exports.__esModule = true;
exports.identityCommitmentHasher = exports.genEddsaKeyPair = exports.genPubKey = exports.genRandomBuffer = exports.mimcspongeHash = exports.pedersenHash = exports.poseidonHash = void 0;
var crypto = require("crypto");
var circomlib = require("circomlib");
var utils = require("ffjavascript").utils;
var poseidonHash = function (inputs) {
    return circomlib.poseidon(inputs);
};
exports.poseidonHash = poseidonHash;
var pedersenHash = function (inputs) {
    var p = circomlib.babyJub.unpackPoint(circomlib.pedersenHash.hash(Buffer.concat(inputs.map(function (x) { return Buffer.from(utils.leInt2Buff(x, 32)); }))));
    return BigInt(p[0]);
};
exports.pedersenHash = pedersenHash;
var identityCommitmentHasher = {
    'poseidon': poseidonHash,
    'pedersen': pedersenHash
};
exports.identityCommitmentHasher = identityCommitmentHasher;
var mimcspongeHash = function (inputs) {
    return circomlib.mimcsponge.multiHash(inputs);
};
exports.mimcspongeHash = mimcspongeHash;
var genRandomBuffer = function (numBytes) {
    if (numBytes === void 0) { numBytes = 32; }
    return crypto.randomBytes(numBytes);
};
exports.genRandomBuffer = genRandomBuffer;
var genPubKey = function (privKey) {
    return circomlib.eddsa.prv2pub(privKey);
};
exports.genPubKey = genPubKey;
var genEddsaKeyPair = function (privKey) {
    if (privKey === void 0) { privKey = genRandomBuffer(); }
    var pubKey = genPubKey(privKey);
    return { pubKey: pubKey, privKey: privKey };
};
exports.genEddsaKeyPair = genEddsaKeyPair;
//# sourceMappingURL=common.js.map