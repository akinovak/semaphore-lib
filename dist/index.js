"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.unSerialiseIdentity = exports.serialiseIdentity = exports.createTree = exports.verifyProof = exports.packToSolidityProof = exports.genProof_fastSemaphore = exports.genProof = exports.genMsg = exports.genNullifierHash = exports.genSignalHash = exports.verifySignature = exports.genNullifierHash_poseidon = exports.genIdentityCommitment_fastSemaphore = exports.genIdentityCommitment_poseidon = exports.genIdentityCommitment = exports.genIdentity = exports.genExternalNullifier = exports.signMsg = void 0;
var libsemaphore_1 = require("libsemaphore");
exports.signMsg = libsemaphore_1.signMsg;
exports.genExternalNullifier = libsemaphore_1.genExternalNullifier;
exports.genIdentity = libsemaphore_1.genIdentity;
exports.genIdentityCommitment = libsemaphore_1.genIdentityCommitment;
exports.verifySignature = libsemaphore_1.verifySignature;
exports.serialiseIdentity = libsemaphore_1.serialiseIdentity;
exports.unSerialiseIdentity = libsemaphore_1.unSerialiseIdentity;
var circomlib = require("circomlib");
var ethers = require("ethers");
var groth16 = require('snarkjs').groth16;
var Tree = require('incrementalquintree/build/IncrementalQuinTree');
var SNARK_FIELD_SIZE = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
var _hash5 = function (inputs) {
    return circomlib.poseidon(inputs);
};
var genSignalHash = function (signal) {
    var converted = ethers.utils.hexlify(ethers.utils.toUtf8Bytes(signal));
    return BigInt(ethers.utils.solidityKeccak256(['bytes'], [converted])) >> BigInt(8);
};
exports.genSignalHash = genSignalHash;
var genMsg = function (externalNullifier, signalHash) {
    return circomlib.mimcsponge.multiHash([
        externalNullifier,
        signalHash,
    ]);
};
exports.genMsg = genMsg;
var genNullifierHash = function (externalNullifier, identity, nLevels) {
    return circomlib.poseidon([BigInt(externalNullifier), BigInt(identity.identityNullifier), BigInt(nLevels)]);
};
exports.genNullifierHash = genNullifierHash;
var genProof_fastSemaphore = function (identity, signalHash, identityCommitments, externalNullifier, depth, zeroValue, leavesPerNode, wasmFilePath, finalZkeyPath) { return __awaiter(void 0, void 0, void 0, function () {
    var tree, identityCommitment, leafIndex, _i, identityCommitments_1, identityCommitment_1, proof, grothInput, fullProof, root;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                tree = new Tree.IncrementalQuinTree(depth, zeroValue, leavesPerNode, _hash5);
                identityCommitment = genIdentityCommitment_poseidon(identity);
                leafIndex = identityCommitments.indexOf(identityCommitment);
                for (_i = 0, identityCommitments_1 = identityCommitments; _i < identityCommitments_1.length; _i++) {
                    identityCommitment_1 = identityCommitments_1[_i];
                    tree.insert(identityCommitment_1);
                }
                proof = tree.genMerklePath(leafIndex);
                grothInput = {
                    identity_pk: identity.keypair.pubKey,
                    identity_nullifier: identity.identityNullifier,
                    identity_trapdoor: identity.identityTrapdoor,
                    identity_path_index: proof.indices,
                    path_elements: proof.pathElements,
                    external_nullifier: externalNullifier,
                    signal_hash: signalHash
                };
                return [4 /*yield*/, groth16.fullProve(grothInput, wasmFilePath, finalZkeyPath)];
            case 1:
                fullProof = _a.sent();
                root = tree.root;
                return [2 /*return*/, {
                        fullProof: fullProof,
                        root: root
                    }];
        }
    });
}); };
exports.genProof_fastSemaphore = genProof_fastSemaphore;
var genProof = function (identity, signature, signalHash, identityCommitments, externalNullifier, depth, zeroValue, leavesPerNode, wasmFilePath, finalZkeyPath) { return __awaiter(void 0, void 0, void 0, function () {
    var tree, identityCommitment, leafIndex, _i, identityCommitments_2, identityCommitment_2, proof, grothInput, fullProof, root;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                tree = new Tree.IncrementalQuinTree(depth, zeroValue, leavesPerNode, _hash5);
                identityCommitment = (0, libsemaphore_1.genIdentityCommitment)(identity);
                leafIndex = identityCommitments.indexOf(identityCommitment);
                for (_i = 0, identityCommitments_2 = identityCommitments; _i < identityCommitments_2.length; _i++) {
                    identityCommitment_2 = identityCommitments_2[_i];
                    tree.insert(identityCommitment_2);
                }
                proof = tree.genMerklePath(leafIndex);
                grothInput = {
                    identity_pk: identity.keypair.pubKey,
                    identity_nullifier: identity.identityNullifier,
                    identity_trapdoor: identity.identityTrapdoor,
                    fake_zero: 0,
                    auth_sig_s: signature.S,
                    identity_path_index: proof.indices,
                    path_elements: proof.pathElements,
                    auth_sig_r: signature.R8,
                    signal_hash: signalHash,
                    external_nullifier: externalNullifier
                };
                return [4 /*yield*/, groth16.fullProve(grothInput, wasmFilePath, finalZkeyPath)];
            case 1:
                fullProof = _a.sent();
                root = tree.root;
                return [2 /*return*/, {
                        fullProof: fullProof,
                        root: root
                    }];
        }
    });
}); };
exports.genProof = genProof;
var packToSolidityProof = function (fullProof) {
    var proof = fullProof.proof, publicSignals = fullProof.publicSignals;
    return {
        a: proof.pi_a.slice(0, 2),
        b: proof.pi_b
            .map(function (x) { return x.reverse(); })
            .slice(0, 2),
        c: proof.pi_c.slice(0, 2),
        inputs: publicSignals.map(function (x) {
            x = BigInt(x);
            return x.mod(SNARK_FIELD_SIZE).toString();
        })
    };
};
exports.packToSolidityProof = packToSolidityProof;
var verifyProof = function (vKey, fullProof) {
    var proof = fullProof.proof, publicSignals = fullProof.publicSignals;
    return groth16.verify(vKey, publicSignals, proof);
};
exports.verifyProof = verifyProof;
var createTree = function (depth, zeroValue, leavesPerNode) {
    return new Tree.IncrementalQuinTree(depth, zeroValue, leavesPerNode, _hash5);
};
exports.createTree = createTree;
var genIdentityCommitment_poseidon = function (identity) {
    return circomlib.poseidon([
        circomlib.babyJub.mulPointEscalar(identity.keypair.pubKey, 8)[0],
        identity.identityNullifier,
        identity.identityTrapdoor
    ]);
};
exports.genIdentityCommitment_poseidon = genIdentityCommitment_poseidon;
var genIdentityCommitment_fastSemaphore = function (identity) {
    return circomlib.poseidon([
        identity.identityNullifier,
        identity.identityTrapdoor
    ]);
};
exports.genIdentityCommitment_fastSemaphore = genIdentityCommitment_fastSemaphore;
var genNullifierHash_poseidon = function (externalNullifier, identityNullifier, nLevels) {
    return circomlib.poseidon([
        externalNullifier,
        identityNullifier,
        nLevels
    ]);
};
exports.genNullifierHash_poseidon = genNullifierHash_poseidon;
//# sourceMappingURL=index.js.map