import * as crypto from 'crypto';
import * as circomlib from 'circomlib';
import { EddsaKeyPair, EddsaPrivateKey, EddsaPublicKey, Hasher } from './types';
const utils = require("ffjavascript").utils;


const poseidonHash = (inputs: bigint[]): bigint => {
    return circomlib.poseidon(inputs)
}

const pedersenHash = (inputs: Array<bigint>): bigint => {
    const p = circomlib.babyJub.unpackPoint(
        circomlib.pedersenHash.hash(
            Buffer.concat(
                inputs.map((x) => Buffer.from(utils.leInt2Buff(x, 32)))
            )
        )
    )
    return BigInt(p[0])
}

const identityCommitmentHasher: {
    [name: string]: Hasher 
} = {
    'poseidon': poseidonHash,
    'pedersen': pedersenHash
}

const mimcspongeHash = (inputs: Array<bigint>): bigint => {
    return circomlib.mimcsponge.multiHash(inputs)
}

const genRandomBuffer = (numBytes: number = 32): Buffer => {
    return crypto.randomBytes(numBytes)
}

const genPubKey = (privKey: EddsaPrivateKey): EddsaPublicKey => {
    return circomlib.eddsa.prv2pub(privKey)
}

const genEddsaKeyPair = (privKey: Buffer = genRandomBuffer()): EddsaKeyPair => {
    const pubKey = genPubKey(privKey)
    return { pubKey, privKey }
}

export { 
    poseidonHash,
    pedersenHash,
    mimcspongeHash,
    genRandomBuffer,
    genPubKey,
    genEddsaKeyPair,
    identityCommitmentHasher
}