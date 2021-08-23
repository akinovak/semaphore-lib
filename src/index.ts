import { signMsg, genExternalNullifier, genIdentity, genIdentityCommitment, verifySignature, serialiseIdentity, unSerialiseIdentity, Identity } from 'libsemaphore';
import * as circomlib from 'circomlib';
import * as ethers from 'ethers';
const { groth16 } = require('snarkjs');
const Tree = require('incrementalquintree/build/IncrementalQuinTree');

const SNARK_FIELD_SIZE: BigInt = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

type IncrementalQuinTree = any;

interface IProof {
    proof: any, 
    publicSignals: any,
}

interface EdDSASignature {
    R8: BigInt[],
    S: BigInt,
}

interface IWitnessData {
    fullProof: IProof, 
    root: BigInt,
}

const _hash5 = (inputs) => {
    return circomlib.poseidon(inputs)
}

const genSignalHash = (signal: string): BigInt => {
    const converted = ethers.utils.hexlify(ethers.utils.toUtf8Bytes(signal));
    return BigInt(ethers.utils.solidityKeccak256(['bytes'], [converted])) >> BigInt(8);
}

const genMsg = (externalNullifier: string, signalHash: BigInt): string => {
    return circomlib.mimcsponge.multiHash([
        externalNullifier,
        signalHash,
    ]);
}

const genNullifierHash = (externalNullifier: string, identity: Identity, nLevels: number): BigInt => {
    return circomlib.poseidon([BigInt(externalNullifier), BigInt(identity.identityNullifier), BigInt(nLevels)]);
}

const genProof = async (identity: Identity, signature: EdDSASignature, signalHash: BigInt, 
    identityCommitments: Array<BigInt>, externalNullifier: string, depth: number, zeroValue: BigInt, 
    leavesPerNode: number, wasmFilePath: string, finalZkeyPath: string): Promise<IWitnessData> => {

    const tree: IncrementalQuinTree = new Tree.IncrementalQuinTree(depth, zeroValue, leavesPerNode, _hash5);
    const identityCommitment: BigInt = genIdentityCommitment(identity);
    const leafIndex = identityCommitments.indexOf(identityCommitment);

    for(const identityCommitment of identityCommitments) {
        tree.insert(identityCommitment);
    }

    const proof = tree.genMerklePath(leafIndex);

    const grothInput: any = {
        identity_pk: identity.keypair.pubKey, 
        identity_nullifier: identity.identityNullifier,
        identity_trapdoor: identity.identityTrapdoor,
        fake_zero: 0,
        auth_sig_s: signature.S,
        identity_path_index: proof.indices,
        path_elements: proof.pathElements,
        auth_sig_r: signature.R8,
        signal_hash: signalHash, 
        external_nullifier: externalNullifier,
    }


    const fullProof: IProof = await groth16.fullProve(grothInput, wasmFilePath, finalZkeyPath);
    const root: BigInt = tree.root;
    return {
        fullProof, 
        root
    }
}

const packToSolidityProof = (fullProof: IProof) => {
    const { proof, publicSignals } = fullProof;

    return {
        a: proof.pi_a.slice(0, 2),
        b: proof.pi_b
            .map(x => x.reverse())
            .slice(0, 2),
        c: proof.pi_c.slice(0, 2),
        inputs: publicSignals.map(x => {
            x = BigInt(x);
            return x.mod(SNARK_FIELD_SIZE).toString()
        })
    };
}

const verifyProof = (vKey: string, fullProof: IProof): Promise<boolean> => {
    const { proof, publicSignals } = fullProof;
    return groth16.verify(vKey, publicSignals, proof)
}

const createTree = (depth: number, zeroValue: number | BigInt, leavesPerNode: number): IncrementalQuinTree => {
    return new Tree.IncrementalQuinTree(depth, zeroValue, leavesPerNode, _hash5);
}


export {
    Identity,
    IncrementalQuinTree,
    EdDSASignature,
    IProof,
    IWitnessData,
    signMsg,
    genExternalNullifier,
    genIdentity,
    genIdentityCommitment,
    verifySignature,
    genSignalHash,
    genNullifierHash,
    genMsg,
    genProof,
    packToSolidityProof,
    verifyProof,
    createTree,
    serialiseIdentity,
    unSerialiseIdentity
}